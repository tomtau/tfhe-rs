mod comparison;
mod concat;
mod conversion;
mod is_empty;
mod len;
mod repeat;
mod replace;
mod search;
mod split;
mod trim;

pub use split::{FhePatternLen, FheSplitResult};

use std::cmp::Ordering;

use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe::integer::ServerKey as IntegerServerKey;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, FheUsize, Number, Padded, Pattern},
    client_key::{ClientKey, PRECISION_BITS},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey(IntegerServerKey, usize);

impl From<&ClientKey> for ServerKey {
    fn from(key: &ClientKey) -> Self {
        let num_blocks =
            PRECISION_BITS / key.as_ref().parameters().message_modulus().0.ilog2() as usize;
        Self(IntegerServerKey::new(key), num_blocks)
    }
}

impl From<IntegerServerKey> for ServerKey {
    fn from(key: IntegerServerKey) -> Self {
        // FIXME: extract from `key` when the accessor is available.
        const NUM_BLOCKS: usize = 4;
        Self(key, NUM_BLOCKS)
    }
}

/// 0c == \f == form feed
/// 0b == \v == vertical tab
const ASCII_WHITESPACES: [char; 6] = [' ', '\t', '\n', '\r', '\x0c', '\x0b'];

impl ServerKey {
    #[inline]
    fn is_whitespace(&self, c: &FheAsciiChar) -> FheBool {
        ASCII_WHITESPACES
            .par_iter()
            .map(|&x| Some(self.0.scalar_eq_parallelized(c.as_ref(), x as u8)))
            .reduce(|| None, |a, b| self.or(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn true_ct(&self) -> FheBool {
        self.0.create_trivial_radix(1, self.1)
    }

    #[inline]
    fn false_ct(&self) -> FheBool {
        self.0.create_trivial_zero_radix(self.1)
    }

    #[inline]
    fn check_scalar_range(&self, encrypted_char: &FheAsciiChar, start: u8, end: u8) -> FheBool {
        let (ge_from, le_to) = rayon::join(
            || {
                self.0
                    .scalar_ge_parallelized(encrypted_char.as_ref(), start)
            },
            || self.0.scalar_le_parallelized(encrypted_char.as_ref(), end),
        );
        self.0.bitand_parallelized(&ge_from, &le_to)
    }

    #[inline]
    fn if_then_else(
        &self,
        cond: Option<&FheBool>,
        default_if_none: bool,
        opt_a: &FheBool,
        opt_b: &FheBool,
    ) -> FheBool {
        match cond {
            Some(cond) => self.0.if_then_else_parallelized(cond, opt_a, opt_b),
            None if default_if_none => opt_a.clone(),
            _ => opt_b.clone(),
        }
    }

    #[inline]
    fn or(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitor_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    #[inline]
    fn add(&self, a: Option<&FheUsize>, b: Option<&FheUsize>) -> Option<FheUsize> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.add_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    #[inline]
    fn and_true(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitand_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    /// Returns an encrypted `true` (`1`) if the given pattern matches a sub-slice of
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0`) if it does not.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.contains(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.contains(&bananas, nana)));
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, "apples")));
    /// let apples = client_key.encrypt_str("apples").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, &apples)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn contains<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return self.true_ct();
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return self.false_ct();
                }
                let fst = encrypted_str.as_ref();
                fst.par_windows(pat.len())
                    .map(|window| Some(self.starts_with_clear_par(window, pat)))
                    .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
                    .unwrap_or_else(|| self.false_ct())
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.starts_with_encrypted_par(&fst[i..], snd))
                    .reduce(
                        || self.is_empty(pat),
                        |x, y| self.0.bitor_parallelized(&x, &y),
                    )
            }
        }
    }

    /// Returns an encrypted `true` (`1`) if the given pattern matches a suffix
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0`) if it does not.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.ends_with(&bananas, "anas")));
    /// let anas = client_key.encrypt_str("anas").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.ends_with(&bananas, &anas)));
    /// assert!(!client_key.decrypt_bool(&server_key.ends_with(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.ends_with(&bananas, &nana)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    pub fn ends_with<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                let str_l = fst.len();
                if pat.len() > str_l {
                    return self.false_ct();
                }
                let cache = DashMap::new();
                (0..str_l - pat.len())
                    .into_par_iter()
                    .map(|i| {
                        Some(self.par_eq_clear_cached(
                            i,
                            &fst[i..std::cmp::min(i + pat.len() + 1, str_l)],
                            pat,
                            &cache,
                        ))
                    })
                    .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
                    .unwrap_or_else(|| self.false_ct())
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.par_eq(&fst[i..], snd))
                    .reduce(
                        || self.is_empty(pat),
                        |x, y| self.0.bitor_parallelized(&x, &y),
                    )
            }
        }
    }

    #[inline]
    fn par_eq_ignore_ascii_case(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd)
            .map(|(x, y)| {
                // 'a' == 97, 'z' == 122
                let (x_eq_y, ((is_lower_x, converted_x), (is_lower_y, converted_y))) = rayon::join(
                    || self.0.eq_parallelized(x.as_ref(), y.as_ref()),
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || self.check_scalar_range(x, 97, 122),
                                    || self.0.scalar_sub_parallelized(x.as_ref(), 32),
                                )
                            },
                            || {
                                rayon::join(
                                    || self.check_scalar_range(y, 97, 122),
                                    || self.0.scalar_sub_parallelized(y.as_ref(), 32),
                                )
                            },
                        )
                    },
                );

                // !is_lower_x && !is_lower_y && x_eq_y
                // || is_lower_x && is_lower_y && x_eq_y
                // || is_lower_x && !is_lower_y && converted_x == y
                // || !is_lower_x && is_lower_y && x == converted_y
                // simplifies to:
                // x_eq_y || is_lower_x && !is_lower_y && converted_x == y || !is_lower_x && is_lower_y && x == converted_y
                let ((not_is_lower_y, not_is_lower_x), (converted_x_eq_y, x_eq_converted_y)) =
                    rayon::join(
                        || {
                            rayon::join(
                                || self.0.bitnot_parallelized(&is_lower_y),
                                || self.0.bitnot_parallelized(&is_lower_x),
                            )
                        },
                        || {
                            rayon::join(
                                || self.0.eq_parallelized(&converted_x, y.as_ref()),
                                || self.0.eq_parallelized(x.as_ref(), &converted_y),
                            )
                        },
                    );
                let (is_lower_x_not_y, is_lower_y_not_x) = rayon::join(
                    || self.0.bitand_parallelized(&is_lower_x, &not_is_lower_y),
                    || self.0.bitand_parallelized(&is_lower_y, &not_is_lower_x),
                );
                let (is_lower_x_not_y_eq_converted_x, is_lower_y_not_x_eq_converted_y) =
                    rayon::join(
                        || {
                            self.0
                                .bitand_parallelized(&is_lower_x_not_y, &converted_x_eq_y)
                        },
                        || {
                            self.0
                                .bitand_parallelized(&is_lower_y_not_x, &x_eq_converted_y)
                        },
                    );
                Some(self.0.bitor_parallelized(
                    &x_eq_y,
                    &self.0.bitor_parallelized(
                        &is_lower_x_not_y_eq_converted_x,
                        &is_lower_y_not_x_eq_converted_y,
                    ),
                ))
            })
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.true_ct())
    }

    /// Checks that two encrypted strings are an ASCII case-insensitive match
    /// and returns an encrypted `true` (`1`) if they are.
    ///
    /// Same as `eq(to_lowercase(a), to_lowercase(b))`,
    /// but without allocating and copying temporaries.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("Ferris").unwrap();
    /// let s2 = client_key.encrypt_str("FERRIS").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.eq_ignore_case(&s1, &s2)));
    /// ```
    #[must_use]
    #[inline]
    pub fn eq_ignore_case(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.0.bitand_parallelized(
                &self.par_eq_ignore_ascii_case(fst, &snd[..fst.len()]),
                &self.par_eq_zero(&snd[fst.len()..]),
            ),
            Ordering::Equal => self.par_eq_ignore_ascii_case(fst, snd),
            Ordering::Greater => self.0.bitand_parallelized(
                &self.par_eq_ignore_ascii_case(&fst[..snd.len()], snd),
                &self.par_eq_zero(&fst[snd.len()..]),
            ),
        }
    }

    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and a byte index)
    /// that contains the byte index for the first character of the first match of the pattern in
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component) if the pattern doesn't match.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, "a")), Some(1));
    /// let a = client_key.encrypt_str("a").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, a)), Some(1));
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, "z")), None);
    /// let z = client_key.encrypt_str("z").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, z)), None);
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn find<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheOption<FheUsize> {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return (self.true_ct(), self.false_ct());
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return (self.false_ct(), self.false_ct());
                }
                let fst = encrypted_str.as_ref();
                let (found, index) = fst
                    .par_windows(pat.len())
                    .enumerate()
                    .map(|(i, window)| {
                        (
                            Some(self.starts_with_clear_par(window, pat)),
                            self.0.create_trivial_radix(i as u64, self.1),
                        )
                    })
                    .reduce(
                        || (None, self.0.create_trivial_radix(u64::MAX, self.1)),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.or(x_starts.as_ref(), y_starts.as_ref()),
                                || self.if_then_else(x_starts.as_ref(), false, &x_i, &y_i),
                            )
                        },
                    );
                (found.unwrap_or_else(|| self.false_ct()), index)
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return (self.true_ct(), self.false_ct());
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| {
                        (
                            self.starts_with_encrypted_par(&fst[i..], snd),
                            self.0.create_trivial_radix(i as u64, self.1),
                        )
                    })
                    .reduce(
                        || (self.is_empty(pat), self.false_ct()),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.0.bitor_parallelized(&x_starts, &y_starts),
                                || self.0.if_then_else_parallelized(&x_starts, &x_i, &y_i),
                            )
                        },
                    )
            }
        }
    }

    /// Returns an encrypted `true` (`1`) if `encrypted_str` has a length of zero bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.is_empty(&s)));
    ///
    /// let s = client_key.encrypt_str("not empty").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.is_empty(&s)));
    /// ```
    #[must_use]
    #[inline]
    pub fn is_empty(&self, encrypted_str: &FheString<Padded>) -> FheBool {
        self.0
            .scalar_eq_parallelized(&encrypted_str.as_ref()[0].as_ref(), 0)
    }

    /// Returns the length of `encrypted_str`.
    ///
    /// This length is in bytes (minus the null-terminating byte or any zero-padding bytes).
    /// In other words, it is what a human considers the length of the ASCII string.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("foo").unwrap();
    /// let len = server_key.len(&s);
    /// assert_eq!(3, client_key.decrypt_usize(&len));
    /// ```
    #[must_use]
    #[inline]
    pub fn len(&self, encrypted_str: &FheString<Padded>) -> FheUsize {
        let fst = encrypted_str.as_ref();
        fst[..fst.len() - 1]
            .par_iter()
            .map(|x| Some(self.0.scalar_ne_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |a, b| self.add(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    fn repeat_clear_rec<'a>(
        &self,
        substrings: &'a DashMap<usize, FheString<Padded>>,
        n: usize,
    ) -> dashmap::mapref::one::Ref<'a, usize, FheString<Padded>> {
        if let Some(s) = substrings.get(&n) {
            s
        } else {
            if let Some(s) = (n - 1..=n / 2).into_par_iter().find_map_any(|i| {
                if let Some(s) = substrings.get(&i) {
                    let prev = self.repeat_clear_rec(substrings, n - i);
                    let concatted = self.concat(&prev, &s);
                    substrings.insert(n, concatted);
                    Some(substrings.get(&n).expect("just inserted"))
                } else {
                    None
                }
            }) {
                s
            } else {
                let prev = self.repeat_clear_rec(substrings, n - 1);
                let concatted =
                    self.concat(&prev, &substrings.get(&1).expect("one should be inserted"));
                substrings.insert(n, concatted);
                return substrings.get(&n).expect("just inserted");
            }
        }
    }

    /// Creates a new [`FheString`] by repeating a string `n` times.
    ///
    /// `n` can either be a [`Number::Clear`] or a [`Number::Encrypted`].
    /// If `n` is encrypted, the function will trim the result to the maximum
    /// length of the padded length of `FheString` times 256.
    ///
    /// # Panics
    ///
    /// This function will panic if the capacity would overflow.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("abc").unwrap();
    /// assert_eq!("abcabcabcabc", client_key.decrypt_str(&server_key.repeat(&s, 4)));
    /// let n = client_key.encrypt_usize(4);
    /// assert_eq!("abcabcabcabc", client_key.decrypt_str(&server_key.repeat(&s, n)));
    /// ```
    ///
    /// A panic upon overflow:
    ///
    /// ```should_panic
    /// // this will panic at runtime
    /// let s = client_key.encrypt_str("0123456789abcdef").unwrap();
    /// let huge = server_key.repeat(&s, usize::MAX);
    /// ```
    #[must_use]
    pub fn repeat<N: Into<Number>>(
        &self,
        encrypted_str: &FheString<Padded>,
        n: N,
    ) -> FheString<Padded> {
        let str_ref = encrypted_str.as_ref();
        let zero = self.false_ct();

        match n.into() {
            Number::Clear(rep_l) if rep_l == 0 => {
                FheString::new_unchecked(vec![self.false_ct().into()])
            }
            Number::Clear(rep_l) if rep_l == 1 => encrypted_str.clone(),
            Number::Clear(rep_l) if rep_l < 8 => {
                // on M2, it seems to be faster to do this for smaller `n`
                // even though concat isn't that optimized now
                let substrings = DashMap::new();
                substrings.insert(1, encrypted_str.clone());
                let result = self.repeat_clear_rec(&substrings, rep_l).clone();
                result
            }
            Number::Clear(rep_l) => {
                let mut result = Vec::with_capacity(str_ref.len() * rep_l);

                let str_len = self.len(encrypted_str);

                (0..str_ref.len() * rep_l)
                    .into_par_iter()
                    .map(|i| {
                        let mut enc_i: FheUsize = self.0.create_trivial_radix(i as u64, self.1);
                        let len_mul = self.0.div_parallelized(&enc_i, &str_len);
                        let (sub_comp, not_reached_end) = rayon::join(
                            || self.0.mul_parallelized(&str_len, &len_mul),
                            || self.0.scalar_lt_parallelized(&len_mul, rep_l as u64),
                        );
                        self.0.sub_assign_parallelized(&mut enc_i, &sub_comp);

                        (0..str_ref.len())
                            .into_par_iter()
                            .map(|j| {
                                let mut cond = self.0.scalar_eq_parallelized(&enc_i, j as u64);
                                self.0
                                    .bitand_assign_parallelized(&mut cond, &not_reached_end);
                                self.0
                                    .if_then_else_parallelized(&cond, &str_ref[j].as_ref(), &zero)
                            })
                            .reduce(|| zero.clone(), |a, b| self.0.bitxor_parallelized(&a, &b))
                            .into()
                    })
                    .collect_into_vec(&mut result);
                FheString::new_unchecked(result)
            }
            Number::Encrypted(rep_l) => {
                const MAX_REP_L: usize = 256;
                let mut result = Vec::with_capacity(str_ref.len() * MAX_REP_L);

                let str_len = self.len(encrypted_str);

                (0..str_ref.len() * MAX_REP_L)
                    .into_par_iter()
                    .map(|i| {
                        let mut enc_i: FheUsize = self.0.create_trivial_radix(i as u64, self.1);
                        let len_mul = self.0.div_parallelized(&enc_i, &str_len);
                        let (sub_comp, not_reached_end) = rayon::join(
                            || self.0.mul_parallelized(&str_len, &len_mul),
                            || self.0.lt_parallelized(&len_mul, &rep_l),
                        );
                        self.0.sub_assign_parallelized(&mut enc_i, &sub_comp);

                        (0..str_ref.len())
                            .into_par_iter()
                            .map(|j| {
                                let mut cond = self.0.scalar_eq_parallelized(&enc_i, j as u64);
                                self.0
                                    .bitand_assign_parallelized(&mut cond, &not_reached_end);
                                self.0
                                    .if_then_else_parallelized(&cond, str_ref[j].as_ref(), &zero)
                            })
                            .reduce(|| zero.clone(), |a, b| self.0.bitxor_parallelized(&a, &b))
                            .into()
                    })
                    .collect_into_vec(&mut result);

                FheString::new_unchecked(result)
            }
        }
    }

    #[inline]
    fn find_shifted_index_char(
        &self,
        i: usize,
        fst: &[FheAsciiChar],
        shifted_indices: &[(FheBool, FheUsize)],
    ) -> FheAsciiChar {
        (0..shifted_indices.len())
            .into_par_iter()
            .map(|j| {
                let (part_cond, not_in_pattern) = rayon::join(
                    || {
                        self.0
                            .scalar_eq_parallelized(&shifted_indices[j].1, i as u64)
                    },
                    || self.0.scalar_eq_parallelized(&shifted_indices[j].0, 0),
                );
                let cond = self.0.bitand_parallelized(&part_cond, &not_in_pattern);
                self.0
                    .if_then_else_parallelized(&cond, fst[j].as_ref(), &self.false_ct())
            })
            .reduce(
                || self.false_ct(),
                |a, b| self.0.bitxor_parallelized(&a, &b),
            )
            .into()
    }

    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and a byte index)
    /// that contains the byte index for the first character of the last match of the pattern in
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component) if the pattern doesn't match.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, "a")), Some(5));
    /// let a = client_key.encrypt_str("a").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, a)), Some(5));
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, "z")), None);
    /// let z = client_key.encrypt_str("z").unwrap();
    /// assert_eq!(client_key.decrypt_option_usize(&server_key.find(&bananas, z)), None);
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    /// ```
    #[inline]
    pub fn rfind<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheOption<FheUsize> {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return (self.true_ct(), self.len(encrypted_str));
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return (self.false_ct(), self.false_ct());
                }
                let fst = encrypted_str.as_ref();
                let (found, index) = fst
                    .par_windows(pat.len())
                    .enumerate()
                    .map(|(i, window)| {
                        (
                            Some(self.starts_with_clear_par(window, pat)),
                            self.0.create_trivial_radix(i as u64, self.1),
                        )
                    })
                    .reduce(
                        || (None, self.0.create_trivial_radix(u64::MAX, self.1)),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.or(x_starts.as_ref(), y_starts.as_ref()),
                                || self.if_then_else(y_starts.as_ref(), false, &y_i, &x_i),
                            )
                        },
                    );
                (found.unwrap_or_else(|| self.false_ct()), index)
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                let len = self.len(encrypted_str);
                if snd.len() < 2 {
                    return (self.true_ct(), len);
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| {
                        (
                            self.starts_with_encrypted_par(&fst[i..], snd),
                            self.0.if_then_else_parallelized(
                                &self.0.scalar_eq_parallelized(fst[i].as_ref(), 0),
                                &len,
                                &self.0.create_trivial_radix(i as u64, self.1),
                            ),
                        )
                    })
                    .reduce(
                        || (self.is_empty(pat), len.clone()),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.0.bitor_parallelized(&x_starts, &y_starts),
                                || self.0.if_then_else_parallelized(&y_starts, &y_i, &x_i),
                            )
                        },
                    )
            }
        }
    }

    #[inline]
    fn starts_with_clear_par(&self, enc_ref: &[FheAsciiChar], pat: &str) -> FheBool {
        if enc_ref.len() < pat.len() {
            self.false_ct()
        } else if pat.is_empty() {
            self.true_ct()
        } else {
            enc_ref
                .par_iter()
                .zip(pat.as_bytes().par_iter())
                .map(|(a, b)| Some(self.0.scalar_eq_parallelized(a.as_ref(), *b as u64)))
                .reduce(|| None, |s, x| self.and_true(s.as_ref(), x.as_ref()))
                .unwrap_or_else(|| self.false_ct())
        }
    }

    #[inline]
    fn starts_with_encrypted_par(&self, enc_ref: &[FheAsciiChar], pat: &[FheAsciiChar]) -> FheBool {
        if pat.as_ref().len() < 2 {
            self.true_ct()
        } else {
            enc_ref
                .par_iter()
                .zip(pat.as_ref().par_iter())
                .map(|(a, b)| {
                    let (pattern_ended, a_eq_b) = rayon::join(
                        || self.0.scalar_eq_parallelized(b.as_ref(), 0),
                        || self.0.eq_parallelized(a.as_ref(), b.as_ref()),
                    );
                    Some(
                        self.0
                            .if_then_else_parallelized(&pattern_ended, &self.true_ct(), &a_eq_b),
                    )
                })
                .reduce(|| None, |s, x| self.and_true(s.as_ref(), x.as_ref()))
                .unwrap_or_else(|| self.false_ct())
        }
    }

    /// Returns an encrypted `true` (`1`) if the given pattern matches a prefix
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0`) if it does not.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, "bana")));
    /// let bana = client_key.encrypt_str("bana").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, &bana)));
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, &nana)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    pub fn starts_with<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => self.starts_with_clear_par(encrypted_str.as_ref(), pat),
            Pattern::Encrypted(pat) => {
                self.starts_with_encrypted_par(encrypted_str.as_ref(), pat.as_ref())
            }
        }
    }

    /// Returns the lowercase equivalent of this encrypted string as a new [`FheString`].
    ///
    /// 'Lowercase' is defined as adding 32 to the uppercase character, otherwise it remains the same.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("HELLO").unwrap();
    /// assert_eq!("hello", client_key.decrypt_str(&server_key.to_lowercase(&s)));
    ///
    /// let s = client_key.encrypt_str("hello").unwrap();
    /// assert_eq!("hello", client_key.decrypt_str(&server_key.to_lowercase(&s)));
    /// ```
    #[must_use = "this returns the lowercase string as a new FheString, \
                  without modifying the original"]
    pub fn to_lowercase(&self, encrypted_str: &FheString<Padded>) -> FheString<Padded> {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'A' == 65, 'Z' == 90
                    let (is_upper, converted) = rayon::join(
                        || self.check_scalar_range(x, 65, 90),
                        || self.0.scalar_add_parallelized(x.as_ref(), 32),
                    );
                    // (is_upper & converted) | (!is_upper & x)
                    self.0
                        .if_then_else_parallelized(&is_upper, &converted, x.as_ref())
                        .into()
                })
                .collect(),
        )
    }

    /// Returns the uppercase equivalent of this encrypted string as a new [`FheString`].
    ///
    /// 'Uppercase' is defined as subtracting 32 from the lowercase character, otherwise it remains the same.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("hello").unwrap();
    /// assert_eq!("HELLO", client_key.decrypt_str(&server_key.to_uppercase(&s)));
    ///
    /// let s = client_key.encrypt_str("HELLO").unwrap();
    /// assert_eq!("HELLO", client_key.decrypt_str(&server_key.to_uppercase(&s)));
    /// ```
    #[must_use = "this returns the uppercase string as a new FheString, \
                  without modifying the original"]
    pub fn to_uppercase(&self, encrypted_str: &FheString<Padded>) -> FheString<Padded> {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'a' == 97, 'z' == 122
                    let (is_lower, converted) = rayon::join(
                        || self.check_scalar_range(x, 97, 122),
                        || self.0.scalar_sub_parallelized(x.as_ref(), 32),
                    );
                    // (is_lower & converted) | (!is_lower & x)
                    self.0
                        .if_then_else_parallelized(&is_lower, &converted, x.as_ref())
                        .into()
                })
                .collect(),
        )
    }

    /// Returns the concatenation of this encrypted string and another as a new [`FheString`]
    /// and is equivalent to the `+` operator.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("hello").unwrap();
    /// let s2 = client_key.encrypt_str("world").unwrap();
    /// assert_eq!("helloworld", client_key.decrypt_str(&server_key.concat(&s1, &s2)));
    /// ```
    pub fn concat(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheString<Padded> {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();

        if fst.len() < 2 {
            return other_encrypted_str.clone();
        } else if snd.len() < 2 {
            return encrypted_str.clone();
        }
        let fst_ended = fst[..fst.len() - 1]
            .iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x.as_ref(), 0)));
        let mut result = Vec::with_capacity(fst.len() + snd.len() - 1);
        result.par_extend(fst[..fst.len() - 1].par_iter().cloned());
        result.par_extend(snd.par_iter().cloned());
        // TODO: can the fold be parallelized? (unsure about the identity and associativity)
        FheString::new_unchecked(
            fst_ended
                .enumerate()
                .fold(
                    (result, None),
                    |(mut result, previous_ended), (i, ended)| {
                        let cond = self.and_true(
                            previous_ended
                                .as_ref()
                                .map(|x| self.0.bitnot_parallelized(x))
                                .as_ref(),
                            ended.as_ref(),
                        );
                        result[i..].par_iter_mut().enumerate().for_each(|(j, x)| {
                            if j < snd.len() {
                                *x = self
                                    .if_then_else(cond.as_ref(), false, snd[j].as_ref(), x.as_ref())
                                    .into();
                            } else {
                                *x = self
                                    .if_then_else(
                                        cond.as_ref(),
                                        false,
                                        &self.false_ct(),
                                        x.as_ref(),
                                    )
                                    .into();
                            }
                        });
                        (result, ended)
                    },
                )
                .0,
        )
    }

    #[inline]
    fn par_ge(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> (Option<FheBool>, FheBool) {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| {
                rayon::join(
                    || Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())),
                    || self.0.gt_parallelized(x.as_ref(), y.as_ref()),
                )
            })
            .reduce(
                || (None, self.true_ct()),
                |(previous_ne, previous_gt), (current_ne, current_gt)| {
                    rayon::join(
                        || self.or(previous_ne.as_ref(), current_ne.as_ref()),
                        || {
                            self.if_then_else(
                                previous_ne.as_ref(),
                                false,
                                &previous_gt,
                                &current_gt,
                            )
                        },
                    )
                },
            )
    }

    /// This method tests greater than or equal to (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `>=` operator. The ordering is lexicographical.
    ///
    /// Lexicographical comparison is an operation with the following properties:
    ///
    /// - Two sequences are compared element by element.
    /// - The first mismatching element defines which sequence is lexicographically less or greater than the other.
    /// - If one sequence is a prefix of another, the shorter sequence is lexicographically less than the other.
    /// - If two sequence have equivalent elements and are of the same length, then the sequences are lexicographically equal.
    /// - An empty sequence is lexicographically less than any non-empty sequence.
    /// - Two empty sequences are lexicographically equal.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("A").unwrap();
    /// let s2 = client_key.encrypt_str("B").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.ge(&s1, &s2)));
    /// assert!(client_key.decrypt_bool(&server_key.ge(&s1, &s1)));
    /// assert!(client_key.decrypt_bool(&server_key.ge(&s2, &s1)));
    /// ```
    #[inline]
    #[must_use]
    pub fn ge(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => {
                let (any_ne, leftmost_gt) = self.par_ge(fst, &snd[..fst.len()]);

                self.if_then_else(
                    any_ne.as_ref(),
                    false,
                    &leftmost_gt,
                    &self.par_eq_zero(&snd[fst.len()..]),
                )
            }
            Ordering::Equal => {
                let (any_ne, leftmost_gt) = self.par_ge(fst, snd);
                self.if_then_else(any_ne.as_ref(), false, &leftmost_gt, &self.true_ct())
            }
            Ordering::Greater => {
                let (any_ne, leftmost_gt) = self.par_ge(&fst[..snd.len()], snd);
                self.if_then_else(any_ne.as_ref(), false, &leftmost_gt, &self.true_ct())
            }
        }
    }

    #[inline]
    fn par_le(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> (Option<FheBool>, FheBool) {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| {
                rayon::join(
                    || Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())),
                    || self.0.lt_parallelized(x.as_ref(), y.as_ref()),
                )
            })
            .reduce(
                || (None, self.true_ct()),
                |(previous_ne, previous_lt), (current_ne, current_lt)| {
                    rayon::join(
                        || self.or(previous_ne.as_ref(), current_ne.as_ref()),
                        || {
                            self.if_then_else(
                                previous_ne.as_ref(),
                                false,
                                &previous_lt,
                                &current_lt,
                            )
                        },
                    )
                },
            )
    }

    /// This method tests less than or equal to (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `<=` operator. The ordering is lexicographical.
    ///
    /// Lexicographical comparison is an operation with the following properties:
    ///
    /// - Two sequences are compared element by element.
    /// - The first mismatching element defines which sequence is lexicographically less or greater than the other.
    /// - If one sequence is a prefix of another, the shorter sequence is lexicographically less than the other.
    /// - If two sequence have equivalent elements and are of the same length, then the sequences are lexicographically equal.
    /// - An empty sequence is lexicographically less than any non-empty sequence.
    /// - Two empty sequences are lexicographically equal.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("A").unwrap();
    /// let s2 = client_key.encrypt_str("B").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.le(&s1, &s2)));
    /// assert!(client_key.decrypt_bool(&server_key.le(&s1, &s1)));
    /// assert!(!client_key.decrypt_bool(&server_key.le(&s2, &s1)));
    /// ```
    #[inline]
    #[must_use]
    pub fn le(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => {
                let (any_ne, leftmost_lt) = self.par_le(fst, &snd[..fst.len()]);
                self.if_then_else(
                    any_ne.as_ref(),
                    false,
                    &leftmost_lt,
                    &self.par_eq_zero(&snd[fst.len()..]),
                )
            }
            Ordering::Equal => {
                let (any_ne, leftmost_lt) = self.par_le(fst, snd);
                self.if_then_else(any_ne.as_ref(), false, &leftmost_lt, &self.true_ct())
            }
            Ordering::Greater => {
                let (any_ne, leftmost_lt) = self.par_le(&fst[..snd.len()], snd);
                self.if_then_else(
                    any_ne.as_ref(),
                    false,
                    &leftmost_lt,
                    &self.par_eq_zero(&fst[snd.len()..]),
                )
            }
        }
    }

    #[inline]
    fn par_ne(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())))
            .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn par_ne_zero(&self, fst: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .map(|x| Some(self.0.scalar_ne_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// This method tests inequality (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `!=` operator.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("A").unwrap();
    /// let s2 = client_key.encrypt_str("B").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.ne(&s1, &s2)));
    /// assert!(!client_key.decrypt_bool(&server_key.ne(&s1, &s1)));
    /// ```
    #[inline]
    #[must_use]
    pub fn ne(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.0.bitor_parallelized(
                &self.par_ne(fst, &snd[..fst.len()]),
                &self.par_ne_zero(&snd[fst.len()..]),
            ),
            Ordering::Equal => self.par_ne(fst, snd),
            Ordering::Greater => self.0.bitor_parallelized(
                &self.par_ne(&fst[..snd.len()], snd),
                &self.par_ne_zero(&fst[snd.len()..]),
            ),
        }
    }

    #[inline]
    fn par_eq(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| Some(self.0.eq_parallelized(x.as_ref(), y.as_ref())))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn par_eq_clear_cached(
        &self,
        start_index: usize,
        fst: &[FheAsciiChar],
        snd: &str,
        cache: &DashMap<(usize, u8), FheBool>,
    ) -> FheBool {
        (start_index..start_index + fst.len())
            .into_par_iter()
            .zip(fst.par_iter())
            .zip(snd.as_bytes().par_iter().chain(rayon::iter::once(&0u8)))
            .map(|((i, x), y)| {
                let key = (i, *y);
                let result = cache.get(&key).map(|v| v.clone()).unwrap_or_else(|| {
                    let v = self.0.scalar_eq_parallelized(x.as_ref(), *y);
                    cache.insert(key, v.clone());
                    v
                });
                Some(result)
            })
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn par_eq_zero(&self, fst: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.true_ct())
    }

    /// This method tests equality (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `==` operator.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("A").unwrap();
    /// let s2 = client_key.encrypt_str("B").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.eq(&s1, &s1)));
    /// assert!(!client_key.decrypt_bool(&server_key.eq(&s1, &s2)));
    /// ```
    #[must_use]
    pub fn eq(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.0.bitand_parallelized(
                &self.par_eq(fst, &snd[..fst.len()]),
                &self.par_eq_zero(&snd[fst.len()..]),
            ),
            Ordering::Equal => self.par_eq(fst, snd),
            Ordering::Greater => self.0.bitand_parallelized(
                &self.par_eq(&fst[..snd.len()], snd),
                &self.par_eq_zero(&fst[snd.len()..]),
            ),
        }
    }
}
