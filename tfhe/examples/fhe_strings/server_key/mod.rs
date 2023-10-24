mod split;
mod trim;

pub use split::{FheSplit, FheSplitItem};

use std::cmp::Ordering;

use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe::integer::ServerKey as IntegerServerKey;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, FheUsize, Number, Pattern},
    client_key::{ClientKey, NUM_BLOCKS},
    scan::scan,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey(IntegerServerKey);

impl From<&ClientKey> for ServerKey {
    fn from(key: &ClientKey) -> Self {
        Self(IntegerServerKey::new(key))
    }
}

impl From<IntegerServerKey> for ServerKey {
    fn from(key: IntegerServerKey) -> Self {
        Self(key)
    }
}

impl ServerKey {
    #[inline]
    fn true_ct(&self) -> FheBool {
        self.0.create_trivial_radix(1, NUM_BLOCKS)
    }

    #[inline]
    fn false_ct(&self) -> FheBool {
        self.0.create_trivial_zero_radix(NUM_BLOCKS)
    }

    #[inline]
    fn check_scalar_range(&self, encrypted_char: &FheAsciiChar, start: u8, end: u8) -> FheBool {
        let (ge_from, le_to) = rayon::join(
            || self.0.scalar_ge_parallelized(encrypted_char, start),
            || self.0.scalar_le_parallelized(encrypted_char, end),
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
    pub fn contains<'a, P: Into<Pattern<'a>>>(&self, encrypted_str: &FheString, pat: P) -> FheBool {
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
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, "anas")));
    /// let anas = client_key.encrypt_str("anas").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, &anas)));
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, &nana)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    pub fn ends_with<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
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
                (0..str_l - pat.len() - 1)
                    .into_par_iter()
                    .map(|i| {
                        Some(self.par_eq_clear_cached(i, &fst[i..i + pat.len() + 1], pat, &cache))
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
                    || self.0.eq_parallelized(x, y),
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || self.check_scalar_range(x, 97, 122),
                                    || self.0.scalar_sub_parallelized(x, 32),
                                )
                            },
                            || {
                                rayon::join(
                                    || self.check_scalar_range(y, 97, 122),
                                    || self.0.scalar_sub_parallelized(y, 32),
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
                                || self.0.eq_parallelized(&converted_x, y),
                                || self.0.eq_parallelized(x, &converted_y),
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
        encrypted_str: &FheString,
        other_encrypted_str: &FheString,
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
    pub fn find<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
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
                            self.0.create_trivial_radix(i as u64, NUM_BLOCKS),
                        )
                    })
                    .reduce(
                        || (None, self.0.create_trivial_radix(u64::MAX, NUM_BLOCKS)),
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
                            self.0.create_trivial_radix(i as u64, NUM_BLOCKS),
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
    pub fn is_empty(&self, encrypted_str: &FheString) -> FheBool {
        self.0.scalar_eq_parallelized(&encrypted_str.as_ref()[0], 0)
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
    pub fn len(&self, encrypted_str: &FheString) -> FheUsize {
        let fst = encrypted_str.as_ref();
        fst[..fst.len() - 1]
            .par_iter()
            .map(|x| Some(self.0.scalar_ne_parallelized(x, 0)))
            .reduce(|| None, |a, b| self.add(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// Creates a new [`String`] by repeating a string `n` times.
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
    /// assert_eq!("abc".repeat(4), String::from("abcabcabcabc"));
    /// ```
    ///
    /// A panic upon overflow:
    ///
    /// ```should_panic
    /// // this will panic at runtime
    /// let huge = "0123456789abcdef".repeat(usize::MAX);
    /// ```
    #[must_use]
    pub fn repeat(&self, encrypted_str: &FheString, n: Number) -> String {
        todo!()
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
                    .if_then_else_parallelized(&cond, &fst[j], &self.false_ct())
            })
            .reduce(
                || self.false_ct(),
                |a, b| self.0.bitxor_parallelized(&a, &b),
            )
    }

    /// Replaces all matches of a pattern with another string.
    ///
    /// `replace` creates a new [`FheString`], and copies the data from `encrypted_str` into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice.
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
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is new", client_key.decrypt_str(&server_key.replace(&s, "old", "new")));
    /// assert_eq!("than an old", client_key.decrypt_str(&server_key.replace(&s, "is", "an")));
    /// let old = client_key.encrypt_str("old").unwrap();
    /// let new = client_key.encrypt_str("new").unwrap();
    /// let is = client_key.encrypt_str("is").unwrap();
    /// let an = client_key.encrypt_str("an").unwrap();
    /// assert_eq!("this is new", client_key.decrypt_str(&server_key.replace(&s, &old, &new)));
    /// assert_eq!("than an old", client_key.decrypt_str(&server_key.replace(&s, &is, &an)));
    /// ```
    ///
    /// When the pattern doesn't match, it returns `encrypted_str` as [`FheString`]:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replace(&s, "X", "Y")));
    /// let x = client_key.encrypt_str("X").unwrap();
    /// let y = client_key.encrypt_str("Y").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replace(&s, &x, &y)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information

    #[must_use = "this returns the replaced FheString as a new allocation, \
                  without modifying the original"]
    #[inline]
    pub fn replace<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        from: P,
        to: P,
    ) -> FheString {
        let str_ref = encrypted_str.as_ref();
        match (from.into(), to.into()) {
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if from_pat.is_empty() && to_pat.is_empty() =>
            {
                encrypted_str.clone()
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) if from_pat.is_empty() => {
                let to_pat_enc = to_pat.as_bytes().par_iter().map(|x| {
                    self.0
                        .create_trivial_radix::<u64, FheAsciiChar>(*x as u64, NUM_BLOCKS)
                });
                let mut result = Vec::with_capacity(str_ref.len() * to_pat.len());
                result.par_extend(to_pat_enc.clone());
                // TODO: zero-out after the string end
                for c in str_ref[..str_ref.len() - 1].iter() {
                    result.push(c.clone());
                    result.par_extend(to_pat_enc.clone());
                }
                result.push(str_ref[str_ref.len() - 1].clone());
                FheString::new_unchecked(result)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if to_pat.len() == from_pat.len() =>
            {
                let to_pat_enc: Vec<_> = to_pat
                    .as_bytes()
                    .par_iter()
                    .map(|x| {
                        self.0
                            .create_trivial_radix::<u64, FheAsciiChar>(*x as u64, NUM_BLOCKS)
                    })
                    .collect();
                let pattern_starts = str_ref
                    .par_windows(from_pat.len())
                    .map(|window| Some(self.starts_with_clear_par(window, from_pat)));
                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let not_start_x = self.0.bitnot_parallelized(start_x);
                            let next_start = self.0.bitand_parallelized(&not_start_x, &start_y);
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .flatten()
                .collect();
                let mut result = str_ref.to_vec();
                for (i, starts) in accumulated_starts.iter().enumerate() {
                    for j in i..i + from_pat.len() {
                        result[j] = self.0.if_then_else_parallelized(
                            starts,
                            &to_pat_enc[j - i],
                            &result[j],
                        );
                    }
                }
                FheString::new_unchecked(result)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) => {
                let max_len = if from_pat.len() > to_pat.len() {
                    str_ref.len()
                } else {
                    (str_ref.len() - 1) * (to_pat.len() - from_pat.len() + 1) + 1
                };
                let mut result = Vec::with_capacity(max_len);
                let to_pat_enc: Vec<_> = to_pat
                    .as_bytes()
                    .par_iter()
                    .map(|x| {
                        self.0
                            .create_trivial_radix::<u64, FheAsciiChar>(*x as u64, NUM_BLOCKS)
                    })
                    .collect();
                let pattern_starts = str_ref.par_windows(from_pat.len()).map(|window| {
                    let starts = self.starts_with_clear_par(window, from_pat);
                    Some((
                        self.0
                            .scalar_mul_parallelized(&starts, from_pat.len() as u64),
                        starts,
                    ))
                });
                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some((start_x, count_x)), Some((start_y, count_y))) => {
                            let count = self.0.add_parallelized(count_x, count_y);
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_count =
                                self.0
                                    .if_then_else_parallelized(&in_pattern, &count_x, &count);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &start_y,
                            );
                            Some((next_start, next_count))
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .flatten()
                .collect();

                let mut pattern_found_count = accumulated_starts
                    .last()
                    .cloned()
                    .map(|(_, y)| y)
                    .unwrap_or_else(|| self.false_ct());
                let shifted_indices: Vec<_> = (0..str_ref.len() - 1)
                    .into_par_iter()
                    .zip(accumulated_starts)
                    .map(|(i, (starts, count))| {
                        if from_pat.len() > to_pat.len() {
                            let shift_len = from_pat.len() - to_pat.len();
                            let lhs = self
                                .0
                                .create_trivial_radix::<u64, FheAsciiChar>(i as u64, NUM_BLOCKS);
                            let rhs = self.0.scalar_mul_parallelized(&count, shift_len as u64);
                            (starts, self.0.sub_parallelized(&lhs, &rhs))
                        } else {
                            let shift_len = to_pat.len() - from_pat.len();
                            let lhs = self.0.scalar_mul_parallelized(&count, shift_len as u64);
                            (starts, self.0.scalar_add_parallelized(&lhs, i as u64))
                        }
                    })
                    .collect::<Vec<_>>();

                result.par_extend(
                    (0..max_len)
                        .into_par_iter()
                        .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
                );
                for i in 0..max_len - 1 {
                    let (to_fill, remaining_pat) = rayon::join(
                        || self.0.scalar_eq_parallelized(&result[i], 0 as u64),
                        || self.0.scalar_gt_parallelized(&pattern_found_count, 0),
                    );
                    let cond = self.0.bitand_parallelized(&to_fill, &remaining_pat);
                    for j in 0..to_pat_enc.len() {
                        result[i + j] =
                            self.0
                                .if_then_else_parallelized(&cond, &to_pat_enc[j], &result[i + j]);
                    }
                    self.0
                        .sub_assign_parallelized(&mut pattern_found_count, &cond);
                }
                FheString::new_unchecked(result)
            }
            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat)) => {
                let from_pat_ref = from_pat.as_ref();
                let to_pat_ref = to_pat.as_ref();
                let max_len = (str_ref.len() - 1) * to_pat_ref.len() + 1;
                let mut result = Vec::with_capacity(max_len);

                let ((from_pat_len, to_pat_len), to_pat_notzeroes) = rayon::join(
                    || rayon::join(|| self.len(from_pat), || self.len(to_pat)),
                    || {
                        to_pat_ref[..to_pat_ref.len() - 1]
                            .par_iter()
                            .map(|x| self.0.scalar_ne_parallelized(x, 0 as u64))
                            .collect::<Vec<_>>()
                    },
                );

                let (pattern_starts, (from_pat_gt, shrink_shift_len, grow_shift_len)) = rayon::join(
                    || {
                        (0..str_ref.len()).into_par_iter().map(|i| {
                            let (starts, not_ended) = rayon::join(
                                || self.starts_with_encrypted_par(&str_ref[i..], from_pat_ref),
                                || self.0.scalar_ne_parallelized(&str_ref[i], 0),
                            );
                            Some((
                                self.0.mul_parallelized(&starts, &from_pat_len),
                                starts,
                                not_ended,
                            ))
                        })
                    },
                    || {
                        let from_pat_gt = self.0.gt_parallelized(&from_pat_len, &to_pat_len);
                        let shrink_shift_len = self.0.sub_parallelized(&from_pat_len, &to_pat_len);
                        let grow_shift_len = self.0.sub_parallelized(&to_pat_len, &from_pat_len);
                        (from_pat_gt, shrink_shift_len, grow_shift_len)
                    },
                );
                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (
                            Some((start_x, count_x, not_ended_x)),
                            Some((start_y, count_y, not_ended_y)),
                        ) => {
                            let count = self.0.add_parallelized(count_x, count_y);
                            let not_ended = self.0.bitor_parallelized(not_ended_x, not_ended_y);
                            let count_correct = self
                                .0
                                .if_then_else_parallelized(&not_ended, &count, count_x);
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_pattern = self.0.scalar_gt_parallelized(start_y, 0);

                            let next_count = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &count_x,
                                &count_correct,
                            );
                            let start_y_not_ended =
                                self.0.bitand_parallelized(&next_pattern, not_ended_y);
                            let next_start_y = self.0.if_then_else_parallelized(
                                &start_y_not_ended,
                                &start_y,
                                &self.false_ct(),
                            );
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &next_start_y,
                            );
                            Some((next_start, next_count, not_ended_y.clone()))
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .flatten()
                .collect();

                let mut pattern_found_count = accumulated_starts
                    .last()
                    .cloned()
                    .map(|(_, y, _)| y)
                    .unwrap_or_else(|| self.false_ct());
                let shifted_indices: Vec<_> = (0..str_ref.len() - 1)
                    .into_par_iter()
                    .zip(accumulated_starts)
                    .map(|(i, (starts, count, _))| {
                        let (shrink_index, grow_index) = rayon::join(
                            || {
                                let lhs = self.0.create_trivial_radix::<u64, FheAsciiChar>(
                                    i as u64, NUM_BLOCKS,
                                );
                                let rhs = self.0.mul_parallelized(&count, &shrink_shift_len);
                                self.0.sub_parallelized(&lhs, &rhs)
                            },
                            || {
                                let lhs = self.0.mul_parallelized(&count, &grow_shift_len);
                                self.0.scalar_add_parallelized(&lhs, i as u64)
                            },
                        );
                        (
                            starts,
                            self.0.if_then_else_parallelized(
                                &from_pat_gt,
                                &shrink_index,
                                &grow_index,
                            ),
                        )
                    })
                    .collect::<Vec<_>>();

                result.par_extend(
                    (0..max_len)
                        .into_par_iter()
                        .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
                );

                for i in 0..max_len {
                    let (to_fill, remaining_pat) = rayon::join(
                        || self.0.scalar_eq_parallelized(&result[i], 0 as u64),
                        || self.0.scalar_gt_parallelized(&pattern_found_count, 0),
                    );
                    let cond = self.0.bitand_parallelized(&to_fill, &remaining_pat);
                    for j in 0..to_pat_ref.len() - 1 {
                        if i + j >= result.len() {
                            break;
                        }
                        let sub_cond = self.0.bitand_parallelized(&cond, &to_pat_notzeroes[j]);
                        result[i + j] = self.0.if_then_else_parallelized(
                            &sub_cond,
                            &to_pat_ref[j],
                            &result[i + j],
                        );
                    }
                    self.0
                        .sub_assign_parallelized(&mut pattern_found_count, &cond);
                }
                FheString::new_unchecked(result)
            }
            _ => {
                // since both `from` and `to` need to be `P`
                unreachable!("mixed replacement patterns are not supported")
            }
        }
    }

    /// Replaces first N matches of a pattern with another string.
    ///
    /// `replacen` creates a new [`String`], and copies the data from this string slice into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice at most `count` times.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "foo foo 123 foo";
    /// assert_eq!("new new 123 foo", s.replacen("foo", "new", 2));
    /// assert_eq!("faa fao 123 foo", s.replacen('o', "a", 3));
    /// assert_eq!("foo foo new23 foo", s.replacen(char::is_numeric, "new", 1));
    /// ```
    ///
    /// When the pattern doesn't match, it returns this string slice as [`String`]:
    ///
    /// ```
    /// let s = "this is old";
    /// assert_eq!(s, s.replacen("cookie monster", "little lamb", 10));
    /// ```
    #[must_use = "this returns the replaced string as a new allocation, \
                  without modifying the original"]
    pub fn replacen<'a>(
        &'a self,
        encrypted_str: &FheString,
        pat: Pattern<'a>,
        to: &str,
        count: usize,
    ) -> String {
        todo!()
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
    pub fn rfind<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
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
                            self.0.create_trivial_radix(i as u64, NUM_BLOCKS),
                        )
                    })
                    .reduce(
                        || (None, self.0.create_trivial_radix(u64::MAX, NUM_BLOCKS)),
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
                                &self.0.scalar_eq_parallelized(&fst[i], 0),
                                &len,
                                &self.0.create_trivial_radix(i as u64, NUM_BLOCKS),
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
                .map(|(a, b)| Some(self.0.scalar_eq_parallelized(a, *b as u64)))
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
                        || self.0.scalar_eq_parallelized(b, 0),
                        || self.0.eq_parallelized(a, b),
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
    pub fn starts_with<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
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
    pub fn to_lowercase(&self, encrypted_str: &FheString) -> FheString {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'A' == 65, 'Z' == 90
                    let (is_upper, converted) = rayon::join(
                        || self.check_scalar_range(x, 65, 90),
                        || self.0.scalar_add_parallelized(x, 32),
                    );
                    // (is_upper & converted) | (!is_upper & x)
                    self.0.if_then_else_parallelized(&is_upper, &converted, x)
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
    pub fn to_uppercase(&self, encrypted_str: &FheString) -> FheString {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'a' == 97, 'z' == 122
                    let (is_lower, converted) = rayon::join(
                        || self.check_scalar_range(x, 97, 122),
                        || self.0.scalar_sub_parallelized(x, 32),
                    );
                    // (is_lower & converted) | (!is_lower & x)
                    self.0.if_then_else_parallelized(&is_lower, &converted, x)
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
    pub fn concat(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheString {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();

        if fst.len() < 2 {
            return other_encrypted_str.clone();
        } else if snd.len() < 2 {
            return encrypted_str.clone();
        }
        let fst_ended = fst[..fst.len() - 1]
            .iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x, 0)));
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
                                *x = self.if_then_else(cond.as_ref(), false, &snd[j], x);
                            } else {
                                *x = self.if_then_else(cond.as_ref(), false, &self.false_ct(), x);
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
                    || Some(self.0.ne_parallelized(x, y)),
                    || self.0.gt_parallelized(x, y),
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
    /// assert!(!client_key.ge(&s1, &s2));
    /// assert!(client_key.ge(&s1, &s1));
    /// assert!(client_key.ge(&s2, &s1));
    /// ```
    #[inline]
    #[must_use]
    pub fn ge(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheBool {
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
                    || Some(self.0.ne_parallelized(x, y)),
                    || self.0.lt_parallelized(x, y),
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
    /// assert!(client_key.le(&s1, &ss));
    /// assert!(client_key.le(&s1, &s2));
    /// assert!(!client_key.le(&s2, &s1));
    /// ```
    #[inline]
    #[must_use]
    pub fn le(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheBool {
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
            .map(|(x, y)| Some(self.0.ne_parallelized(x, y)))
            .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn par_ne_zero(&self, fst: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .map(|x| Some(self.0.scalar_ne_parallelized(x, 0)))
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
    /// assert!(client_key.ne(&s1, &s2));
    /// assert!(!client_key.ne(&s1, &s1));
    /// ```
    #[inline]
    #[must_use]
    pub fn ne(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheBool {
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
            .map(|(x, y)| Some(self.0.eq_parallelized(x, y)))
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
                    let v = self.0.scalar_eq_parallelized(x, *y);
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
            .map(|x| Some(self.0.scalar_eq_parallelized(x, 0)))
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
    /// assert!(client_key.eq(&s1, &s1));
    /// assert!(!client_key.eq(&s1, &s2));
    /// ```
    #[must_use]
    pub fn eq(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheBool {
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
