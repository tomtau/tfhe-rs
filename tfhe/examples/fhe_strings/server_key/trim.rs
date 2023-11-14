use dashmap::DashMap;
use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, Pattern},
    scan::scan,
};

use super::ServerKey;

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

    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and `FheString`)
    /// that contains a new encrypted string with the prefix removed.
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component)
    /// if the string doesn't start with the pattern.
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
    /// let foobar = client_key.encrypt_str("foo:bar").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, "foo:")), Some("bar".to_string()));
    /// let foo = client_key.encrypt_str("foo").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, &foo)), Some(":bar".to_string()));
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, "bar")), None);
    /// let bar = client_key.encrypt_str("bar").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, &bar)), None);
    /// let foofoo = client_key.encrypt_str("foofoo").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foofoo, "foo")), Some("foo".to_string()));
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_prefix(&foofoo, &foo)), Some("foo".to_string()));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[must_use = "this returns the remaining substring as a new FheString, \
                  without modifying the original"]
    pub fn strip_prefix<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        prefix: P,
    ) -> FheOption<FheString> {
        let enc_ref = encrypted_str.as_ref();
        let str_l = enc_ref.len();

        match prefix.into() {
            Pattern::Clear(pat) => {
                let starts_with = self.starts_with_clear_par(enc_ref, pat);
                let pat_l = pat.len();
                if str_l < pat_l {
                    (starts_with, encrypted_str.clone())
                } else if pat.is_empty() {
                    (starts_with, encrypted_str.clone())
                } else {
                    let mut result = Vec::with_capacity(str_l);
                    result.par_extend(enc_ref.par_iter().enumerate().map(|(i, c)| {
                        if i + pat_l < str_l {
                            self.0.if_then_else_parallelized(
                                &starts_with,
                                enc_ref[i + pat_l].as_ref(),
                                c.as_ref(),
                            )
                        } else {
                            self.0.if_then_else_parallelized(
                                &starts_with,
                                &self.false_ct(),
                                c.as_ref(),
                            )
                        }
                        .into()
                    }));
                    (starts_with, FheString::new_unchecked(result))
                }
            }
            Pattern::Encrypted(pat) => {
                let pat_ref = pat.as_ref();
                let pat_l = pat_ref.len();

                if pat_l < 2 {
                    (self.true_ct(), encrypted_str.clone())
                } else {
                    let pattern_found = enc_ref.par_iter().zip(pat_ref.par_iter()).map(|(a, b)| {
                        let ((pattern_ended, a_eq_b), pattern_not_ended) = rayon::join(
                            || {
                                rayon::join(
                                    || self.0.scalar_eq_parallelized(b.as_ref(), 0),
                                    || self.0.eq_parallelized(a.as_ref(), b.as_ref()),
                                )
                            },
                            || self.0.scalar_ne_parallelized(b.as_ref(), 0),
                        );
                        (
                            Some(self.0.if_then_else_parallelized(
                                &pattern_ended,
                                &self.true_ct(),
                                &a_eq_b,
                            )),
                            pattern_not_ended,
                        )
                    });
                    let not_ending = pattern_found.clone().map(|(_, x)| x);
                    let starts_with = pattern_found
                        .map(|(x, _)| x)
                        .reduce(|| None, |s, x| self.and_true(s.as_ref(), x.as_ref()))
                        .unwrap_or_else(|| self.false_ct());
                    let pattern_not_ended: Vec<_> = not_ending
                        .map(|x| self.0.bitand_parallelized(&starts_with, &x))
                        .collect();
                    let mut result = Vec::with_capacity(str_l);
                    let zero = self.false_ct();
                    result.par_extend((0..str_l).into_par_iter().map(|i| {
                        let window = &enc_ref[i..std::cmp::min(i + pat_l + 1, str_l)];

                        let mut c = window[0].clone();
                        // TODO: can this be parallelized?
                        for j in 1..window.len() {
                            let c_to_move = if i + pat_l < str_l {
                                window[j].as_ref()
                            } else {
                                &zero
                            };
                            // move starts_with and if pattern is not ended at j - 1
                            c = self
                                .0
                                .if_then_else_parallelized(
                                    &pattern_not_ended[j - 1],
                                    c_to_move,
                                    c.as_ref(),
                                )
                                .into();
                        }
                        c
                    }));
                    result.push(enc_ref.last().cloned().expect("last element"));

                    (starts_with, FheString::new_unchecked(result))
                }
            }
        }
    }

    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and `FheString`)
    /// that contains a new encrypted string with the suffix removed once (i.e. the string before the suffix).
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component)
    /// if the string doesn't end with the pattern.
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
    /// let barfoo = client_key.encrypt_str("bar:foo").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, ":foo")), Some("bar".to_string()));
    /// let foo = client_key.encrypt_str("foo").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, &foo)), Some("bar:".to_string()));
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, "bar")), None);
    /// let bar = client_key.encrypt_str("bar").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, &bar)), None);
    /// let foofoo = client_key.encrypt_str("foofoo").unwrap();
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&foofoo, "foo")), Some("foo".to_string()));
    /// assert_eq!(client_key.decrypt_option_str(&server_key.strip_suffix(&foofoo, &foo)), Some("foo".to_string()));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[must_use = "this returns the remaining substring as a new FheString, \
                  without modifying the original"]
    pub fn strip_suffix<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        suffix: P,
    ) -> FheOption<FheString> {
        match suffix.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                let str_l = fst.len();
                if pat.len() > str_l {
                    return (self.false_ct(), encrypted_str.clone());
                }
                let cache = DashMap::new();
                let suffix_found = (0..str_l - pat.len())
                    .into_par_iter()
                    .map(|i| {
                        Some(self.par_eq_clear_cached(
                            i,
                            &fst[i..std::cmp::min(i + pat.len() + 1, str_l)],
                            pat,
                            &cache,
                        ))
                    })
                    .chain(rayon::iter::repeatn(None, pat.len()));
                let clear_mask: Vec<_> =
                    scan(suffix_found, |x, y| self.or(x.as_ref(), y.as_ref()), None).collect();
                let found = clear_mask.last().cloned().expect("last element");

                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(fst.par_iter().zip(clear_mask).map(|(c, cond)| {
                    self.if_then_else(cond.as_ref(), false, &self.false_ct(), c.as_ref())
                        .into()
                }));
                result.push(fst.last().cloned().expect("last element"));
                (
                    found.unwrap_or_else(|| self.false_ct()),
                    FheString::new_unchecked(result),
                )
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                let empty_pattern = self.is_empty(pat);
                let not_empty_pattern = self.0.bitnot_parallelized(&empty_pattern);
                let suffix_found = (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.par_eq(&fst[i..], snd));
                let clear_mask: Vec<_> = scan(
                    suffix_found,
                    |found_p, y| self.0.bitor_parallelized(found_p, y),
                    empty_pattern,
                )
                .collect();
                let found = clear_mask
                    .last()
                    .cloned()
                    .unwrap_or_else(|| self.false_ct());
                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(fst.par_iter().zip(clear_mask).map(|(c, found)| {
                    let cond = self.0.bitand_parallelized(&found, &not_empty_pattern);
                    self.0
                        .if_then_else_parallelized(&cond, &self.false_ct(), c.as_ref())
                        .into()
                }));
                (found, FheString::new_unchecked(result))
            }
        }
    }

    /// Returns a new [`FheString`] with leading and trailing whitespace removed.
    ///
    /// 'Whitespace' is defined as one of 6 ASCII characters (' ', '\t', '\n', '\r', '\v', '\f').
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
    /// let s = client_key.encrypt_str("\n Hello\tworld\t\n").unwrap();
    /// assert_eq!("Hello\tworld", client_key.decrypt_str(&server_key.trim(&s)));
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                  without modifying the original"]
    pub fn trim(&self, encrypted_str: &FheString) -> FheString {
        // TODO: do something better than this
        self.trim_start(&self.trim_end(&encrypted_str))
    }

    /// Returns a new [`FheString`] with trailing whitespace removed.
    ///
    /// 'Whitespace' is defined as one of 6 ASCII characters (' ', '\t', '\n', '\r', '\v', '\f').
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
    /// let s = client_key.encrypt_str("\n Hello\tworld\t\n").unwrap();
    /// assert_eq!("\n Hello\tworld", client_key.decrypt_str(&server_key.trim_end(&s)));
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                  without modifying the original"]
    pub fn trim_end(&self, encrypted_str: &FheString) -> FheString {
        let fst = encrypted_str.as_ref();
        if fst.len() < 2 {
            return encrypted_str.clone();
        }
        let cache_is_whitespace: DashMap<usize, FheBool> = DashMap::with_capacity(fst.len() - 1);
        let right_boundaries_ended = fst.par_windows(2).enumerate().map(|(i, window)| {
            let left_whitespace = cache_is_whitespace
                .get(&i)
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[0]);
                    cache_is_whitespace.insert(i, v.clone());
                    v
                });
            let right_whitespace = cache_is_whitespace
                .get(&(i + 1))
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[1]);
                    cache_is_whitespace.insert(i + 1, v.clone());
                    v
                });

            (
                Some(self.0.bitand_parallelized(
                    &self.0.bitnot_parallelized(&left_whitespace),
                    &right_whitespace,
                )),
                Some(self.0.bitand_parallelized(
                    &left_whitespace,
                    &self.0.scalar_eq_parallelized(window[1].as_ref(), 0),
                )),
            )
        });
        let accumulated_boundaries: Vec<_> = scan(
            right_boundaries_ended.rev(),
            |(right_boundary_x, ends_with_whitespace_x),
             (right_boundary_y, ends_with_whitespace_y)| {
                (
                    self.or(right_boundary_x.as_ref(), right_boundary_y.as_ref()),
                    self.or(
                        ends_with_whitespace_x.as_ref(),
                        ends_with_whitespace_y.as_ref(),
                    ),
                )
            },
            (None, None),
        )
        .collect();
        let mut result = Vec::with_capacity(fst.len());
        result.par_extend(
            fst.into_par_iter()
                .rev()
                .skip(1)
                .zip(accumulated_boundaries)
                .map(|(c, (hit_right_boundary, ends_with_ws))| {
                    if let (Some(hrb), Some(ews)) = (hit_right_boundary, ends_with_ws) {
                        let not_hit_right_boundary = self.0.bitnot_parallelized(&hrb);
                        let cond = self.0.bitand_parallelized(&not_hit_right_boundary, &ews);
                        self.0
                            .if_then_else_parallelized(&cond, &self.false_ct(), c.as_ref())
                            .into()
                    } else {
                        c.clone()
                    }
                })
                .rev(),
        );
        result.push(fst.last().cloned().expect("last element"));
        FheString::new_unchecked(result)
    }

    /// Returns a new [`FheString`] with leading whitespace removed.
    ///
    /// 'Whitespace' is defined as one of 6 ASCII characters (' ', '\t', '\n', '\r', '\v', '\f').
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
    /// let s = client_key.encrypt_str("\n Hello\tworld\t\n").unwrap();
    /// assert_eq!("Hello\tworld\t\n", client_key.decrypt_str(&server_key.trim_start(&s)));
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                  without modifying the original"]
    pub fn trim_start(&self, encrypted_str: &FheString) -> FheString {
        let fst = encrypted_str.as_ref();
        let str_l = fst.len();
        if str_l < 2 {
            return encrypted_str.clone();
        }
        let cache_is_whitespace: DashMap<usize, FheBool> = DashMap::with_capacity(fst.len() - 1);
        let starts_with_ws = self.is_whitespace(&fst[0]);
        cache_is_whitespace.insert(0, starts_with_ws.clone());
        let left_boundaries_ended = fst.par_windows(2).enumerate().map(|(i, window)| {
            let left_whitespace = cache_is_whitespace
                .get(&i)
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[0]);
                    cache_is_whitespace.insert(i, v.clone());
                    v
                });
            let right_whitespace = cache_is_whitespace
                .get(&(i + 1))
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[1]);
                    cache_is_whitespace.insert(i + 1, v.clone());
                    v
                });
            (
                self.0.bitor_parallelized(
                    &self.0.scalar_eq_parallelized(&left_whitespace, 0),
                    &right_whitespace,
                ),
                left_whitespace,
            )
        });
        let accumulated_ws_before_boundary: Vec<_> = scan(
            left_boundaries_ended,
            |(ws_before_boundary_x, count_x), (ws_before_boundary_y, count_y)| {
                let (boundary_not_hit, count_xy) = rayon::join(
                    || {
                        self.0.bitand_parallelized(
                            &starts_with_ws,
                            &self
                                .0
                                .bitand_parallelized(&ws_before_boundary_x, &ws_before_boundary_y),
                        )
                    },
                    || self.0.add_parallelized(count_x, count_y),
                );
                let next_count =
                    self.0
                        .if_then_else_parallelized(&boundary_not_hit, &count_xy, &count_x);
                (boundary_not_hit, next_count)
            },
            (starts_with_ws.clone(), starts_with_ws.clone()),
        )
        .map(|(_, count)| count)
        .collect();
        let shifted_indices: Vec<_> = (0..str_l)
            .into_par_iter()
            .map(|i| {
                self.0
                    .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1)
            })
            .zip(accumulated_ws_before_boundary)
            .map(|(i, count)| self.0.sub_parallelized(&i, &count))
            .collect();

        let mut result = Vec::with_capacity(fst.len());
        result.par_extend((0..str_l).into_par_iter().map(|i| {
            (i..shifted_indices.len())
                .into_par_iter()
                .map(|j| {
                    self.0.if_then_else_parallelized(
                        &self.0.scalar_eq_parallelized(&shifted_indices[j], i as u64),
                        fst[j].as_ref(),
                        &self.false_ct(),
                    )
                })
                .reduce(
                    || self.false_ct(),
                    |a, b| self.0.bitxor_parallelized(&a, &b),
                )
                .into()
        }));
        FheString::new_unchecked(result)
    }
}
