use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};

use crate::ciphertext::{FheOption, FheString, Padded, Pattern, Unpadded};
use crate::server_key::ServerKey;

impl ServerKey {
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
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, "foo:")),
    ///     Some("bar".to_string())
    /// );
    /// let foo = client_key.encrypt_str("foo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, &foo)),
    ///     Some(":bar".to_string())
    /// );
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, "bar")),
    ///     None
    /// );
    /// let bar = client_key.encrypt_str("bar").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foobar, &bar)),
    ///     None
    /// );
    /// let foofoo = client_key.encrypt_str("foofoo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foofoo, "foo")),
    ///     Some("foo".to_string())
    /// );
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_prefix(&foofoo, &foo)),
    ///     Some("foo".to_string())
    /// );
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[must_use = "this returns the remaining substring as a new FheString, \
                  without modifying the original"]
    pub fn strip_prefix<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        prefix: P,
    ) -> FheOption<FheString<Padded>> {
        let enc_ref = encrypted_str.as_ref();
        let str_l = enc_ref.len();

        match prefix.into() {
            Pattern::Clear(pat) => {
                let starts_with = self.starts_with_clear_par(enc_ref, pat);
                let pat_l = pat.len();
                if str_l < pat_l || pat.is_empty() {
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

    pub fn strip_prefix_unpadded<'a, P: Into<Pattern<'a, Unpadded>>>(
        &self,
        encrypted_str: &FheString<Unpadded>,
        prefix: P,
    ) -> FheOption<FheString<Padded>> {
        let enc_ref = encrypted_str.as_ref();
        let str_l = enc_ref.len();

        match prefix.into() {
            Pattern::Clear(pat) => {
                let starts_with = self.starts_with_clear_par(enc_ref, pat);
                let pat_l = pat.len();
                if str_l < pat_l || pat.is_empty() {
                    (starts_with, self.pad_string(encrypted_str))
                } else {
                    let zero = self.false_ct();
                    let mut result = Vec::with_capacity(str_l);
                    result.par_extend(enc_ref.par_iter().enumerate().map(|(i, c)| {
                        if i + pat_l < str_l {
                            self.0.if_then_else_parallelized(
                                &starts_with,
                                enc_ref[i + pat_l].as_ref(),
                                c.as_ref(),
                            )
                        } else {
                            self.0
                                .if_then_else_parallelized(&starts_with, &zero, c.as_ref())
                        }
                        .into()
                    }));
                    result.push(zero.into());
                    (starts_with, FheString::new_unchecked(result))
                }
            }
            Pattern::Encrypted(pat) => {
                let pat_l = pat.as_ref().len();

                let starts_with = self.starts_with_unpadded(encrypted_str, Pattern::Encrypted(pat));

                if str_l < pat_l || pat_l == 0 {
                    (starts_with, self.pad_string(encrypted_str))
                } else {
                    let zero = self.false_ct();
                    let mut result = Vec::with_capacity(str_l);
                    result.par_extend(enc_ref.par_iter().enumerate().map(|(i, c)| {
                        if i + pat_l < str_l {
                            self.0.if_then_else_parallelized(
                                &starts_with,
                                enc_ref[i + pat_l].as_ref(),
                                c.as_ref(),
                            )
                        } else {
                            self.0
                                .if_then_else_parallelized(&starts_with, &zero, c.as_ref())
                        }
                        .into()
                    }));
                    result.push(zero.into());
                    (starts_with, FheString::new_unchecked(result))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["foo9bar", "foofoo"],
        ["foo9", "bar", "foo"],
        1..=3
    )]
    fn test_strip_prefix_padded(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, &encrypted_pattern,))
                .as_deref()
        );
    }

    #[test_matrix(
        ["foo9bar", "foofoo"],
        ["foo9", "bar", "foo"]
    )]
    fn test_strip_prefix_unpadded(input: &str, pattern: &str) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_unpadded(input).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix_unpadded(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key.encrypt_str_unpadded(pattern).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(
                    &server_key.strip_prefix_unpadded(&encrypted_str, &encrypted_pattern,)
                )
                .as_deref()
        );
    }
}
