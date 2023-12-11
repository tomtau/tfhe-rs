use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{FheOption, FheString, Pattern};
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
    pub fn strip_prefix<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        prefix: P,
    ) -> FheOption<FheString> {
        let enc_ref = encrypted_str.as_ref();
        let str_l = enc_ref.len();

        match (encrypted_str, prefix.into()) {
            (FheString::Padded(_), Pattern::Clear(pat)) => {
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
                    (starts_with, FheString::new_unchecked_padded(result))
                }
            }
            (FheString::Padded(_), Pattern::Encrypted(pat @ FheString::Padded(_))) => {
                let pat_ref = pat.as_ref();
                let pat_l = pat_ref.len();

                if pat_l < 2 {
                    (self.true_ct(), encrypted_str.clone())
                } else {
                    let fst = encrypted_str.as_ref();
                    let (starts_with, pat_l) =
                        rayon::join(|| self.starts_with(encrypted_str, pat), || self.len(pat));
                    // TODO: could return a "broken" / one-off version of string here without doing
                    // the shifting
                    let shifted_indices: Vec<_> = (0..str_l)
                        .into_par_iter()
                        .map(|i| {
                            let enc_i = self
                                .0
                                .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1);
                            let shifted_i = self.0.sub_parallelized(&enc_i, &pat_l);
                            self.0
                                .if_then_else_parallelized(&starts_with, &shifted_i, &enc_i)
                        })
                        .collect();

                    let mut result = Vec::with_capacity(fst.len());
                    result.par_extend(
                        (0..str_l)
                            .into_par_iter()
                            .map(|i| self.shift_zero_prefix(fst, &shifted_indices, i)),
                    );
                    (starts_with, FheString::new_unchecked_padded(result))
                }
            }
            (FheString::Unpadded(_), Pattern::Clear(pat)) => {
                let starts_with = self.starts_with_clear_par(enc_ref, pat);
                let pat_l = pat.len();
                if str_l < pat_l || pat.is_empty() {
                    (
                        if str_l < pat_l {
                            self.false_ct()
                        } else {
                            self.true_ct()
                        },
                        encrypted_str.clone(),
                    )
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
                    (starts_with, FheString::new_unchecked_padded(result))
                }
            }
            (FheString::Unpadded(_), Pattern::Encrypted(pat @ FheString::Unpadded(_))) => {
                let pat_l = pat.as_ref().len();

                let starts_with = self.starts_with(encrypted_str, pat);

                if str_l < pat_l || pat_l == 0 {
                    (
                        if str_l < pat_l {
                            self.false_ct()
                        } else {
                            self.true_ct()
                        },
                        encrypted_str.clone(),
                    )
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
                    (starts_with, FheString::new_unchecked_padded(result))
                }
            }
            // TODO: more effiecient versions for combinations of padded and unpadded
            (x, Pattern::Encrypted(y)) => {
                let px = self.pad_string(x);
                let py = self.pad_string(y);
                self.strip_prefix(&px, &py)
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
        let encrypted_str = client_key.encrypt_str(input).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key.encrypt_str(pattern).unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, &encrypted_pattern,))
                .as_deref()
        );
    }
}
