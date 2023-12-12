use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};

use crate::ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, FheUsize, Pattern};
use crate::scan::scan;
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and `FheString`)
    /// that contains a new encrypted string with the suffix removed once (i.e. the string before
    /// the suffix).
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component)
    /// if the string doesn't end with the pattern.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
    ///
    /// let barfoo = client_key.encrypt_str("bar:foo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, ":foo")),
    ///     Some("bar".to_string())
    /// );
    /// let foo = client_key.encrypt_str("foo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, &foo)),
    ///     Some("bar:".to_string())
    /// );
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, "bar")),
    ///     None
    /// );
    /// let bar = client_key.encrypt_str("bar").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&barfoo, &bar)),
    ///     None
    /// );
    /// let foofoo = client_key.encrypt_str("foofoo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&foofoo, "foo")),
    ///     Some("foo".to_string())
    /// );
    /// assert_eq!(
    ///     client_key.decrypt_option_str(&server_key.strip_suffix(&foofoo, &foo)),
    ///     Some("foo".to_string())
    /// );
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
        match (encrypted_str, suffix.into()) {
            (FheString::Padded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                if pat.len() > fst.len() {
                    return (self.false_ct(), encrypted_str.clone());
                }
                let suffix_found = self
                    .find_clear_pattern_padded_suffixes(fst, pat)
                    .chain(rayon::iter::repeatn(None, pat.len()));
                let clear_mask: Vec<_> =
                    scan(suffix_found, |x, y| self.or(x.as_ref(), y.as_ref()), None).collect();
                let found = clear_mask.last().cloned().expect("last element");

                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(fst.par_iter().zip(clear_mask).map(|(c, cond)| {
                    self.if_then_else_usize(cond.as_ref(), false, &self.zero_ct(), c.as_ref())
                        .into()
                }));
                result.push(fst.last().cloned().expect("last element"));
                (
                    found.unwrap_or_else(|| self.false_ct()),
                    FheString::new_unchecked_padded(result),
                )
            }
            (FheString::Padded(_), Pattern::Encrypted(pat @ FheString::Padded(_))) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                let empty_pattern = self.is_empty(pat);
                let not_empty_pattern = self.0.boolean_bitnot(&empty_pattern);
                let suffix_found = (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.par_eq(&fst[i..], snd));
                let clear_mask: Vec<_> = scan(
                    suffix_found,
                    |found_p, y| self.0.boolean_bitor(found_p, y),
                    empty_pattern,
                )
                .collect();
                let found = clear_mask
                    .last()
                    .cloned()
                    .unwrap_or_else(|| self.false_ct());
                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(fst.par_iter().zip(clear_mask).map(|(c, found)| {
                    let cond = self.0.boolean_bitand(&found, &not_empty_pattern);
                    self.0
                        .if_then_else_parallelized(&cond, &self.zero_ct(), c.as_ref())
                        .into()
                }));
                (found, FheString::new_unchecked_padded(result))
            }
            (FheString::Unpadded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                if pat.len() > fst.len() {
                    return (self.false_ct(), encrypted_str.clone());
                }
                let suffix_start = fst.len() - pat.len();
                let suffix_found = self.starts_with_clear_par(&fst[suffix_start..], pat);
                let zero = self.zero_ct();
                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(
                    fst.par_iter().enumerate().map(|(i, c)| {
                        self.zero_out_suffix(suffix_start, &suffix_found, &zero, i, c)
                    }),
                );
                result.push(zero.into());
                (suffix_found, FheString::new_unchecked_padded(result))
            }
            (FheString::Unpadded(_), Pattern::Encrypted(pat @ FheString::Unpadded(_))) => {
                let snd = pat.as_ref();
                if snd.is_empty() {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                if snd.len() > fst.len() {
                    return (self.false_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                let suffix_start = fst.len() - snd.len();
                let suffix_found = self.par_eq(&fst[suffix_start..], snd);
                let zero = self.zero_ct();
                let mut result = Vec::with_capacity(fst.len());
                result.par_extend(
                    fst.par_iter().enumerate().map(|(i, c)| {
                        self.zero_out_suffix(suffix_start, &suffix_found, &zero, i, c)
                    }),
                );
                result.push(zero.into());
                (suffix_found, FheString::new_unchecked_padded(result))
            }
            // TODO: more effiecient versions for combinations of padded and unpadded
            (x, Pattern::Encrypted(y)) => {
                let px = self.pad_string(x);
                let py = self.pad_string(y);
                self.strip_suffix(&px, &py)
            }
        }
    }

    /// A helper that returns a zero if the suffix was found
    /// or the original character if not
    fn zero_out_suffix(
        &self,
        suffix_start: usize,
        suffix_found: &FheBool,
        zero: &FheUsize,
        i: usize,
        c: &FheAsciiChar,
    ) -> FheAsciiChar {
        if i < suffix_start {
            c.clone()
        } else {
            self.0
                .if_then_else_parallelized(suffix_found, zero, c.as_ref())
                .into()
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["foo9bar", "foofoo", "banana"],
        ["foo9", "bar", "ana"],
        1..=3
    )]
    fn test_strip_suffix_padded(input: &str, pattern: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, &encrypted_pattern))
                .as_deref()
        );
    }

    #[test_matrix(
        ["foo9bar", "foofoo", "banana"],
        ["foo9", "bar", "ana"]
    )]
    fn test_strip_suffix_unpadded(input: &str, pattern: &str) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);
        let encrypted_str = client_key.encrypt_str(input).unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key.encrypt_str(pattern).unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, &encrypted_pattern))
                .as_deref()
        );
    }
}
