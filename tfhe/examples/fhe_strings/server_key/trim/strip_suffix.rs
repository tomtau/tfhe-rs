use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};

use crate::ciphertext::{FheOption, FheString, Padded, Pattern};
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
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
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
    pub fn strip_suffix<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        suffix: P,
    ) -> FheOption<FheString<Padded>> {
        match suffix.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return (self.true_ct(), encrypted_str.clone());
                }
                let fst = encrypted_str.as_ref();
                if pat.len() > fst.len() {
                    return (self.false_ct(), encrypted_str.clone());
                }
                let suffix_found = self
                    .find_clear_pattern_suffixes(fst, pat)
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
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
    ["foo9bar", "foofoo", "banana"],
    ["foo9", "bar", "ana"],
    1..=3
    )]
    fn test_strip_suffix(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key
            .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.strip_suffix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, &encrypted_pattern))
                .as_deref()
        );
    }
}
