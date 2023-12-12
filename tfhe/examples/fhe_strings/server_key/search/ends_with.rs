use rayon::prelude::*;

use crate::ciphertext::{FheBool, FheString, Pattern};
use crate::server_key::ServerKey;

impl ServerKey {
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    pub fn ends_with<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheBool {
        match (encrypted_str, pat.into()) {
            (FheString::Padded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                if pat.len() > fst.len() {
                    return self.false_ct();
                }
                self.find_clear_pattern_padded_suffixes(fst, pat)
                    .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
                    .unwrap_or_else(|| self.false_ct())
            }
            (FheString::Padded(_), Pattern::Encrypted(pat @ FheString::Padded(_))) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.par_eq(&fst[i..], snd))
                    .reduce(|| self.is_empty(pat), |x, y| self.0.boolean_bitor(&x, &y))
            }
            (FheString::Unpadded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                if pat.len() > fst.len() {
                    return self.false_ct();
                }
                self.starts_with_clear_par(&fst[fst.len() - pat.len()..], pat)
            }
            (FheString::Unpadded(_), Pattern::Encrypted(pat @ FheString::Unpadded(_))) => {
                let snd = pat.as_ref();
                if snd.is_empty() {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                if snd.len() > fst.len() {
                    return self.false_ct();
                }
                let fst = encrypted_str.as_ref();
                self.par_eq(&fst[fst.len() - snd.len()..], snd)
            }
            // TODO: more effiecient versions for combinations of padded and unpadded
            (x, Pattern::Encrypted(y)) => {
                let px = self.pad_string(x);
                let py = self.pad_string(y);
                self.ends_with(&px, &py)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["bananas"],
        ["anas", "nana", "ana"],
        1..=3
    )]
    fn test_ends_with_padded(input: &str, pattern: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, pattern))
        );
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, &encrypted_pattern))
        );
    }

    #[test_matrix(
            ["bananas"],
            ["anas", "nana", "ana"]
        )]
    fn test_ends_with_unpadded(input: &str, pattern: &str) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str(input).unwrap();
        let encrypted_pattern = client_key.encrypt_str(pattern).unwrap();
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, pattern))
        );
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, &encrypted_pattern))
        );
    }
}
