use crate::ciphertext::{FheBool, FheString, Padded, Pattern, Unpadded};
use crate::server_key::ServerKey;

impl ServerKey {
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

    pub fn starts_with_unpadded<'a, P: Into<Pattern<'a, Unpadded>>>(
        &self,
        encrypted_str: &FheString<Unpadded>,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => self.starts_with_clear_par(encrypted_str.as_ref(), pat),
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.is_empty() {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                if snd.len() > fst.len() {
                    return self.false_ct();
                }
                self.par_eq(fst, snd)
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
        ["bananas"],
        ["bana", "nana"],
        1..=3
    )]
    fn test_starts_with_padded(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        assert_eq!(
            input.starts_with(pattern),
            client_key.decrypt_bool(&server_key.starts_with(&encrypted_str, pattern))
        );
        assert_eq!(
            input.starts_with(pattern),
            client_key.decrypt_bool(&server_key.starts_with(&encrypted_str, &encrypted_pattern))
        );
    }

    #[test_matrix(
        ["bananas"],
        ["bana", "nana"]
    )]
    fn test_starts_with_unpadded(input: &str, pattern: &str) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_unpadded(input).unwrap();
        let encrypted_pattern = client_key.encrypt_str_unpadded(pattern).unwrap();
        assert_eq!(
            input.starts_with(pattern),
            client_key.decrypt_bool(&server_key.starts_with_unpadded(&encrypted_str, pattern))
        );
        assert_eq!(
            input.starts_with(pattern),
            client_key
                .decrypt_bool(&server_key.starts_with_unpadded(&encrypted_str, &encrypted_pattern))
        );
    }
}
