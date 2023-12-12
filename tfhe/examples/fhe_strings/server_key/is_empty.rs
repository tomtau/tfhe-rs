use crate::ciphertext::{FheBool, FheString};

use super::ServerKey;

impl ServerKey {
    /// Returns an encrypted `true` (`1`) if `encrypted_str` has a length of zero bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
        match encrypted_str {
            FheString::Padded(_) => self
                .0
                .scalar_eq_parallelized(encrypted_str.as_ref()[0].as_ref(), 0),
            FheString::Unpadded(_) => {
                if encrypted_str.as_ref().is_empty() {
                    self.true_ct()
                } else {
                    self.false_ct()
                }
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
        1..=3
    )]
    fn test_is_empty(padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let input = "";
        let input2 = "not_empty";
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_str2 = client_key.encrypt_str_padded(input2, padding_len).unwrap();

        assert_eq!(
            input.is_empty(),
            client_key.decrypt_bool(&server_key.is_empty(&encrypted_str))
        );
        assert_eq!(
            input2.is_empty(),
            client_key.decrypt_bool(&server_key.is_empty(&encrypted_str2))
        );
    }
}
