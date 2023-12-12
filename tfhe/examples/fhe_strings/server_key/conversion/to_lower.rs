use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::FheString;
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns the lowercase equivalent of this encrypted string as a new [`FheString`].
    ///
    /// 'Lowercase' is defined as adding 32 to the uppercase character, otherwise it remains the
    /// same.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
    ///
    /// let s = client_key.encrypt_str("HELLO").unwrap();
    /// assert_eq!(
    ///     "hello",
    ///     client_key.decrypt_str(&server_key.to_lowercase(&s))
    /// );
    ///
    /// let s = client_key.encrypt_str("hello").unwrap();
    /// assert_eq!(
    ///     "hello",
    ///     client_key.decrypt_str(&server_key.to_lowercase(&s))
    /// );
    /// ```
    #[must_use = "this returns the lowercase string as a new FheString, \
                      without modifying the original"]
    pub fn to_lowercase(&self, encrypted_str: &FheString) -> FheString {
        let result = encrypted_str
            .as_ref()
            .par_iter()
            .map(|x| self.char_to_lower(x))
            .collect();
        match encrypted_str {
            FheString::Padded(_) => FheString::Padded(result),
            FheString::Unpadded(_) => FheString::Unpadded(result),
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["HELLO", "hell"],
        1..=3
    )]
    fn test_to_lowercase_padded(input: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(
            input.to_lowercase(),
            client_key.decrypt_str(&server_key.to_lowercase(&encrypted_str))
        );
    }

    #[test_matrix(
        ["HELLO", "hell"]
    )]
    fn test_to_lowercase_unpadded(input: &str) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str(input).unwrap();
        assert_eq!(
            input.to_lowercase(),
            client_key.decrypt_str(&server_key.to_lowercase(&encrypted_str))
        );
    }
}
