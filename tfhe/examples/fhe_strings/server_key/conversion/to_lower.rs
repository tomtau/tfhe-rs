use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheString, FheStringPadding};
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
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
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
    pub fn to_lowercase<P: FheStringPadding>(&self, encrypted_str: &FheString<P>) -> FheString<P> {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| self.char_to_lower(x))
                .collect(),
        )
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["HELLO", "hell"],
        1..=3
    )]
    fn test_to_lowercase_padded(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

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
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_unpadded(input).unwrap();
        assert_eq!(
            input.to_lowercase(),
            client_key.decrypt_str(&server_key.to_lowercase(&encrypted_str))
        );
    }
}
