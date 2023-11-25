use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheString, Padded};
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
    pub fn to_lowercase(&self, encrypted_str: &FheString<Padded>) -> FheString<Padded> {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'A' == 65, 'Z' == 90
                    let (is_upper, converted) = rayon::join(
                        || self.check_scalar_range(x, 65, 90),
                        || self.0.scalar_add_parallelized(x.as_ref(), 32),
                    );
                    // (is_upper & converted) | (!is_upper & x)
                    self.0
                        .if_then_else_parallelized(&is_upper, &converted, x.as_ref())
                        .into()
                })
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
    fn test_to_lowercase(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.to_lowercase(),
            client_key.decrypt_str(&server_key.to_lowercase(&encrypted_str))
        );
    }
}
