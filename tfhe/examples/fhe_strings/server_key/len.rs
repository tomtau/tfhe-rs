use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheString, FheUsize};

use super::ServerKey;

impl ServerKey {
    /// Returns the length of `encrypted_str`.
    ///
    /// This length is in bytes (minus the null-terminating byte or any zero-padding bytes).
    /// In other words, it is what a human considers the length of the ASCII string.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("foo").unwrap();
    /// let len = server_key.len(&s);
    /// assert_eq!(3, client_key.decrypt_usize(&len));
    /// ```
    #[must_use]
    #[inline]
    pub fn len(&self, encrypted_str: &FheString) -> FheUsize {
        match encrypted_str {
            FheString::Padded(_) => {
                let fst = encrypted_str.as_ref();
                fst[..fst.len() - 1]
                    .par_iter()
                    .map(|x| Some(self.0.scalar_ne_parallelized(x.as_ref(), 0)))
                    .reduce(|| None, |a, b| self.add(a.as_ref(), b.as_ref()))
                    .unwrap_or_else(|| self.false_ct())
            }
            FheString::Unpadded(_) => self
                .0
                .create_trivial_radix(encrypted_str.as_ref().len() as u64, self.1),
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
        "foo",
        1..=3
    )]
    fn test_len(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();

        assert_eq!(
            input.len(),
            client_key.decrypt_usize(&server_key.len(&encrypted_str))
        );
    }
}
