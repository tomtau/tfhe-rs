use std::cmp::Ordering;

use crate::ciphertext::{FheBool, FheString, Padded, Unpadded};
use crate::server_key::ServerKey;

impl ServerKey {
    /// This method tests inequality (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `!=` operator.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("A").unwrap();
    /// let s2 = client_key.encrypt_str("B").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.ne(&s1, &s2)));
    /// assert!(!client_key.decrypt_bool(&server_key.ne(&s1, &s1)));
    /// ```
    #[inline]
    #[must_use]
    pub fn ne(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.0.bitor_parallelized(
                &self.par_ne(fst, &snd[..fst.len()]),
                &self.par_ne_zero(&snd[fst.len()..]),
            ),
            Ordering::Equal => self.par_ne(fst, snd),
            Ordering::Greater => self.0.bitor_parallelized(
                &self.par_ne(&fst[..snd.len()], snd),
                &self.par_ne_zero(&fst[snd.len()..]),
            ),
        }
    }

    #[inline]
    #[must_use]
    pub fn ne_unpadded(
        &self,
        encrypted_str: &FheString<Unpadded>,
        other_encrypted_str: &FheString<Unpadded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.true_ct(),
            Ordering::Equal => self.par_ne(fst, snd),
            Ordering::Greater => self.true_ct(),
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
        ["A", "bananas"],
        ["B", "ana", "apples", "ban", "bbn"],
        1..=3
    )]
    fn test_ne_padded(input_a: &str, input_b: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s1 = client_key.encrypt_str_padded(input_a, padding_len).unwrap();
        let s2 = client_key.encrypt_str_padded(input_b, padding_len).unwrap();
        assert_eq!(
            input_a != input_b,
            client_key.decrypt_bool(&server_key.ne(&s1, &s2))
        );
        assert_eq!(
            input_a != input_a,
            client_key.decrypt_bool(&server_key.ne(&s1, &s1))
        );
        assert_eq!(
            input_b != input_a,
            client_key.decrypt_bool(&server_key.ne(&s2, &s1))
        );
    }

    #[test_matrix(
            ["A", "bananas"],
            ["B", "ana", "apples", "ban", "bbn"]
    )]
    fn test_ne_unpadded(input_a: &str, input_b: &str) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s1 = client_key.encrypt_str_unpadded(input_a).unwrap();
        let s2 = client_key.encrypt_str_unpadded(input_b).unwrap();
        assert_eq!(
            input_a != input_b,
            client_key.decrypt_bool(&server_key.ne_unpadded(&s1, &s2))
        );
        assert_eq!(
            input_a != input_a,
            client_key.decrypt_bool(&server_key.ne_unpadded(&s1, &s1))
        );
        assert_eq!(
            input_b != input_a,
            client_key.decrypt_bool(&server_key.ne_unpadded(&s2, &s1))
        );
    }
}
