use std::cmp::Ordering;

use crate::ciphertext::{FheBool, FheString, Padded};
use crate::server_key::ServerKey;

impl ServerKey {
    /// This method tests greater than or equal to (for `encrypted_str` and `other_encrypted_str`)
    /// and is equivalent to the `>=` operator. The ordering is lexicographical.
    ///
    /// Lexicographical comparison is an operation with the following properties:
    ///
    /// - Two sequences are compared element by element.
    /// - The first mismatching element defines which sequence is lexicographically less or greater
    ///   than the other.
    /// - If one sequence is a prefix of another, the shorter sequence is lexicographically less
    ///   than the other.
    /// - If two sequence have equivalent elements and are of the same length, then the sequences
    ///   are lexicographically equal.
    /// - An empty sequence is lexicographically less than any non-empty sequence.
    /// - Two empty sequences are lexicographically equal.
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
    /// assert!(!client_key.decrypt_bool(&server_key.ge(&s1, &s2)));
    /// assert!(client_key.decrypt_bool(&server_key.ge(&s1, &s1)));
    /// assert!(client_key.decrypt_bool(&server_key.ge(&s2, &s1)));
    /// ```
    #[inline]
    #[must_use]
    pub fn ge(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => {
                let (any_ne, leftmost_gt) = self.par_ge(fst, &snd[..fst.len()]);

                self.if_then_else(
                    any_ne.as_ref(),
                    false,
                    &leftmost_gt,
                    &self.par_eq_zero(&snd[fst.len()..]),
                )
            }
            Ordering::Equal => {
                let (any_ne, leftmost_gt) = self.par_ge(fst, snd);
                self.if_then_else(any_ne.as_ref(), false, &leftmost_gt, &self.true_ct())
            }
            Ordering::Greater => {
                let (any_ne, leftmost_gt) = self.par_ge(&fst[..snd.len()], snd);
                self.if_then_else(any_ne.as_ref(), false, &leftmost_gt, &self.true_ct())
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
        ["A", "bananas"],
        ["B", "ana", "apples", "ban", "bbn"],
        1..=3
    )]
    fn test_ge(input_a: &str, input_b: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s1 = client_key
            .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
            .unwrap();
        let s2 = client_key
            .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input_a >= input_b,
            client_key.decrypt_bool(&server_key.ge(&s1, &s2))
        );
        assert_eq!(
            input_a >= input_a,
            client_key.decrypt_bool(&server_key.ge(&s1, &s1))
        );
        assert_eq!(
            input_b >= input_a,
            client_key.decrypt_bool(&server_key.ge(&s2, &s1))
        );
    }
}
