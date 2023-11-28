use std::cmp::Ordering;

use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, Padded, Unpadded};
use crate::server_key::ServerKey;

impl ServerKey {
    /// Checks that two encrypted strings are an ASCII case-insensitive match
    /// and returns an encrypted `true` (`1`) if they are.
    ///
    /// Same as `eq(to_lowercase(a), to_lowercase(b))`,
    /// but without allocating and copying temporaries.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s1 = client_key.encrypt_str("Ferris").unwrap();
    /// let s2 = client_key.encrypt_str("FERRIS").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.eq_ignore_case(&s1, &s2)));
    /// ```
    #[must_use]
    #[inline]
    pub fn eq_ignore_case(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.0.bitand_parallelized(
                &self.par_eq_ignore_ascii_case(fst, &snd[..fst.len()]),
                &self.par_eq_zero(&snd[fst.len()..]),
            ),
            Ordering::Equal => self.par_eq_ignore_ascii_case(fst, snd),
            Ordering::Greater => self.0.bitand_parallelized(
                &self.par_eq_ignore_ascii_case(&fst[..snd.len()], snd),
                &self.par_eq_zero(&fst[snd.len()..]),
            ),
        }
    }

    #[must_use]
    #[inline]
    pub fn eq_ignore_case_unpadded(
        &self,
        encrypted_str: &FheString<Unpadded>,
        other_encrypted_str: &FheString<Unpadded>,
    ) -> FheBool {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        match fst.len().cmp(&snd.len()) {
            Ordering::Less => self.false_ct(),
            Ordering::Equal => self.par_eq_ignore_ascii_case(fst, snd),
            Ordering::Greater => self.false_ct(),
        }
    }

    /// A helper that checks that two encrypted strings are an ASCII case-insensitive match
    /// and returns an encrypted `true` (`1`) if they are.
    /// This function assumes the string slices are of the same length.
    #[inline]
    fn par_eq_ignore_ascii_case(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd)
            .map(|(x, y)| {
                let (lower_x, lower_y) =
                    rayon::join(|| self.char_to_lower(x), || self.char_to_lower(y));
                Some(self.0.eq_parallelized(lower_x.as_ref(), lower_y.as_ref()))
            })
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        "ferris",
        "FERRIS",
        1..=3
    )]
    fn test_eq_ignore_case_padded(input1: &str, input2: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str2 = client_key.encrypt_str(input2).unwrap();
        let encrypted_str = client_key.encrypt_str_padded(input1, padding_len).unwrap();
        assert_eq!(
            input1.eq_ignore_ascii_case(input2),
            client_key.decrypt_bool(&server_key.eq_ignore_case(&encrypted_str, &encrypted_str2))
        );
    }

    #[test_matrix("ferris", "FERRIS")]
    fn test_eq_ignore_case_unpadded(input1: &str, input2: &str) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str2 = client_key.encrypt_str_unpadded(input2).unwrap();
        let encrypted_str = client_key.encrypt_str_unpadded(input1).unwrap();
        assert_eq!(
            input1.eq_ignore_ascii_case(input2),
            client_key
                .decrypt_bool(&server_key.eq_ignore_case_unpadded(&encrypted_str, &encrypted_str2))
        );
    }
}
