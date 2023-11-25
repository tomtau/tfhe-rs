use std::cmp::Ordering;

use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, Padded};
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

    #[inline]
    fn par_eq_ignore_ascii_case(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd)
            .map(|(x, y)| {
                // 'a' == 97, 'z' == 122
                let (x_eq_y, ((is_lower_x, converted_x), (is_lower_y, converted_y))) = rayon::join(
                    || self.0.eq_parallelized(x.as_ref(), y.as_ref()),
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || self.check_scalar_range(x, 97, 122),
                                    || self.0.scalar_sub_parallelized(x.as_ref(), 32),
                                )
                            },
                            || {
                                rayon::join(
                                    || self.check_scalar_range(y, 97, 122),
                                    || self.0.scalar_sub_parallelized(y.as_ref(), 32),
                                )
                            },
                        )
                    },
                );

                // !is_lower_x && !is_lower_y && x_eq_y
                // || is_lower_x && is_lower_y && x_eq_y
                // || is_lower_x && !is_lower_y && converted_x == y
                // || !is_lower_x && is_lower_y && x == converted_y
                // simplifies to:
                // x_eq_y || is_lower_x && !is_lower_y && converted_x == y || !is_lower_x &&
                // is_lower_y && x == converted_y
                let ((not_is_lower_y, not_is_lower_x), (converted_x_eq_y, x_eq_converted_y)) =
                    rayon::join(
                        || {
                            rayon::join(
                                || self.0.bitnot_parallelized(&is_lower_y),
                                || self.0.bitnot_parallelized(&is_lower_x),
                            )
                        },
                        || {
                            rayon::join(
                                || self.0.eq_parallelized(&converted_x, y.as_ref()),
                                || self.0.eq_parallelized(x.as_ref(), &converted_y),
                            )
                        },
                    );
                let (is_lower_x_not_y, is_lower_y_not_x) = rayon::join(
                    || self.0.bitand_parallelized(&is_lower_x, &not_is_lower_y),
                    || self.0.bitand_parallelized(&is_lower_y, &not_is_lower_x),
                );
                let (is_lower_x_not_y_eq_converted_x, is_lower_y_not_x_eq_converted_y) =
                    rayon::join(
                        || {
                            self.0
                                .bitand_parallelized(&is_lower_x_not_y, &converted_x_eq_y)
                        },
                        || {
                            self.0
                                .bitand_parallelized(&is_lower_y_not_x, &x_eq_converted_y)
                        },
                    );
                Some(self.0.bitor_parallelized(
                    &x_eq_y,
                    &self.0.bitor_parallelized(
                        &is_lower_x_not_y_eq_converted_x,
                        &is_lower_y_not_x_eq_converted_y,
                    ),
                ))
            })
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.true_ct())
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
    fn test_eq_ignore_case(input1: &str, input2: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str2 = client_key.encrypt_str(input2).unwrap();
        let encrypted_str = client_key
            .encrypt_str_padded(input1, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input1.eq_ignore_ascii_case(input2),
            client_key.decrypt_bool(&server_key.eq_ignore_case(&encrypted_str, &encrypted_str2))
        );
    }
}
