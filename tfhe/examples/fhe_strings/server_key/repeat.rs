use dashmap::DashMap;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number};

use super::ServerKey;

impl ServerKey {
    /// Creates a new [`FheString`] by repeating a string `n` times.
    ///
    /// `n` can either be a [`Number::Clear`] or a [`Number::Encrypted`].
    /// If `n` is encrypted, the function will trim the result to the maximum
    /// length of the padded length of `FheString` times 256.
    ///
    /// # Panics
    ///
    /// This function will panic if the capacity would overflow.
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
    /// let s = client_key.encrypt_str("abc").unwrap();
    /// assert_eq!(
    ///     "abcabcabcabc",
    ///     client_key.decrypt_str(&server_key.repeat(&s, 4))
    /// );
    /// let n = client_key.encrypt_usize(4);
    /// assert_eq!(
    ///     "abcabcabcabc",
    ///     client_key.decrypt_str(&server_key.repeat(&s, n))
    /// );
    /// ```
    ///
    /// A panic upon overflow:
    ///
    /// ```should_panic
    /// // this will panic at runtime
    /// let s = client_key.encrypt_str("0123456789abcdef").unwrap();
    /// let huge = server_key.repeat(&s, usize::MAX);
    /// ```
    #[must_use]
    pub fn repeat<N: Into<Number>>(&self, encrypted_str: &FheString, n: N) -> FheString {
        let str_ref = encrypted_str.as_ref();
        let zero = self.false_ct();

        match (encrypted_str, n.into()) {
            (_, Number::Clear(0)) => FheString::new_unchecked_unpadded(vec![]),
            (_, Number::Clear(1)) => encrypted_str.clone(),
            (FheString::Padded(_), Number::Clear(rep_l)) if rep_l < 8 => {
                // on M2, it seems to be faster to do this for smaller `n`
                // even though concat isn't that optimized now
                let substrings = DashMap::new();
                substrings.insert(1, encrypted_str.clone());
                let result = self.repeat_clear_rec(&substrings, rep_l).clone();
                result
            }
            (FheString::Padded(_), Number::Clear(rep_l)) => {
                let mut result = Vec::with_capacity(str_ref.len() * rep_l);

                let str_len = self.len(encrypted_str);

                (0..str_ref.len() * rep_l)
                    .into_par_iter()
                    .map(|i| {
                        self.duplicate_padded_str_char(
                            str_ref,
                            &zero,
                            Number::Clear(rep_l),
                            &str_len,
                            i,
                        )
                    })
                    .collect_into_vec(&mut result);
                FheString::new_unchecked_padded(result)
            }
            (FheString::Padded(_), Number::Encrypted(rep_l)) => {
                // for the encrypted number, we don't know the exact length
                // so we allocated as if we would repeat the string 256 times (at most)
                const MAX_REP_L: usize = 256;
                let mut result = Vec::with_capacity(str_ref.len() * MAX_REP_L);

                let str_len = self.len(encrypted_str);

                (0..str_ref.len() * MAX_REP_L)
                    .into_par_iter()
                    .map(|i| {
                        self.duplicate_padded_str_char(
                            str_ref,
                            &zero,
                            Number::Encrypted(rep_l.clone()),
                            &str_len,
                            i,
                        )
                    })
                    .collect_into_vec(&mut result);

                FheString::new_unchecked_padded(result)
            }
            (FheString::Unpadded(_), Number::Clear(rep_l)) => {
                let str_ref = encrypted_str
                    .as_ref()
                    .par_iter()
                    .map(|c| c.as_ref())
                    .collect::<Vec<_>>();
                FheString::new_unchecked_unpadded(
                    str_ref
                        .repeat(rep_l)
                        .par_iter()
                        .map(|c| (*c).clone().into())
                        .collect(),
                )
            }
            (FheString::Unpadded(_), Number::Encrypted(rep_l)) => {
                const MAX_REP_L: usize = 256;

                let str_ref = encrypted_str
                    .as_ref()
                    .par_iter()
                    .map(|c| c.as_ref())
                    .collect::<Vec<_>>();
                let zero = self.false_ct();
                let len = self.0.scalar_mul_parallelized(&rep_l, str_ref.len() as u64);
                let mut result = str_ref
                    .repeat(MAX_REP_L)
                    .par_iter()
                    .enumerate()
                    .map(|(i, c)| {
                        let cond = self.0.scalar_gt_parallelized(&len, i as u64);
                        self.0.if_then_else_parallelized(&cond, *c, &zero).into()
                    })
                    .collect::<Vec<_>>();
                result.push(self.false_ct().into());
                FheString::new_unchecked_padded(result)
            }
        }
    }

    /// This helper will find the `i`th character based on the `str_ref` and `n`.
    #[inline]
    fn duplicate_padded_str_char(
        &self,
        str_ref: &[FheAsciiChar],
        zero: &FheBool,
        n: Number,
        str_len: &FheUsize,
        i: usize,
    ) -> FheAsciiChar {
        let mut enc_i: FheUsize = self.0.create_trivial_radix(i as u64, self.1);
        let len_mul = self.0.div_parallelized(&enc_i, str_len);
        let (sub_comp, not_reached_end) = rayon::join(
            || self.0.mul_parallelized(str_len, &len_mul),
            || match n {
                Number::Clear(rep_l) => self.0.scalar_lt_parallelized(&len_mul, rep_l as u64),
                Number::Encrypted(rep_l) => self.0.lt_parallelized(&len_mul, &rep_l),
            },
        );
        // shift the index to the correct position
        self.0.sub_assign_parallelized(&mut enc_i, &sub_comp);

        // find the character or 0 if we reached the end / N
        (0..str_ref.len())
            .into_par_iter()
            .map(|j| {
                let mut cond = self.0.scalar_eq_parallelized(&enc_i, j as u64);
                self.0
                    .bitand_assign_parallelized(&mut cond, &not_reached_end);
                self.0
                    .if_then_else_parallelized(&cond, str_ref[j].as_ref(), zero)
            })
            .reduce(|| zero.clone(), |a, b| self.0.bitxor_parallelized(&a, &b))
            .into()
    }

    /// this is a recursive helper that will fill the `substrings` map
    fn repeat_clear_rec<'a>(
        &self,
        substrings: &'a DashMap<usize, FheString>,
        n: usize,
    ) -> dashmap::mapref::one::Ref<'a, usize, FheString> {
        if let Some(s) = substrings.get(&n) {
            // if we already have the result, return it
            s
            // or if we have the partial result, we can just concat it with the other half
        } else if let Some(s) = (n - 1..=n / 2).into_par_iter().find_map_any(|i| {
            if let Some(s) = substrings.get(&i) {
                let prev = self.repeat_clear_rec(substrings, n - i);
                let concatted = self.concat(&prev, &s);
                substrings.insert(n, concatted);
                Some(substrings.get(&n).expect("just inserted"))
            } else {
                None
            }
        }) {
            s
        } else {
            let prev = self.repeat_clear_rec(substrings, n - 1);
            let concatted =
                self.concat(&prev, &substrings.get(&1).expect("one should be inserted"));
            substrings.insert(n, concatted);
            return substrings.get(&n).expect("just inserted");
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
        "abc",
        0..=4,
        1..=3
    )]
    fn test_repeat_padded(input: &str, n: usize, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_n = client_key.encrypt_usize(n);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();

        assert_eq!(
            input.repeat(n),
            client_key.decrypt_str(&server_key.repeat(&encrypted_str, n))
        );
        assert_eq!(
            input.repeat(n),
            client_key.decrypt_str(&server_key.repeat(&encrypted_str, encrypted_n.clone()))
        );
    }

    #[test_matrix(
        "abc",
        0..=4
    )]
    fn test_repeat_unpadded(input: &str, n: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_n = client_key.encrypt_usize(n);

        let encrypted_str = client_key.encrypt_str(input).unwrap();

        assert_eq!(
            input.repeat(n),
            client_key.decrypt_str(&server_key.repeat(&encrypted_str, n))
        );
        assert_eq!(
            input.repeat(n),
            client_key.decrypt_str(&server_key.repeat(&encrypted_str, encrypted_n.clone()))
        );
    }
}
