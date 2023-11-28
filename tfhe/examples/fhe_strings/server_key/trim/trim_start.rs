use dashmap::DashMap;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator,
};
use rayon::slice::ParallelSlice;
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{FheBool, FheString, Padded};
use crate::scan::scan;
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns a new [`FheString`] with leading whitespace removed.
    ///
    /// 'Whitespace' is defined as one of 6 ASCII characters (' ', '\t', '\n', '\r', '\v', '\f').
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
    /// let s = client_key.encrypt_str("\n Hello\tworld\t\n").unwrap();
    /// assert_eq!(
    ///     "Hello\tworld\t\n",
    ///     client_key.decrypt_str(&server_key.trim_start(&s))
    /// );
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                      without modifying the original"]
    pub fn trim_start(&self, encrypted_str: &FheString<Padded>) -> FheString<Padded> {
        let fst = encrypted_str.as_ref();
        let str_l = fst.len();
        if str_l < 2 {
            return encrypted_str.clone();
        }
        let cache_is_whitespace: DashMap<usize, FheBool> = DashMap::with_capacity(fst.len() - 1);
        let starts_with_ws = self.is_whitespace(&fst[0]);
        cache_is_whitespace.insert(0, starts_with_ws.clone());
        let left_boundaries_ended = fst.par_windows(2).enumerate().map(|(i, window)| {
            let (left_whitespace, right_whitespace) =
                self.check_whitespace(&cache_is_whitespace, i, window);
            (
                self.0.bitor_parallelized(
                    &self.0.scalar_eq_parallelized(&left_whitespace, 0),
                    &right_whitespace,
                ),
                left_whitespace,
            )
        });
        let accumulated_ws_before_boundary: Vec<_> = scan(
            left_boundaries_ended,
            |(ws_before_boundary_x, count_x), (ws_before_boundary_y, count_y)| {
                let (boundary_not_hit, count_xy) = rayon::join(
                    || {
                        self.0.bitand_parallelized(
                            &starts_with_ws,
                            &self
                                .0
                                .bitand_parallelized(ws_before_boundary_x, ws_before_boundary_y),
                        )
                    },
                    || self.0.add_parallelized(count_x, count_y),
                );
                let next_count =
                    self.0
                        .if_then_else_parallelized(&boundary_not_hit, &count_xy, count_x);
                (boundary_not_hit, next_count)
            },
            (starts_with_ws.clone(), starts_with_ws.clone()),
        )
        .map(|(_, count)| count)
        .collect();
        let shifted_indices: Vec<_> = (0..str_l)
            .into_par_iter()
            .map(|i| {
                self.0
                    .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1)
            })
            .zip(accumulated_ws_before_boundary)
            .map(|(i, count)| self.0.sub_parallelized(&i, &count))
            .collect();

        let mut result = Vec::with_capacity(fst.len());
        result.par_extend((0..str_l).into_par_iter().map(|i| {
            (i..shifted_indices.len())
                .into_par_iter()
                .map(|j| {
                    self.0.if_then_else_parallelized(
                        &self.0.scalar_eq_parallelized(&shifted_indices[j], i as u64),
                        fst[j].as_ref(),
                        &self.false_ct(),
                    )
                })
                .reduce(
                    || self.false_ct(),
                    |a, b| self.0.bitxor_parallelized(&a, &b),
                )
                .into()
        }));
        FheString::new_unchecked(result)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["\n Hello\tworld\t\n"],
        1..=3
    )]
    fn test_trim_start(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(
            input.trim_start(),
            client_key.decrypt_str(&server_key.trim_start(&s))
        );
    }
}
