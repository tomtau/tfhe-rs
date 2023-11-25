use dashmap::DashMap;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator,
};
use rayon::slice::ParallelSlice;

use crate::ciphertext::{FheBool, FheString, Padded};
use crate::scan::scan;
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns a new [`FheString`] with trailing whitespace removed.
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
    ///     "\n Hello\tworld",
    ///     client_key.decrypt_str(&server_key.trim_end(&s))
    /// );
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                      without modifying the original"]
    pub fn trim_end(&self, encrypted_str: &FheString<Padded>) -> FheString<Padded> {
        let fst = encrypted_str.as_ref();
        if fst.len() < 2 {
            return encrypted_str.clone();
        }
        let cache_is_whitespace: DashMap<usize, FheBool> = DashMap::with_capacity(fst.len() - 1);
        let right_boundaries_ended = fst.par_windows(2).enumerate().map(|(i, window)| {
            let left_whitespace = cache_is_whitespace
                .get(&i)
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[0]);
                    cache_is_whitespace.insert(i, v.clone());
                    v
                });
            let right_whitespace = cache_is_whitespace
                .get(&(i + 1))
                .map(|v| v.clone())
                .unwrap_or_else(|| {
                    let v = self.is_whitespace(&window[1]);
                    cache_is_whitespace.insert(i + 1, v.clone());
                    v
                });

            (
                Some(self.0.bitand_parallelized(
                    &self.0.bitnot_parallelized(&left_whitespace),
                    &right_whitespace,
                )),
                Some(self.0.bitand_parallelized(
                    &left_whitespace,
                    &self.0.scalar_eq_parallelized(window[1].as_ref(), 0),
                )),
            )
        });
        let accumulated_boundaries: Vec<_> = scan(
            right_boundaries_ended.rev(),
            |(right_boundary_x, ends_with_whitespace_x),
             (right_boundary_y, ends_with_whitespace_y)| {
                (
                    self.or(right_boundary_x.as_ref(), right_boundary_y.as_ref()),
                    self.or(
                        ends_with_whitespace_x.as_ref(),
                        ends_with_whitespace_y.as_ref(),
                    ),
                )
            },
            (None, None),
        )
        .collect();
        let mut result = Vec::with_capacity(fst.len());
        result.par_extend(
            fst.into_par_iter()
                .rev()
                .skip(1)
                .zip(accumulated_boundaries)
                .map(|(c, (hit_right_boundary, ends_with_ws))| {
                    if let (Some(hrb), Some(ews)) = (hit_right_boundary, ends_with_ws) {
                        let not_hit_right_boundary = self.0.bitnot_parallelized(&hrb);
                        let cond = self.0.bitand_parallelized(&not_hit_right_boundary, &ews);
                        self.0
                            .if_then_else_parallelized(&cond, &self.false_ct(), c.as_ref())
                            .into()
                    } else {
                        c.clone()
                    }
                })
                .rev(),
        );
        result.push(fst.last().cloned().expect("last element"));
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
    fn test_trim_end(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.trim_end(),
            client_key.decrypt_str(&server_key.trim_end(&s))
        );
    }
}
