use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator,
};

use crate::ciphertext::{FheString, Padded, Pattern};
use crate::scan::scan;
use crate::server_key::ServerKey;

use super::{FheSplitResult, SplitFoundPattern};

impl ServerKey {
    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern. Differs from the iterator produced by
    /// `split` in that `split_inclusive` leaves the matched part as the
    /// terminator of the substring.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("Mary had a little lamb\nlittle lamb\nlittle lamb.").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "\n")),
    ///   vec![Mary had a little lamb\n", "little lamb\n", "little lamb."]
    /// );
    /// ```
    ///
    /// If the last element of the string is matched,
    /// that element will be considered the terminator of the preceding substring.
    /// That substring will be the last item returned by the iterator.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key
    ///     .encrypt_str("Mary had a little lamb\nlittle lamb\nlittle lamb.\n")
    ///     .unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split_inclusive(s, "\n")),
    ///     vec![
    ///         "Mary had a little lamb\n",
    ///         "little lamb\n",
    ///         "little lamb.\n"
    ///     ]
    /// );
    /// ```
    #[inline]
    pub fn split_inclusive<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => {
                FheSplitResult::SplitInclusive(self.empty_clear_pattern_split(str_ref, false, None))
            }
            Pattern::Clear(p) if p.len() > str_ref.len() => {
                FheSplitResult::SplitInclusive(self.larger_clear_pattern_split(str_ref))
            }
            Pattern::Clear(pat) => {
                let accumulated_starts = self
                    .clear_accumulated_starts(str_len, str_ref, pat, None)
                    .filter_map(|x| x.map(|(_, y)| self.0.scalar_eq_parallelized(&y, 1)))
                    .collect::<Vec<_>>();
                FheSplitResult::SplitInclusive(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned())
                        .collect(),
                )
            }
            Pattern::Encrypted(pat) => {
                let zero = self.false_ct();
                let is_empty = self.is_empty(pat);
                let mut split_sequence = SplitFoundPattern::new();
                split_sequence.push_back((is_empty.clone(), zero.into()));
                let pat_ref = pat.as_ref();
                let pat_len = self.0.max_parallelized(&self.len(pat), &is_empty);
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_encrypted_par(&str_ref[i..], pat_ref);
                    Some(self.0.mul_parallelized(&starts, &pat_len))
                });

                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                start_y,
                            );
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| x.map(|y| self.0.scalar_eq_parallelized(&y, 1)))
                .collect();
                split_sequence.par_extend(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned()),
                );
                FheSplitResult::SplitInclusive(split_sequence)
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
        [("Mary had a little lamb\nlittle lamb\nlittle lamb.", "\n"),
        ("Mary had a little lamb\nlittle lamb\nlittle lamb.\n", "\n"),
        ("", "X"),
        ("lionXXtigerXleo", "X"),
        ("lion::tiger::leo", "::"),
        ("9999a99b9c", "9"),
        ("(///)", "/"),
        ("010", "0"),
        ("rust", ""),
        ("    a  b c", " "),
        ("banana", "ana"),
        ("foo:bar", "foo:"),
        ("foo:bar", "bar"),],
        1..=3
    )]
    fn test_split_inclusive((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
            .unwrap();
        assert_eq!(
            input.split_inclusive(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split_inclusive(&encrypted_str, split_pattern))
        );
        assert_eq!(
            input.split_inclusive(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(
                server_key.split_inclusive(&encrypted_str, &encrypted_split_pattern)
            )
        );
    }
}
