use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, ParallelExtend, ParallelIterator,
};

use crate::ciphertext::{FheString, Pattern};
use crate::scan::scan;
use crate::server_key::ServerKey;

use super::{FhePatternLen, FheSplitResult, SplitFoundPattern};

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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn split_inclusive<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheSplitResult {
        let enc_str = self.pad_string(encrypted_str); // TODO: unpadded version
        let str_ref = enc_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => {
                {
                    // TODO: more efficient way
                    let empty_pat = FheString::new_unchecked_padded(vec![self.zero_ct().into()]);
                    let (_, split_found) =
                        self.split_inner(encrypted_str, Pattern::Encrypted(&empty_pat), false);
                    FheSplitResult::SplitInclusive(FhePatternLen::Plain(0), split_found)
                }
            }
            Pattern::Clear(p) if p.len() > str_ref.len() => FheSplitResult::SplitInclusive(
                FhePatternLen::Plain(p.len()),
                self.larger_clear_pattern_split(str_ref),
            ),
            Pattern::Clear(pat) => {
                let accumulated_starts = self
                    .clear_accumulated_starts(str_len, str_ref, pat, None)
                    .filter_map(|x| {
                        x.map(|(_, y)| self.0.scalar_eq_parallelized(&y, pat.len() as u64))
                    })
                    .collect::<Vec<_>>();
                FheSplitResult::SplitInclusive(
                    FhePatternLen::Plain(pat.len()),
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned())
                        .collect(),
                )
            }
            Pattern::Encrypted(p) => {
                let pat = self.pad_string(p); // TODO: unpadded version
                let is_empty = self.is_empty(&pat);
                let is_empty_radix = is_empty.into_radix(self.1, &self.0);
                let mut split_sequence = SplitFoundPattern::new();
                let pat_ref = pat.as_ref();
                let orig_len = self.len(&pat);
                let pat_len = self.0.max_parallelized(&orig_len, &is_empty_radix);
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_encrypted_par(&str_ref[i..], pat_ref);
                    let starts_radix = starts.into_radix(self.1, &self.0);
                    let not_ended = self.0.scalar_ne_parallelized(str_ref[i].as_ref(), 0);
                    Some((self.0.mul_parallelized(&starts_radix, &pat_len), not_ended))
                });

                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some((start_x, _not_ended_x)), Some((start_y, not_ended_y))) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start_y = self.0.if_then_else_parallelized(
                                not_ended_y,
                                start_y,
                                &self.zero_ct(),
                            );
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &next_start_y,
                            );
                            Some((next_start, not_ended_y.clone()))
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| x.map(|y| self.0.eq_parallelized(&y.0, &pat_len)))
                .collect();
                split_sequence.par_extend(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned()),
                );
                FheSplitResult::SplitInclusive(FhePatternLen::Encrypted(orig_len), split_sequence)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

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
        ("1111111", "11"),
        ("123123123", "123"),
        ("12121212121", "1212"),
        ("banana", "ana"),
        ("foo:bar", "foo:"),
        ("foo:bar", "bar"),],
        1..=3
    )]
    fn test_split_inclusive((input, split_pattern): (&str, &str), padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

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
