use rayon::iter::{ParallelExtend, ParallelIterator};

use crate::ciphertext::{FheString, Number, Pattern};
use crate::server_key::ServerKey;

use super::{FhePatternLen, FheSplitResult, SplitFoundPattern};

impl ServerKey {
    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by a pattern, restricted to returning at most `n` items.
    ///
    /// If `n` substrings are returned, the last substring (the `n`th substring)
    /// will contain the remainder of the string.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// `n` can either be a [`Number::Clear`] or a [`Number::Encrypted`].
    //
    /// # Iterator behavior
    ///
    /// The returned iterator will not be double ended, because it is
    /// not efficient to support.
    ///
    /// If the pattern allows a reverse search, the [`rsplitn`] method can be
    /// used.
    ///
    /// [`rsplitn`]: ServerKey::rsplitn
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("Mary had a little lambda").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.splitn(s, 3, " ")),
    ///   vec!["Mary", "had", "a little lambda"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleopard").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, 3, "X")),
    ///   vec!["lion", "", "tigerXleopard"]
    /// );
    ///
    /// let s = client_key.encrypt_str("abcXdef").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, 1, "X")),
    ///   vec!["abcXdef"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, 1, "X")),
    ///   vec![""]
    /// );
    #[inline]
    pub fn splitn<'a, N: Into<Number>, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        n: N,
        pat: P,
    ) -> FheSplitResult {
        let enc_str = self.pad_string(encrypted_str); // TODO: is it necessary?

        let str_ref = enc_str.as_ref();
        let str_len = str_ref.len();
        match (pat.into(), n.into()) {
            (_, Number::Clear(0)) => FheSplitResult::SplitN(
                Some(self.true_ct()),
                FhePatternLen::Plain(0),
                Default::default(),
            ),
            (Pattern::Clear(p), Number::Clear(_count)) if p.len() > str_ref.len() => {
                FheSplitResult::SplitN(
                    None,
                    FhePatternLen::Plain(p.len()),
                    self.larger_clear_pattern_split(str_ref),
                )
            }
            (Pattern::Clear(p), Number::Clear(count)) if p.is_empty() => FheSplitResult::SplitN(
                None,
                FhePatternLen::Plain(0),
                self.empty_clear_pattern_split(str_ref, true, Some(count)),
            ),

            (Pattern::Clear(pat), max_count) => {
                let zero = self.false_ct();
                let zero_count = match &max_count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0u64)),
                    _ => None,
                };
                let mut split_sequence = SplitFoundPattern::new();
                let empty_input = self.is_empty(encrypted_str);
                if pat.is_empty() {
                    match &max_count {
                        Number::Encrypted(mc) => {
                            let not_single_match = self.0.scalar_ne_parallelized(mc, 1u64);

                            split_sequence.push_back((
                                self.0.bitor_parallelized(&not_single_match, &empty_input),
                                zero.clone().into(),
                            ));
                            split_sequence.push_back((
                                self.0.bitand_parallelized(&not_single_match, &empty_input),
                                zero.clone().into(),
                            ));
                        }
                        _ => split_sequence.push_back((self.true_ct(), zero.clone().into())),
                    };
                }
                let adjust_max_count = if pat.is_empty() {
                    match max_count {
                        Number::Clear(mc) => Number::Clear(mc.saturating_sub(1)),
                        Number::Encrypted(mc) => {
                            let reduced_match = self.0.scalar_sub_parallelized(&mc, 1u64);
                            Number::Encrypted(self.0.if_then_else_parallelized(
                                &empty_input,
                                &self.false_ct(),
                                &reduced_match,
                            ))
                        }
                    }
                } else {
                    max_count
                };
                let accumulated_starts = self
                    .clear_accumulated_starts(str_len, str_ref, pat, Some(&adjust_max_count))
                    .filter_map(|x| {
                        x.map(|(count, starts_y)| {
                            let (starts, (in_pattern, le_maxcount)) = rayon::join(
                                || self.0.scalar_eq_parallelized(&starts_y, pat.len() as u64),
                                || {
                                    self.check_in_pattern_max_count(
                                        &adjust_max_count,
                                        count,
                                        &starts_y,
                                    )
                                },
                            );
                            self.check_le_max_count(starts, in_pattern, le_maxcount)
                        })
                    })
                    .collect::<Vec<_>>();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                FheSplitResult::SplitN(zero_count, FhePatternLen::Plain(pat.len()), split_sequence)
            }
            (Pattern::Encrypted(p), count) => {
                let pat = self.pad_string(p); // TODO: unpadded version

                let zero_count = match &count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0u64)),
                    _ => None,
                };
                let (orig_len, split_sequence) =
                    self.encrypted_split(str_len, str_ref, &pat, Some(count));
                FheSplitResult::SplitN(
                    zero_count,
                    FhePatternLen::Encrypted(orig_len),
                    split_sequence,
                )
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

    #[inline]
    fn splitn_test((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
            .unwrap();
        let encrypted_n = client_key.encrypt_usize(n);
        println!("clear clear: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(&encrypted_str, n, split_pattern))
        );
        println!("clear encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                encrypted_n.clone(),
                split_pattern
            ))
        );
        println!("encrypted clear: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                n,
                &encrypted_split_pattern
            ))
        );
        println!("encrypted encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                encrypted_n,
                &encrypted_split_pattern
            ))
        );
    }

    #[test_matrix(
        [("Mary had a little lamb", 3, " "),
        ("", 3, "X"),
        ("lionXXtigerXleopard", 1, "X"),
        ("abcXdef", 1, "X"),],
        1..=3
    )]
    fn test_splitn((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
        splitn_test((input, n, split_pattern), padding_len)
    }

    #[test_matrix(
        ["rust", ""],
        0..=3,
        1..=3
    )]
    fn test_splitn_empty(input: &str, n: usize, padding_len: usize) {
        splitn_test((input, n, ""), padding_len)
    }
}
