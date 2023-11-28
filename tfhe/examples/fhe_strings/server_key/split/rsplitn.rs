use rayon::iter::{ParallelExtend, ParallelIterator};

use crate::ciphertext::{FheBool, FheString, FheUsize, Number, Padded, Pattern};
use crate::server_key::ServerKey;

use super::{FhePatternLen, FheSplitResult, SplitFoundPattern};

impl ServerKey {
    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by a pattern, starting from the end of the string,
    /// restricted to returning at most `n` items.
    ///
    /// If `n` substrings are returned, the last substring (the `n`th substring)
    /// will contain the remainder of the string.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// `n` can either be a [`Number::Clear`] or a [`Number::Encrypted`].
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will not be double ended, because it is not
    /// efficient to support.
    ///
    /// For splitting from the front, the [`splitn`] method can be used.
    ///
    /// [`splitn`]: ServerKey::splitn
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
    ///     client_key.decrypt_split(server_key.rsplitn(s, 3, " ")),
    ///     vec!["lamb", "little", "Mary had a"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleopard").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplitn(s, 3, "X")),
    ///     vec!["leopard", "tiger", "lionX"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leopard").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplitn(s, 2, "::")),
    ///     vec!["leopard", "lion::tiger"]
    /// );
    /// ```
    #[inline]
    pub fn rsplitn<'a, N: Into<Number>, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        n: N,
        pat: P,
    ) -> FheSplitResult {
        let (zero_count, pat_len, pattern_splits) = self.rsplitn_inner(encrypted_str, n, pat);
        FheSplitResult::RSplitN(zero_count, pat_len, pattern_splits)
    }

    #[inline]
    pub(super) fn rsplitn_inner<'a, N: Into<Number>, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        n: N,
        pat: P,
    ) -> (Option<FheBool>, FhePatternLen, SplitFoundPattern) {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match (pat.into(), n.into()) {
            (_, Number::Clear(0)) => (
                Some(self.true_ct()),
                FhePatternLen::Plain(0),
                Default::default(),
            ),
            (Pattern::Clear(p), Number::Clear(_)) if p.len() > str_ref.len() => (
                None,
                FhePatternLen::Plain(p.len()),
                self.larger_clear_pattern_split(str_ref),
            ),
            (Pattern::Clear(p), n) if p.is_empty() => {
                // TODO: more efficient way
                let empty_pat = FheString::new_unchecked(vec![self.false_ct().into()]);
                self.rsplitn_inner(encrypted_str, n, Pattern::Encrypted(&empty_pat))
            }
            (Pattern::Clear(pat), max_count) => {
                let zero_count = match &max_count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0_u64)),
                    _ => None,
                };
                let mut rev_str_ref = str_ref.to_vec();
                rev_str_ref.reverse();
                let pat_rev: String = pat.chars().rev().collect();
                let zero = self.false_ct();
                let mut split_sequence = SplitFoundPattern::new();
                let mut accumulated_starts = self
                    .clear_accumulated_starts(str_len, &rev_str_ref, &pat_rev, Some(&max_count))
                    .filter_map(|x| {
                        x.map(|(count, starts_y)| {
                            let (starts, (in_pattern, le_maxcount)) = rayon::join(
                                || self.0.scalar_eq_parallelized(&starts_y, 1),
                                || self.check_in_pattern_max_count(&max_count, count, &starts_y),
                            );
                            self.check_le_max_count(starts, in_pattern, le_maxcount)
                        })
                    })
                    .collect::<Vec<_>>();
                accumulated_starts.reverse();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                (zero_count, FhePatternLen::Plain(pat.len()), split_sequence)
            }
            (Pattern::Encrypted(pat), count) => {
                let zero_count = match &count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0_u64)),
                    _ => None,
                };
                let (orig_len, split_sequence) =
                    self.encrypted_rsplit(str_len, str_ref, pat, Some(count));
                (
                    zero_count,
                    FhePatternLen::Encrypted(orig_len),
                    split_sequence,
                )
            }
        }
    }

    #[inline]
    pub(super) fn check_le_max_count(
        &self,
        starts: FheUsize,
        in_pattern: FheUsize,
        le_maxcount: Option<FheUsize>,
    ) -> (FheUsize, FheUsize) {
        if let Some(mc) = le_maxcount {
            rayon::join(
                || self.0.bitand_parallelized(&starts, &mc),
                || self.0.bitand_parallelized(&in_pattern, &mc),
            )
        } else {
            (starts, in_pattern)
        }
    }

    #[inline]
    pub(super) fn check_in_pattern_max_count(
        &self,
        max_count: &Number,
        count: Option<FheUsize>,
        starts_y: &FheUsize,
    ) -> (FheUsize, Option<FheUsize>) {
        (
            self.0.scalar_gt_parallelized(starts_y, 0u64),
            match (&max_count, count.as_ref()) {
                (Number::Clear(mc), Some(c)) => Some(self.0.scalar_lt_parallelized(c, *mc as u64)),
                (Number::Encrypted(mc), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
                _ => None,
            },
        )
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn rsplitn_test((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
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
            input.rsplitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplitn(&encrypted_str, n, split_pattern))
        );
        println!("clear encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.rsplitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplitn(
                &encrypted_str,
                encrypted_n.clone(),
                split_pattern,
            ))
        );
        println!("encrypted clear: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.rsplitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplitn(
                &encrypted_str,
                n,
                &encrypted_split_pattern,
            ))
        );
        println!("encrypted encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.rsplitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplitn(
                &encrypted_str,
                encrypted_n,
                &encrypted_split_pattern,
            ))
        );
    }

    #[test_matrix(
        [("Mary had a little lamb", 3, " "),
        ("", 3, "X"),
        ("lionXXtigerXleopard", 3, "X"),
        ("lion::tiger::leopard", 2, "::"),],
        1..=3
    )]
    fn test_rsplitn((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
        rsplitn_test((input, n, split_pattern), padding_len)
    }

    #[test_matrix(
        ["rust", ""],
        0..=3,
        1..=3
    )]
    fn test_rsplitn_empty(input: &str, n: usize, padding_len: usize) {
        rsplitn_test((input, n, ""), padding_len)
    }
}
