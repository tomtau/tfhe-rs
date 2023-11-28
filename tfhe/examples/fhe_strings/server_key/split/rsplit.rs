use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{FheAsciiChar, FheString, FheUsize, Number, Padded, Pattern};
use crate::scan::scan;
use crate::server_key::ServerKey;

use super::{FhePatternLen, FheSplitResult, SplitFoundPattern};

impl ServerKey {
    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern and yielded in reverse order.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Iterator behavior
    ///
    /// For iterating from the front, the [`split`] method can be used.
    ///
    /// [`split`]: ServerKey::split
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
    /// let s = client_key.encrypt_str("Mary had a little lamb").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit(s, " ")),
    ///     vec!["lamb", "little", "a", "had", "Mary"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit(s, "X")),
    ///     vec![""]
    /// );
    /// let x = client_key.encrypt_str("X").unwrap();
    /// assert_eq!(client_key.decrypt_split(server_key.rsplit(s, &x)), vec![""]);
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleopard").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit(s, "X")),
    ///     vec!["leopard", "tiger", "", "lion"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leopard").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit(s, "::")),
    ///     vec!["leopard", "tiger", "lion"]
    /// );
    /// ```
    #[inline]
    pub fn rsplit<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.rsplit_inner(encrypted_str, pat);
        FheSplitResult::RSplit(pat_len, pattern_splits)
    }

    #[inline]
    pub(super) fn rsplit_inner<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> (FhePatternLen, SplitFoundPattern) {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => (
                FhePatternLen::Plain(0),
                self.empty_clear_pattern_split(str_ref, true, None),
            ),
            Pattern::Clear(p) if p.len() > str_ref.len() => (
                FhePatternLen::Plain(p.len()),
                self.larger_clear_pattern_split(str_ref),
            ),
            Pattern::Clear(pat) => {
                let mut rev_str_ref = str_ref.to_vec();
                rev_str_ref.reverse();
                let pat_rev: String = pat.chars().rev().collect();
                let zero = self.false_ct();
                let mut split_sequence = SplitFoundPattern::new();
                let mut accumulated_starts = self
                    .clear_accumulated_starts(str_len, &rev_str_ref, &pat_rev, None)
                    .filter_map(|x| {
                        x.map(|(_, y)| {
                            (
                                self.0.scalar_eq_parallelized(&y, 1),
                                self.0.scalar_gt_parallelized(&y, 0u64),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                accumulated_starts.reverse();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                (FhePatternLen::Plain(pat.len()), split_sequence)
            }
            Pattern::Encrypted(pat) => {
                let (orig_len, split_sequence) = self.encrypted_rsplit(str_len, str_ref, pat, None);
                (FhePatternLen::Encrypted(orig_len), split_sequence)
            }
        }
    }

    #[inline]
    pub(super) fn encrypted_rsplit(
        &self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &FheString<Padded>,
        max_count: Option<Number>,
    ) -> (FheUsize, SplitFoundPattern) {
        let mut rev_str_ref = str_ref.to_vec();
        rev_str_ref.reverse();
        let zero = self.false_ct();
        let (is_empty_pat, (orig_len, rev_pat)) = rayon::join(
            || self.is_empty(pat),
            || rayon::join(|| self.len(pat), || self.reverse_padded_pattern(pat)),
        );
        let mut split_sequence = SplitFoundPattern::new();

        let (empty_str_ref, empty_skip_len) = rayon::join(
            || self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64),
            || {
                let zero_count = str_ref
                    .par_iter()
                    .map(|x| self.0.scalar_eq_parallelized(x.as_ref(), 0u64))
                    .reduce(|| self.false_ct(), |x, y| self.0.add_parallelized(&x, &y));
                self.0.mul_parallelized(&zero_count, &is_empty_pat)
            },
        );

        match &max_count {
            Some(Number::Clear(1)) => {
                split_sequence.push_back((empty_str_ref.clone(), zero.clone().into()));
            }
            Some(Number::Encrypted(mc)) => {
                let not_count_one = self.0.scalar_ne_parallelized(mc, 1u64);
                let and_empty_pat = self.0.bitand_parallelized(&is_empty_pat, &not_count_one);

                let and_empty_str_ref = self.0.bitand_parallelized(&and_empty_pat, &empty_str_ref);

                split_sequence.push_back((empty_str_ref.clone(), zero.clone().into()));
                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
            None => {
                split_sequence.push_back((is_empty_pat.clone(), zero.clone().into()));
            }
            _ => {
                let and_empty_str_ref = self.0.bitand_parallelized(&is_empty_pat, &empty_str_ref);
                split_sequence.push_back((empty_str_ref.clone(), zero.clone().into()));

                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
        }

        let adjust_max_count = match &max_count {
            Some(Number::Clear(mc)) => {
                let normal_count = self.0.create_trivial_radix(*mc as u64, self.1);
                let final_count = self.0.add_parallelized(&normal_count, &empty_skip_len);

                Some(
                    self.0
                        .if_then_else_parallelized(&empty_str_ref, &zero, &final_count),
                )
            }
            Some(Number::Encrypted(mc)) => {
                let final_count = self.0.add_parallelized(mc, &empty_skip_len);
                Some(
                    self.0
                        .if_then_else_parallelized(&empty_str_ref, &zero, &final_count),
                )
            }
            _ => None,
        };

        let pat_ref = pat.as_ref();
        let (pat_len, is_not_empty) = rayon::join(
            || self.0.max_parallelized(&orig_len, &is_empty_pat),
            || self.0.scalar_ne_parallelized(pat_ref[0].as_ref(), 0),
        );
        let (rev_pattern_starts, zeroes) = rayon::join(
            || {
                (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_encrypted_par(&rev_str_ref[i..], &rev_pat);

                    let starts_len = self.0.mul_parallelized(&starts, &pat_len);
                    Some((max_count.as_ref().map(|_| starts), starts_len))
                })
            },
            || {
                (0..str_len)
                    .into_par_iter()
                    .map(|i| Some(self.0.scalar_eq_parallelized(str_ref[i].as_ref(), 0)))
            },
        );

        let (mut accumulated_starts, accumulated_zeroes) = rayon::join(
            || {
                scan(
                    rev_pattern_starts,
                    |x, y| match (x, y) {
                        (Some((count_x, start_x)), Some((count_y, start_y))) => {
                            let (count, in_pattern) = rayon::join(
                                || self.add(count_x.as_ref(), count_y.as_ref()),
                                || self.0.scalar_gt_parallelized(start_x, 1),
                            );
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                start_y,
                            );
                            Some((count, next_start))
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| {
                    x.map(|(count, starts)| {
                        let count_not_reached = match (&adjust_max_count, count.as_ref()) {
                            (Some(mc), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
                            _ => None,
                        };
                        let (pattern_starts, in_pattern) = rayon::join(
                            || self.0.scalar_eq_parallelized(&starts, 1u64),
                            || self.0.scalar_gt_parallelized(&starts, 0u64),
                        );
                        if let Some(cnr) = count_not_reached {
                            let (ps, inp) = rayon::join(
                                || self.0.bitand_parallelized(&pattern_starts, &cnr),
                                || self.0.bitand_parallelized(&in_pattern, &is_not_empty),
                            );
                            (ps, self.0.bitand_parallelized(&inp, &cnr))
                        } else {
                            (
                                pattern_starts,
                                self.0.bitand_parallelized(&in_pattern, &is_not_empty),
                            )
                        }
                    })
                })
                .collect::<Vec<_>>()
            },
            || {
                scan(zeroes, |x, y| self.add(x.as_ref(), y.as_ref()), None)
                    .flatten()
                    .collect::<Vec<_>>()
            },
        );

        accumulated_starts.reverse();

        split_sequence.par_extend(
            self.split_compute(
                accumulated_starts
                    .into_par_iter()
                    .zip(accumulated_zeroes)
                    .map(|((starts, in_pattern), count_zero)| {
                        let not_ended = self.0.scalar_le_parallelized(&count_zero, 1);
                        (self.0.bitand_parallelized(&starts, &not_ended), in_pattern)
                    })
                    .collect(),
                str_ref,
                &zero,
            ),
        );

        (orig_len, split_sequence)
    }

    #[inline]
    fn reverse_padded_pattern(&self, pat: &FheString<Padded>) -> Vec<FheAsciiChar> {
        let fst = pat.as_ref();
        let mut rev_fst = fst.to_vec();
        rev_fst.reverse();
        let pat_len = fst.len();
        let zero = self.false_ct();
        let no_zeroes = rev_fst
            .par_iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |a, b| self.add(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| zero.clone());
        let shifted_indices: Vec<_> = (0..pat_len)
            .into_par_iter()
            .map(|i| {
                let mut enc_i = self
                    .0
                    .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1);
                self.0.sub_assign_parallelized(&mut enc_i, &no_zeroes);
                enc_i
            })
            .collect();

        let mut result = Vec::with_capacity(fst.len());
        result.par_extend((0..pat_len).into_par_iter().map(|i| {
            (i..shifted_indices.len())
                .into_par_iter()
                .map(|j| {
                    self.0.if_then_else_parallelized(
                        &self.0.scalar_eq_parallelized(&shifted_indices[j], i as u64),
                        rev_fst[j].as_ref(),
                        &zero,
                    )
                })
                .reduce(|| zero.clone(), |a, b| self.0.bitxor_parallelized(&a, &b))
                .into()
        }));
        result
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn rsplit_test((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
            .unwrap();
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            input.rsplit(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplit(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            input.rsplit(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplit(&encrypted_str, &encrypted_split_pattern))
        );
    }

    #[test_matrix(
        [("Mary had a little lamb", " "),
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
    fn test_rsplit((input, split_pattern): (&str, &str), padding_len: usize) {
        rsplit_test((input, split_pattern), padding_len);
    }

    #[test_matrix(
        1..=3
    )]
    fn test_rsplit_empty(padding_len: usize) {
        rsplit_test(("", ""), padding_len)
    }
}
