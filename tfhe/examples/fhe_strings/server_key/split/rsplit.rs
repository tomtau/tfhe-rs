use std::collections::VecDeque;

use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number, Pattern};
use crate::scan::scan;
use crate::server_key::ServerKey;

use super::{FhePatternLen, FheSplitResult, PatternLenAndEndLen, SplitFoundPattern};

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
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn rsplit<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.rsplit_inner(encrypted_str, pat, true);
        FheSplitResult::RSplit(pat_len, pattern_splits)
    }

    /// A helper that returns the split pattern length and the split sequence
    /// for rsplit* methods.
    #[inline]
    pub(super) fn rsplit_inner<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
        terminator: bool,
    ) -> (PatternLenAndEndLen, SplitFoundPattern) {
        match encrypted_str {
            FheString::Padded(_) => {
                let str_real_len = self.len(encrypted_str);
                let str_ref = encrypted_str.as_ref();
                let str_len = str_ref.len();
                match pat.into() {
                    Pattern::Clear(p) if p.is_empty() => (
                        (
                            FhePatternLen::Plain(0),
                            FhePatternLen::Encrypted(str_real_len),
                        ),
                        self.empty_clear_pattern_split(str_ref, terminator, None),
                    ),
                    Pattern::Clear(p) if p.len() > str_ref.len() => (
                        (
                            FhePatternLen::Plain(p.len()),
                            FhePatternLen::Encrypted(str_real_len),
                        ),
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
                        split_sequence.par_extend(self.split_compute(
                            accumulated_starts,
                            str_ref,
                            &zero,
                        ));
                        (
                            (
                                FhePatternLen::Plain(pat.len()),
                                FhePatternLen::Encrypted(str_real_len),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(pat) => {
                        let (orig_len, split_sequence) =
                            self.encrypted_rsplit(str_len, str_ref, pat, None, terminator);
                        (
                            (
                                FhePatternLen::Encrypted(orig_len),
                                FhePatternLen::Encrypted(str_real_len),
                            ),
                            split_sequence,
                        )
                    }
                }
            }
            FheString::Unpadded(_) => {
                let str_ref = encrypted_str.as_ref();
                let one = self.true_ct();

                let zero = self.false_ct();
                match pat.into() {
                    Pattern::Clear(p) if p.is_empty() && str_ref.is_empty() => {
                        let mut split_sequence = VecDeque::new();
                        split_sequence.push_back((one.clone(), zero.clone().into()));
                        if terminator {
                            split_sequence.push_back((zero.clone(), zero.clone().into()));
                            split_sequence.push_back((zero.clone(), zero.clone().into()));

                            split_sequence.push_back((one.clone(), zero.clone().into()));
                        }
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(p) if p.as_ref().is_empty() && str_ref.is_empty() => {
                        let mut split_sequence = VecDeque::new();
                        split_sequence.push_back((one.clone(), zero.clone().into()));
                        if terminator {
                            split_sequence.push_back((zero.clone(), zero.clone().into()));
                            split_sequence.push_back((zero.clone(), zero.clone().into()));

                            split_sequence.push_back((one.clone(), zero.clone().into()));
                        }
                        (
                            (
                                FhePatternLen::Plain(p.as_ref().len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Clear(p) if p.len() > str_ref.len() => {
                        let split_sequence = self.larger_clear_pattern_split(str_ref);
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(FheString::Unpadded(p)) if p.len() > str_ref.len() => {
                        let split_sequence = self.larger_clear_pattern_split(str_ref);
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Clear(p) => self.rsplit_inner(
                        &self.pad_string(encrypted_str),
                        Pattern::Clear(p),
                        terminator,
                    ),
                    Pattern::Encrypted(p) => self.rsplit_inner(
                        &self.pad_string(encrypted_str),
                        &self.pad_string(p),
                        terminator,
                    ),
                }
            }
        }
    }

    /// A helper that computes the split of a padded encrypted pattern on a given encrypted string
    /// for rsplit* methods.
    #[inline]
    pub(super) fn encrypted_rsplit(
        &self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &FheString,
        max_count: Option<Number>,
        terminator: bool,
    ) -> (FheUsize, SplitFoundPattern) {
        let pat = self.pad_string(pat); // TODO: unpadded pattern
        let mut rev_str_ref = str_ref.to_vec();
        rev_str_ref.reverse();
        let zero = self.false_ct();
        let (is_empty_pat, (orig_len, rev_pat)) = rayon::join(
            || self.is_empty(&pat),
            || rayon::join(|| self.len(&pat), || self.reverse_padded_pattern(&pat)),
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

        let adjust_max_count =
            self.adjust_rsplit_init_max_count(&max_count, &is_empty_pat, &empty_skip_len);

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
                        (Some((count_x, start_x)), Some((count_y, start_y))) => self
                            .accumulate_enc_rsplit_starts(
                                &adjust_max_count,
                                count_x,
                                start_x,
                                count_y,
                                start_y,
                            ),
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| {
                    x.map(|(count, starts)| {
                        self.finalized_accumulate_rsplit_starts(
                            &adjust_max_count,
                            &is_not_empty,
                            count,
                            &starts,
                        )
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
        if terminator {
            match max_count {
                Some(Number::Clear(mc)) if mc >= 1 => {
                    split_sequence.push_back((zero.clone(), zero.clone().into()));
                    split_sequence.push_back((zero.clone(), zero.clone().into()));

                    split_sequence.push_back((empty_str_ref, zero.into()));
                }
                None => {
                    split_sequence.push_back((zero.clone(), zero.clone().into()));
                    split_sequence.push_back((zero.clone(), zero.clone().into()));

                    split_sequence.push_back((empty_str_ref, zero.into()));
                }
                Some(Number::Encrypted(mc)) => {
                    let gt_one = self.0.scalar_ge_parallelized(&mc, 1);
                    split_sequence.push_back((zero.clone(), zero.clone().into()));
                    split_sequence.push_back((zero.clone(), zero.clone().into()));

                    split_sequence.push_back((
                        self.0.bitand_parallelized(&empty_str_ref, &gt_one),
                        zero.into(),
                    ));
                }
                _ => {}
            }
        }

        (orig_len, split_sequence)
    }

    /// A helper that produces a tuple where the first
    /// component indicates whether the pattern starts at the given position
    /// and the second component whether a character at that position is in the pattern.
    /// (it adjust both components if the max count is reached or the padded string is empty)
    #[inline]
    fn finalized_accumulate_rsplit_starts(
        &self,
        adjust_max_count: &Option<RadixCiphertext>,
        is_not_empty: &RadixCiphertext,
        count: Option<FheBool>,
        starts: &FheBool,
    ) -> (FheBool, FheBool) {
        let count_not_reached = match (&adjust_max_count, count.as_ref()) {
            (Some(mc), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
            _ => None,
        };
        let (pattern_starts, in_pattern) = rayon::join(
            || self.0.scalar_eq_parallelized(starts, 1u64),
            || self.0.scalar_gt_parallelized(starts, 0u64),
        );
        if let Some(cnr) = count_not_reached {
            let (ps, inp) = rayon::join(
                || self.0.bitand_parallelized(&pattern_starts, &cnr),
                || self.0.bitand_parallelized(&in_pattern, is_not_empty),
            );
            (ps, self.0.bitand_parallelized(&inp, &cnr))
        } else {
            (
                pattern_starts,
                self.0.bitand_parallelized(&in_pattern, is_not_empty),
            )
        }
    }

    /// A helper that processes the accumulated starts for computing the split
    /// the first component is the number of pattern matches (if max_count is set),
    /// the second is the number between the pattern length/1 and 0
    #[inline]
    fn accumulate_enc_rsplit_starts(
        &self,
        max_count: &Option<FheUsize>,
        count_x: &Option<FheUsize>,
        start_x: &FheUsize,
        count_y: &Option<FheUsize>,
        start_y: &FheUsize,
    ) -> Option<(Option<FheUsize>, FheUsize)> {
        let mut count_xy = self.add(count_x.as_ref(), count_y.as_ref());
        let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
        let mut start_y = start_y.clone();
        if let (Some(count), Some(c_xy)) = (max_count.as_ref(), count_xy.as_ref()) {
            let (min_next_count, not_reached_max_count) = rayon::join(
                || self.0.min_parallelized(c_xy, count),
                || self.0.le_parallelized(c_xy, count),
            );
            count_xy = Some(min_next_count);

            start_y = self.0.if_then_else_parallelized(
                &not_reached_max_count,
                &start_y,
                &self.false_ct(),
            );
        }
        let next_count = if let (Some(count_x), Some(count_xy)) = (count_x, count_xy) {
            Some(
                self.0
                    .if_then_else_parallelized(&in_pattern, count_x, &count_xy),
            )
        } else {
            None
        };

        let next_start = self.0.if_then_else_parallelized(
            &in_pattern,
            &self.0.scalar_sub_parallelized(start_x, 1),
            &start_y,
        );
        Some((next_count, next_start))
    }

    /// A helper that adjust the max_count if the padded string or pattern are empty
    #[inline]
    fn adjust_rsplit_init_max_count(
        &self,
        max_count: &Option<Number>,
        is_empty_pat: &FheBool,
        empty_skip_len: &FheUsize,
    ) -> Option<FheUsize> {
        match &max_count {
            Some(Number::Clear(mc)) => {
                let normal_count = self.0.create_trivial_radix(*mc as u64, self.1);
                let mut final_count = self.0.add_parallelized(&normal_count, empty_skip_len);
                self.0
                    .sub_assign_parallelized(&mut final_count, is_empty_pat);
                Some(final_count)
            }
            Some(Number::Encrypted(mc)) => {
                let mut final_count = self.0.add_parallelized(mc, empty_skip_len);
                self.0
                    .sub_assign_parallelized(&mut final_count, is_empty_pat);
                Some(final_count)
            }
            _ => None,
        }
    }

    /// A helper that reverses the padded pattern
    /// (i.e. it reverses the characters and then shifts each character based on the number of
    /// prefix zeroes)
    #[inline]
    fn reverse_padded_pattern(&self, pat: &FheString) -> Vec<FheAsciiChar> {
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
    fn rsplit_padded_test((input, split_pattern): (&str, &str), padding_len: usize) {
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
        ("1111111", "11"),
        ("123123123", "123"),
        ("12121212121", "1212"),
        ("banana", "ana"),
        ("foo:bar", "foo:"),
        ("foo:bar", "bar"),],
        1..=3
    )]
    fn test_rsplit_padded((input, split_pattern): (&str, &str), padding_len: usize) {
        rsplit_padded_test((input, split_pattern), padding_len);
    }

    #[test_matrix(
        1..=3
    )]
    fn test_rsplit_empty_padded(padding_len: usize) {
        rsplit_padded_test(("", ""), padding_len)
    }

    #[test_matrix(
        [("", "a"),
        ("", "")]
    )]
    fn test_rsplit_unpadded((input, split_pattern): (&str, &str)) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str(input).unwrap();
        let encrypted_split_pattern = client_key.encrypt_str(split_pattern).unwrap();
        println!("clear: {input} {split_pattern}");
        assert_eq!(
            input.rsplit(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplit(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern}");

        assert_eq!(
            input.rsplit(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.rsplit(&encrypted_str, &encrypted_split_pattern))
        );
    }
}
