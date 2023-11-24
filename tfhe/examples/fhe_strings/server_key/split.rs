mod rsplit;
mod rsplit_once;
mod rsplit_terminator;
mod rsplitn;
mod split;
mod split_ascii_whitespace;
mod split_inclusive;
mod split_terminator;
mod splitn;

use std::collections::VecDeque;

use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number, Padded, Pattern},
    scan::scan,
};

use super::ServerKey;

/// The pattern length used for interpreting [`FheSplitResult`]
pub enum FhePatternLen {
    Plain(usize),
    Encrypted(FheUsize),
}

type SplitFoundPattern = VecDeque<(FheBool, FheAsciiChar)>;

/// The iterator over the results of FHE splitting a string.
/// Unlike the Rust standard library's `Split` iterator, it is not lazy over string subslices, i.e.
/// it computes eagerly and returns all collected splits.
/// The way to process it is using [`ClientKey`]'s `decrypt_split` method
/// (which produces an equivalent result to calling the Rust standard library's split and collect methods).
pub enum FheSplitResult {
    RSplit(FhePatternLen, SplitFoundPattern),
    RSplitN(Option<FheBool>, FhePatternLen, SplitFoundPattern),
    RSplitOnce(FhePatternLen, SplitFoundPattern),
    RSplitTerminator(FhePatternLen, SplitFoundPattern),
    Split(FhePatternLen, SplitFoundPattern),
    SplitAsciiWhitespace(SplitFoundPattern),
    SplitInclusive(SplitFoundPattern),
    SplitN(Option<FheBool>, FhePatternLen, SplitFoundPattern),
    SplitTerminator(FhePatternLen, SplitFoundPattern),
}

impl FheSplitResult {
    pub fn reverse_results(&self) -> bool {
        matches!(
            self,
            FheSplitResult::RSplit(_, _)
                | FheSplitResult::RSplitN(_, _, _)
                | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    pub fn skip_empty_terminator(&self) -> bool {
        matches!(
            self,
            FheSplitResult::SplitTerminator(_, _) | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    pub fn zero_count(&self) -> Option<&FheBool> {
        match self {
            FheSplitResult::SplitN(z, _, _) | FheSplitResult::RSplitN(z, _, _) => z.as_ref(),
            _ => None,
        }
    }

    /// If the Split option should include "empty" matches, then this returns the pattern
    /// length, so that  [`ClientKey`]'s `decrypt_split` method knows how many zeroed-out characters
    /// correspond to the patterns vs the actual padded string length
    pub fn include_empty_matches(&self) -> Option<&FhePatternLen> {
        match self {
            FheSplitResult::Split(p, _)
            | FheSplitResult::SplitN(_, p, _)
            | FheSplitResult::RSplit(p, _)
            | FheSplitResult::RSplitN(_, p, _)
            | FheSplitResult::RSplitOnce(p, _)
            | FheSplitResult::RSplitTerminator(p, _)
            | FheSplitResult::SplitTerminator(p, _) => Some(p),
            _ => None,
        }
    }
}

impl Iterator for FheSplitResult {
    type Item = (FheBool, FheAsciiChar);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            FheSplitResult::Split(_, x)
            | FheSplitResult::SplitN(_, _, x)
            | FheSplitResult::SplitAsciiWhitespace(x)
            | FheSplitResult::SplitTerminator(_, x)
            | FheSplitResult::SplitInclusive(x)
            | FheSplitResult::RSplit(_, x)
            | FheSplitResult::RSplitOnce(_, x)
            | FheSplitResult::RSplitN(_, _, x)
            | FheSplitResult::RSplitTerminator(_, x) => x.pop_front(),
        }
    }
}

impl ServerKey {
    #[inline]
    fn empty_clear_pattern_split(
        &self,
        str_ref: &[FheAsciiChar],
        terminator: bool,
        max_count: Option<usize>,
    ) -> SplitFoundPattern {
        let zero = self.false_ct();
        let one = self.true_ct();
        let mut split_sequence = SplitFoundPattern::new();

        let mut count = 1;
        match max_count {
            Some(0) => return split_sequence,
            Some(1) => {
                split_sequence.push_back((self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64), zero.clone().into()));

                split_sequence.par_extend(str_ref.par_iter().map(|x| (zero.clone(), x.clone())));
                return split_sequence;
            }
            Some(c) => {
                let len = std::cmp::min(str_ref.len(), c - 2);
                split_sequence.push_back((one.clone(), zero.clone().into()));
                split_sequence.push_back((self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64), zero.clone().into()));

                split_sequence.par_extend(
                    str_ref[..len]
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x.as_ref(), 0), x.clone())),
                );
                count += len;
                if len < str_ref.len() {
                    split_sequence
                        .par_extend(str_ref[len..].par_iter().map(|x| (zero.clone(), x.clone())));
                }
            }
            _ => {
                split_sequence.push_back((one.clone(), zero.clone().into()));
                split_sequence.par_extend(
                    str_ref
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x.as_ref(), 0), x.clone())),
                );
            }
        }
        if terminator {
            if max_count.is_none() || matches!(max_count, Some(c) if c < count) {
                split_sequence.push_back((one, zero.into()));
            }
        }
        split_sequence
    }

    #[inline]
    fn larger_clear_pattern_split(&self, str_ref: &[FheAsciiChar]) -> SplitFoundPattern {
        let zero = self.false_ct();
        str_ref
            .par_iter()
            .map(|x| (zero.clone(), x.clone()))
            .collect()
    }

    #[inline]
    fn clear_accumulated_starts<'a>(
        &'a self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &str,
        max_count: Option<&Number>,
    ) -> impl ParallelIterator<Item=Option<(Option<FheUsize>, FheUsize)>> + 'a {
        let pattern_starts = (0..str_len).into_par_iter().map(|i| {
            let starts = self.starts_with_clear_par(&str_ref[i..], pat);
            let starts_len = self.0.scalar_mul_parallelized(&starts, pat.len() as u64);
            Some((max_count.as_ref().map(|_| starts), starts_len))
        });
        scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x)), Some((count_y, start_y))) => {
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        &start_y,
                    );
                    Some((self.add(count_x.as_ref(), count_y.as_ref()), next_start))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
    }

    #[inline]
    fn encrypted_split(
        &self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &FheString<Padded>,
        max_count: Option<Number>,
    ) -> (FheUsize, SplitFoundPattern) {
        let zero = self.false_ct();
        let (is_empty_pat, orig_len) = rayon::join(|| self.is_empty(pat), || self.len(pat));
        let empty_str_ref = self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64);

        let mut split_sequence = SplitFoundPattern::new();
        match &max_count {
            Some(Number::Clear(1)) => {
                split_sequence.push_back((empty_str_ref.clone(), zero.clone().into()));
            }
            Some(Number::Encrypted(mc)) => {
                let not_count_one = self.0.scalar_ne_parallelized(mc, 1u64);
                let and_empty_pat = self.0.bitand_parallelized(&is_empty_pat, &not_count_one);
                let or_empty_str_ref = self.0.bitor_parallelized(&and_empty_pat, &empty_str_ref);

                let and_empty_str_ref = self.0.bitand_parallelized(&and_empty_pat, &empty_str_ref);

                split_sequence.push_back((or_empty_str_ref, zero.clone().into()));
                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
            None => {
                split_sequence.push_back((is_empty_pat.clone(), zero.clone().into()));
            }
            _ => {
                let and_empty_str_ref = self.0.bitand_parallelized(&is_empty_pat, &empty_str_ref);
                split_sequence.push_back((is_empty_pat.clone(), zero.clone().into()));
                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
        }

        let pat_ref = pat.as_ref();
        let (pat_len, is_not_empty_pat) = rayon::join(
            || self.0.max_parallelized(&orig_len, &is_empty_pat),
            || self.0.scalar_ne_parallelized(pat_ref[0].as_ref(), 0),
        );
        let pattern_starts = (0..str_len).into_par_iter().map(|i| {
            let (starts, ended) = rayon::join(
                || self.starts_with_encrypted_par(&str_ref[i..], pat_ref),
                || self.0.scalar_eq_parallelized(str_ref[i].as_ref(), 0),
            );
            let starts_len = self.0.mul_parallelized(&starts, &pat_len);
            Some((max_count.as_ref().map(|_| starts), starts_len, ended))
        });

        let adjust_max_count = match &max_count {
            Some(Number::Clear(mc)) => {
                let normal_count = self.0.create_trivial_radix(*mc as u64, self.1);
                let final_count = self.0.sub_parallelized(&normal_count, &is_empty_pat);

                Some(self.0.if_then_else_parallelized(&empty_str_ref, &zero, &final_count))
            }
            Some(Number::Encrypted(mc)) => {
                let final_count = self.0.sub_parallelized(mc, &is_empty_pat);
                Some(self.0.if_then_else_parallelized(&empty_str_ref, &zero, &final_count))
            }
            _ => None,
        };

        let accumulated_starts = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x, ended_x)), Some((count_y, start_y, ended_y))) => {
                    let (in_pattern, (ended, count)) = rayon::join(
                        || self.0.scalar_gt_parallelized(start_x, 1),
                        || {
                            (
                                self.0.add_parallelized(ended_x, ended_y),
                                self.add(count_x.as_ref(), count_y.as_ref()),
                            )
                        },
                    );
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        &start_y,
                    );
                    Some((count, next_start, ended))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
            .filter_map(|x| {
                x.map(|(count, starts, ended)| {
                    let count_not_reached = match (&adjust_max_count, count.as_ref()) {
                        (Some(mc), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
                        _ => None,
                    };
                    let ((pattern_starts, not_ended), in_pattern) = rayon::join(
                        || {
                            rayon::join(
                                || {
                                    let pattern_starts = self.0.eq_parallelized(&starts, &pat_len);
                                    if let Some(ref cnr) = count_not_reached {
                                        self.0.bitand_parallelized(cnr, &pattern_starts)
                                    } else {
                                        pattern_starts
                                    }
                                },
                                || self.0.scalar_le_parallelized(&ended, 1),
                            )
                        },
                        || {
                            let in_pattern = self.0.scalar_gt_parallelized(&starts, 0u64);
                            if let Some(ref cnr) = count_not_reached {
                                self.0.bitand_parallelized(cnr, &in_pattern)
                            } else {
                                in_pattern
                            }
                        },
                    );
                    (
                        self.0.bitand_parallelized(&pattern_starts, &not_ended),
                        self.0.bitand_parallelized(&in_pattern, &is_not_empty_pat),
                    )
                })
            })
            .collect();
        split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
        (orig_len, split_sequence)
    }

    #[inline]
    fn split_compute<'a>(
        &'a self,
        accumulated_starts: Vec<(FheBool, FheBool)>,
        str_ref: &'a [FheAsciiChar],
        zero: &'a RadixCiphertext,
    ) -> impl ParallelIterator<Item=(FheBool, FheAsciiChar)> + 'a {
        accumulated_starts
            .into_par_iter()
            .zip(str_ref.into_par_iter())
            .map(|((starts, in_pattern), c)| {
                (
                    starts,
                    self.0
                        .if_then_else_parallelized(&in_pattern, zero, c.as_ref())
                        .into(),
                )
            })
    }

    #[inline]
    fn split_inner<'a, P: Into<Pattern<'a, Padded>>>(
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
                let zero = self.false_ct();
                let mut split_sequence = VecDeque::new();
                let accumulated_starts = self
                    .clear_accumulated_starts(str_len, str_ref, pat, None)
                    .filter_map(|x| {
                        x.map(|(_, y)| {
                            (
                                self.0.scalar_eq_parallelized(&y, pat.len() as u64),
                                self.0.scalar_gt_parallelized(&y, 0u64),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                (FhePatternLen::Plain(pat.len()), split_sequence)
            }
            Pattern::Encrypted(pat) => {
                let (orig_len, split_sequence) = self.encrypted_split(str_len, str_ref, pat, None);
                (FhePatternLen::Encrypted(orig_len), split_sequence)
            }
        }
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

    #[inline]
    fn encrypted_rsplit(
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

        let (empty_str_ref, empty_skip_len) = rayon::join(|| self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64),
                                                          || {
                                                              let zero_count = str_ref.par_iter().map(|x| self.0.scalar_eq_parallelized(x.as_ref(), 0u64)).reduce(|| self.false_ct(), |x, y| self.0.add_parallelized(&x, &y));
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

                Some(self.0.if_then_else_parallelized(&empty_str_ref, &zero, &final_count))
            }
            Some(Number::Encrypted(mc)) => {
                let final_count = self.0.add_parallelized(mc, &empty_skip_len);
                Some(self.0.if_then_else_parallelized(&empty_str_ref, &zero, &final_count))
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
                                &start_y,
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
                                (Some(mc), Some(c)) => {
                                    Some(self.0.lt_parallelized(c, mc))
                                }
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
    fn rsplit_inner<'a, P: Into<Pattern<'a, Padded>>>(
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
                let mut split_sequence = VecDeque::new();
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
    fn rsplitn_inner<'a, N: Into<Number>, P: Into<Pattern<'a, Padded>>>(
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
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0 as u64)),
                    _ => None,
                };
                let mut rev_str_ref = str_ref.to_vec();
                rev_str_ref.reverse();
                let pat_rev: String = pat.chars().rev().collect();
                let zero = self.false_ct();
                let mut split_sequence = VecDeque::new();
                let mut accumulated_starts = self
                    .clear_accumulated_starts(str_len, &rev_str_ref, &pat_rev, Some(&max_count))
                    .filter_map(|x| {
                        x.map(|(count, starts_y)| {
                            let (starts, (in_pattern, le_maxcount)) = rayon::join(
                                || self.0.scalar_eq_parallelized(&starts_y, 1),
                                || {
                                    (
                                        self.0.scalar_gt_parallelized(&starts_y, 0u64),
                                        match (&max_count, count.as_ref()) {
                                            (Number::Clear(mc), Some(c)) => {
                                                Some(self.0.scalar_lt_parallelized(c, *mc as u64))
                                            }
                                            (Number::Encrypted(mc), Some(c)) => {
                                                Some(self.0.lt_parallelized(c, mc))
                                            }
                                            _ => None,
                                        },
                                    )
                                },
                            );
                            if let Some(mc) = le_maxcount {
                                rayon::join(
                                    || self.0.bitand_parallelized(&starts, &mc),
                                    || self.0.bitand_parallelized(&in_pattern, &mc),
                                )
                            } else {
                                (starts, in_pattern)
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                accumulated_starts.reverse();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                (zero_count, FhePatternLen::Plain(pat.len()), split_sequence)
            }
            (Pattern::Encrypted(pat), count) => {
                let zero_count = match &count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0 as u64)),
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
    ///   client_key.decrypt_split(server_key.rsplit(s, " ")),
    ///   vec!["lamb", "little", "a", "had", "Mary"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit(s, "X")),
    ///   vec![""]
    /// );
    /// let x = client_key.encrypt_str("X").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit(s, &x)),
    ///   vec![""]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleopard").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit(s, "X")),
    ///   vec!["leopard", "tiger", "", "lion"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leopard").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit(s, "::")),
    ///   vec!["leopard", "tiger", "lion"]
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

    /// Splits the `encrypted_str`, on the last occurrence of the specified delimiter
    /// and returns prefix before delimiter and suffix after delimiter.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// NOTE: Unlike the standard library's `rsplit_once`, this method returns
    /// `FheSplitResult` with at most two elements. If the pattern is not found,
    /// the result will contain only the original string. (The standard library's
    /// `rsplit_once` returns `None` in this case.)
    ///
    /// # Examples
    ///``
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("cfg").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///   vec!["cfg"]
    /// );
    /// let s = client_key.encrypt_str("cfg=foo").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///   vec!["cfg", "foo"]
    /// );
    /// let s = client_key.encrypt_str("cfg=foo=bar").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///   vec!["cfg=foo", "bar"]
    /// );
    /// ```
    #[inline]
    pub fn rsplit_once<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        delimiter: P,
    ) -> FheSplitResult {
        let (_, pat_len, pattern_splits) = self.rsplitn_inner(encrypted_str, 2, delimiter);
        FheSplitResult::RSplitOnce(pat_len, pattern_splits)
    }

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
    ///   client_key.decrypt_split(server_key.rsplitn(s, 3, " ")),
    ///   vec!["lamb", "little", "Mary had a"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleopard").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplitn(s, 3, "X")),
    ///   vec!["leopard", "tiger", "lionX"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leopard").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplitn(s, 2, "::")),
    ///   vec!["leopard", "lion::tiger"]
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

    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern and yielded in reverse order.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// Equivalent to [`split`], except that the trailing substring is
    /// skipped if empty.
    ///
    /// [`split`]: ServerKey::split
    ///
    /// This method can be used for string data that is _terminated_,
    /// rather than _separated_ by a pattern.
    ///
    /// # Iterator behavior
    ///
    /// For iterating from the front, the [`split_terminator`] method can be
    /// used.
    ///
    /// [`split_terminator`]: ServerKey::split_terminator
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("A.B.").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit_terminator(s, ".")),
    ///   vec!["B", "A"]
    /// );
    ///
    /// let s = client_key.encrypt_str("A..B..").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.rsplit_terminator(s, ".")),
    ///   vec!["", "B", "", "A"]
    /// );
    /// ```
    #[inline]
    pub fn rsplit_terminator<'a, P: Into<Pattern<'a, Padded>>>(
        &'a self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.rsplit_inner(encrypted_str, pat);
        FheSplitResult::RSplitTerminator(pat_len, pattern_splits)
    }

    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will be a [`Split`] and the first returned valid
    /// element is the result of the split operation.
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
    /// let s = client_key.encrypt_str("Mary had a lamb").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   vec!["Mary", "had", "a", "lamb"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "X")),
    ///   vec![""]
    /// );
    /// let x = client_key.encrypt_str("X").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, &x)),
    ///   vec![""]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleo").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "X")),
    ///   vec!["lion", "", "tiger", "leo"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leo").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "::")),
    ///   vec!["lion", "tiger", "leo"]
    /// );
    /// ```
    ///
    /// If a string contains multiple contiguous separators, you will end up
    /// with empty strings in the output:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("||||a||b|c").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "|")),
    ///   vec!["", "", "", "", "a", "", "b", "c"]
    /// );
    /// ```
    ///
    /// Contiguous separators are separated by the empty string.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("(///)").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "/")),
    ///   vec!["(", "", "", ")"]
    /// );
    /// ```
    ///
    /// Separators at the start or end of a string are neighbored
    /// by empty strings.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("010").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "0")),
    ///   vec!["", "1", ""]
    /// );
    /// ```
    ///
    /// When the empty string is used as a separator, it separates
    /// every character in the string, along with the beginning
    /// and end of the string.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("rust").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "")),
    ///   vec!["", "r", "u", "s", "t", ""]
    /// );
    /// ```
    ///
    /// Contiguous separators can lead to possibly surprising behavior
    /// when whitespace is used as the separator. This code is correct:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("    a  b c").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   vec!["", "", "", "", "a", "", "b", "c"]
    /// );
    /// ```
    ///
    /// It does _not_ give you:
    ///
    /// ```,ignore
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   vec!["a", "b", "c"]
    /// );
    /// ```
    ///
    /// Use [`split_ascii_whitespace`] for this behavior.
    ///
    /// [`split_ascii_whitespace`]: ServerKey::split_ascii_whitespace
    #[inline]
    pub fn split<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.split_inner(encrypted_str, pat);
        FheSplitResult::Split(pat_len, pattern_splits)
    }

    /// Splits `encrypted_str` by ASCII whitespace.
    ///
    /// The iterator returned will return encrypted substrings that are sub-slices of
    /// the original `encrypted_str`, separated by any amount of ASCII whitespace.
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
    /// let s = client_key.encrypt_str("A few words").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///   vec!["A", "few", "words"]
    /// );
    /// ```
    ///
    /// All kinds of ASCII whitespace are considered:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str(" Mary   had\ta little  \n\t lamb").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///   vec!["Mary", "had", "a", "little", "lamb"]
    /// );
    /// ```
    ///
    /// If the string is empty or all ASCII whitespace, the iterator yields no string slices:
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///   vec![]
    /// );
    /// let s = client_key.encrypt_str("   ").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///   vec![]
    /// );
    /// ```
    #[must_use = "this returns the split FheString as an iterator, \
                  without modifying the original"]
    #[inline]
    pub fn split_ascii_whitespace(&self, encrypted_str: &FheString<Padded>) -> FheSplitResult {
        let str_ref = encrypted_str.as_ref();
        let zero = self.false_ct();
        let mut split_sequence = VecDeque::new();
        let whitespaces = str_ref.par_iter().map(|x| self.is_whitespace(x));
        split_sequence.par_extend(whitespaces.zip(str_ref.into_par_iter()).map(|(starts, c)| {
            let final_c = self
                .0
                .if_then_else_parallelized(&starts, &zero, c.as_ref())
                .into();
            (starts, final_c)
        }));
        FheSplitResult::SplitAsciiWhitespace(split_sequence)
    }

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
    /// let s = client_key.encrypt_str("Mary had a little lamb\nlittle lamb\nlittle lamb.\n").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_inclusive(s, "\n")),
    ///   vec!["Mary had a little lamb\n", "little lamb\n", "little lamb.\n"]
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
                let mut split_sequence = VecDeque::new();
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
                                &start_y,
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

    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// Equivalent to [`split`], except that the trailing substring
    /// is skipped if empty.
    ///
    /// [`split`]: ServerKey::split
    ///
    /// This method can be used for string data that is _terminated_,
    /// rather than _separated_ by a pattern.
    ///
    /// # Iterator behavior
    ///
    /// If the pattern allows a reverse search but its results might differ
    /// from a forward search, the [`rsplit_terminator`] method can be used.
    ///
    /// [`rsplit_terminator`]: ServerKey::rsplit_terminator
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("A.B.").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_terminator(s, ".")),
    ///   vec!["A", "B"]
    /// );
    ///
    /// let s = client_key.encrypt_str("A..B..").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split_terminator(s, ".")),
    ///   vec!["A", "", "B", ""]
    /// );
    /// ```
    #[inline]
    pub fn split_terminator<'a, P: Into<Pattern<'a, Padded>>>(
        &'a self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.split_inner(encrypted_str, pat);
        FheSplitResult::SplitTerminator(pat_len, pattern_splits)
    }

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
    pub fn splitn<'a, N: Into<Number>, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        n: N,
        pat: P,
    ) -> FheSplitResult {
        let str_ref = encrypted_str.as_ref();
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
                let mut split_sequence = VecDeque::new();
                let empty_input = self.is_empty(encrypted_str);
                if pat.is_empty() {
                    match &max_count {
                        Number::Encrypted(mc) => {
                            let not_single_match = self.0.scalar_ne_parallelized(mc, 1u64);

                            split_sequence.push_back((self.0.bitor_parallelized(&not_single_match, &empty_input), zero.clone().into()));
                            split_sequence.push_back((self.0.bitand_parallelized(&not_single_match, &empty_input), zero.clone().into()));
                        }
                        _ => split_sequence.push_back((self.true_ct(), zero.clone().into()))
                    };
                }
                let adjust_max_count = if pat.is_empty() {
                    match max_count {
                        Number::Clear(mc) => Number::Clear(mc.saturating_sub(1)),
                        Number::Encrypted(mc) => {
                            let reduced_match = self.0.scalar_sub_parallelized(&mc, 1u64);
                            Number::Encrypted(
                                self.0.if_then_else_parallelized(&empty_input, &self.false_ct(), &reduced_match)
                            )
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
                                    (
                                        self.0.scalar_gt_parallelized(&starts_y, 0u64),
                                        match (&adjust_max_count, count.as_ref()) {
                                            (Number::Clear(mc), Some(c)) => {
                                                Some(self.0.scalar_lt_parallelized(c, *mc as u64))
                                            }
                                            (Number::Encrypted(mc), Some(c)) => {
                                                Some(self.0.lt_parallelized(c, mc))
                                            }
                                            _ => None,
                                        },
                                    )
                                },
                            );
                            if let Some(mc) = le_maxcount {
                                rayon::join(
                                    || self.0.bitand_parallelized(&starts, &mc),
                                    || self.0.bitand_parallelized(&in_pattern, &mc),
                                )
                            } else {
                                (starts, in_pattern)
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                FheSplitResult::SplitN(zero_count, FhePatternLen::Plain(pat.len()), split_sequence)
            }
            (Pattern::Encrypted(pat), count) => {
                let zero_count = match &count {
                    Number::Encrypted(mc) => Some(self.0.scalar_eq_parallelized(mc, 0u64)),
                    _ => None,
                };
                let (orig_len, split_sequence) =
                    self.encrypted_split(str_len, str_ref, pat, Some(count));
                FheSplitResult::SplitN(
                    zero_count,
                    FhePatternLen::Encrypted(orig_len),
                    split_sequence,
                )
            }
        }
    }
}
