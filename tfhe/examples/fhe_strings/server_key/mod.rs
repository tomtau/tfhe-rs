mod comparison;
mod concat;
mod conversion;
mod is_empty;
mod len;
mod repeat;
mod replace;
mod search;
mod split;
mod trim;

pub use split::{FhePatternLen, FheSplitResult};

use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe::integer::ServerKey as IntegerServerKey;

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Padded, Unpadded};
use crate::client_key::{ClientKey, PRECISION_BITS};
use crate::scan::scan;

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey(IntegerServerKey, usize);

impl From<&ClientKey> for ServerKey {
    fn from(key: &ClientKey) -> Self {
        let num_blocks =
            PRECISION_BITS / key.as_ref().parameters().message_modulus().0.ilog2() as usize;
        Self(IntegerServerKey::new(key), num_blocks)
    }
}

impl From<IntegerServerKey> for ServerKey {
    fn from(key: IntegerServerKey) -> Self {
        // FIXME: extract from `key` when the accessor is available.
        // this is possible in the latest `main` of the `tfhe` crate repo.
        // `fhe_strings-0.5-refactor` branch contains the WIP changes that uses it.
        const NUM_BLOCKS: usize = 4;
        Self(key, NUM_BLOCKS)
    }
}

/// 0c == \f == form feed
/// 0b == \v == vertical tab
const ASCII_WHITESPACES: [char; 6] = [' ', '\t', '\n', '\r', '\x0c', '\x0b'];

impl ServerKey {
    /// Returns an encrypted `true` (1) if `c` is ASCII whitespace.
    #[inline]
    fn is_whitespace(&self, c: &FheAsciiChar) -> FheBool {
        ASCII_WHITESPACES
            .par_iter()
            .map(|&x| Some(self.0.scalar_eq_parallelized(c.as_ref(), x as u8)))
            .reduce(|| None, |a, b| self.or(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// Returns an encrypted `true` (1) constant.
    #[inline]
    fn true_ct(&self) -> FheBool {
        self.0.create_trivial_radix(1, self.1)
    }

    /// Returns an encrypted `false` (0) constant.
    #[inline]
    fn false_ct(&self) -> FheBool {
        self.0.create_trivial_zero_radix(self.1)
    }

    /// Returns an encrypted `true` (1) if `encrypted_char` is in a given ASCII inclusive range.
    #[inline]
    fn check_scalar_range(&self, encrypted_char: &FheAsciiChar, start: u8, end: u8) -> FheBool {
        let (ge_from, le_to) = rayon::join(
            || {
                self.0
                    .scalar_ge_parallelized(encrypted_char.as_ref(), start)
            },
            || self.0.scalar_le_parallelized(encrypted_char.as_ref(), end),
        );
        self.0.bitand_parallelized(&ge_from, &le_to)
    }

    /// A helper for `cmux` operations where the condition may be missing (due to the neutral None
    /// value). If `cond` is `None`, `default_if_none` is used to determine the result (`opt_a`
    /// if true).
    #[inline]
    fn if_then_else(
        &self,
        cond: Option<&FheBool>,
        default_if_none: bool,
        opt_a: &FheBool,
        opt_b: &FheBool,
    ) -> FheBool {
        match cond {
            Some(cond) => self.0.if_then_else_parallelized(cond, opt_a, opt_b),
            None if default_if_none => opt_a.clone(),
            _ => opt_b.clone(),
        }
    }

    /// A helper for `Or` operations where one side may be missing (due to the neutral None value).
    #[inline]
    fn or(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitor_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    /// A helper that adds two `FheUsize` values, or returns the non-None value if one is missing.
    #[inline]
    fn add(&self, a: Option<&FheUsize>, b: Option<&FheUsize>) -> Option<FheUsize> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.add_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    /// A helper that does "and" operation on two `FheBool` values, or returns the non-None value if one is missing.
    #[inline]
    fn and_true(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitand_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    /// A helper to find the correct character based on the shifted index.
    /// If the character isn't to be included, it'd return an empty character / encrypted 0.
    /// `i` is the intended index of the character
    /// `fst` is the original encrypted string
    /// `shifted_indices` is a list of tuples of (condition, index)
    ///     where the condition is true if the shifted character should not be included
    ///     (i.e. it should be replaced by the pattern's character)
    ///     and index is the correct index of the character
    /// This function assumes the lengths of `fst` and `shifted_indices` are the same.
    #[inline]
    fn find_shifted_index_char(
        &self,
        i: usize,
        fst: &[FheAsciiChar],
        shifted_indices: &[(FheBool, FheUsize)],
    ) -> FheAsciiChar {
        (0..shifted_indices.len())
            .into_par_iter()
            .map(|j| {
                let (part_cond, not_in_pattern) = rayon::join(
                    || {
                        self.0
                            .scalar_eq_parallelized(&shifted_indices[j].1, i as u64)
                    },
                    || self.0.scalar_eq_parallelized(&shifted_indices[j].0, 0),
                );
                let cond = self.0.bitand_parallelized(&part_cond, &not_in_pattern);
                self.0
                    .if_then_else_parallelized(&cond, fst[j].as_ref(), &self.false_ct())
            })
            .reduce(
                || self.false_ct(),
                |a, b| self.0.bitxor_parallelized(&a, &b),
            )
            .into()
    }

    /// Returns an encrypted `true` (1) if `enc_ref` starts with `pat`.
    #[inline]
    fn starts_with_clear_par(&self, enc_ref: &[FheAsciiChar], pat: &str) -> FheBool {
        if enc_ref.len() < pat.len() {
            self.false_ct()
        } else if pat.is_empty() {
            self.true_ct()
        } else {
            enc_ref
                .par_iter()
                .zip(pat.as_bytes().par_iter())
                .map(|(a, b)| Some(self.0.scalar_eq_parallelized(a.as_ref(), *b as u64)))
                .reduce(|| None, |s, x| self.and_true(s.as_ref(), x.as_ref()))
                .unwrap_or_else(|| self.false_ct())
        }
    }

    /// Returns an encrypted `true` (1) if `enc_ref` starts with `pat`.
    #[inline]
    fn starts_with_encrypted_par(&self, enc_ref: &[FheAsciiChar], pat: &[FheAsciiChar]) -> FheBool {
        if pat.as_ref().len() < 2 {
            self.true_ct()
        } else {
            enc_ref
                .par_iter()
                .zip(pat.as_ref().par_iter())
                .map(|(a, b)| {
                    let (pattern_ended, a_eq_b) = rayon::join(
                        || self.0.scalar_eq_parallelized(b.as_ref(), 0),
                        || self.0.eq_parallelized(a.as_ref(), b.as_ref()),
                    );
                    Some(
                        self.0
                            .if_then_else_parallelized(&pattern_ended, &self.true_ct(), &a_eq_b),
                    )
                })
                .reduce(|| None, |s, x| self.and_true(s.as_ref(), x.as_ref()))
                .unwrap_or_else(|| self.false_ct())
        }
    }

    /// A helper that checks that two encrypted strings are a match
    /// and returns an encrypted `true` (`1`) if they are.
    /// This function assumes the string slices are of the same length.
    #[inline]
    fn par_eq(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| Some(self.0.eq_parallelized(x.as_ref(), y.as_ref())))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// A helper that checks that an encrypted character `x` at index `i`
    /// is equal to a clear character `y` and returns an encrypted `true` (`1`) if they are.
    /// (this uses a cache for overlapping patterns)
    #[inline]
    fn char_eq_clear_check_cached(
        &self,
        i: usize,
        x: &FheAsciiChar,
        y: &u8,
        cache: &DashMap<(usize, u8), FheBool>,
    ) -> FheBool {
        let key = (i, *y);
        let result = cache.get(&key).map(|v| v.clone()).unwrap_or_else(|| {
            let v = self.0.scalar_eq_parallelized(x.as_ref(), *y);
            cache.insert(key, v.clone());
            v
        });
        result
    }

    /// A helper that checks that that `fst` is equal to `snd`
    /// and returns an encrypted `true` (`1`) if they are.
    /// This function assumes the string slices are of the same length.
    #[inline]
    fn par_eq_clear_unpadded_cached(
        &self,
        start_index: usize,
        fst: &[FheAsciiChar],
        snd: &str,
        cache: &DashMap<(usize, u8), FheBool>,
    ) -> FheBool {
        (start_index..start_index + fst.len())
            .into_par_iter()
            .zip(fst.par_iter())
            .zip(snd.as_bytes().par_iter())
            .map(|((i, x), y)| Some(self.char_eq_clear_check_cached(i, x, y, cache)))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// A helper that checks that that `fst` is equal to `snd`
    /// and returns an encrypted `true` (`1`) if they are.
    /// This function assumes the `fst` is padded with one zero.
    #[inline]
    fn par_eq_clear_padded_cached(
        &self,
        start_index: usize,
        fst: &[FheAsciiChar],
        snd: &str,
        cache: &DashMap<(usize, u8), FheBool>,
    ) -> FheBool {
        (start_index..start_index + fst.len())
            .into_par_iter()
            .zip(fst.par_iter())
            .zip(snd.as_bytes().par_iter().chain(rayon::iter::once(&0u8)))
            .map(|((i, x), y)| Some(self.char_eq_clear_check_cached(i, x, y, cache)))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// A helper that checks if fst ends with the pattern `pat`.
    /// (as `fst` is padded, this returns an iterator over the possible start indices)
    #[inline]
    fn find_clear_pattern_padded_suffixes<'a>(
        &'a self,
        fst: &'a [FheAsciiChar],
        pat: &'a str,
    ) -> impl ParallelIterator<Item = Option<FheBool>> + 'a {
        let str_l = fst.len();
        let pat_len = pat.len();
        let cache = DashMap::new();
        (0..str_l - pat_len).into_par_iter().map(move |i| {
            Some(self.par_eq_clear_padded_cached(
                i,
                &fst[i..std::cmp::min(i + pat_len + 1, str_l)],
                pat,
                &cache,
            ))
        })
    }

    /// A helper that will accumulate the pattern matches:
    /// input: iterator of tuples: (1 or 0 if provided, 0 or pattern_len)
    /// for example for the pattern "aa" and the string "aaaab":
    /// [(1, 2), (1, 2), (1, 2), (1, 2), (0, 0)]
    /// this helper will then transform it into accumulated amounts with non-overlapping patterns:
    /// [(1, 2), (1, 1), (2, 2), (2, 1), (2, 0)]
    /// the first component is used to count the number of matches,
    /// the second is used to check if it's inside a pattern (pattern len for the beginning of the pattern, 1 for the end;
    /// and anything above 1 for the pattern)
    #[inline]
    fn accumulate_clear_pat_starts<
        M: ParallelIterator<Item = Option<(Option<FheUsize>, FheUsize)>>,
    >(
        &self,
        pattern_starts: M,
    ) -> impl ParallelIterator<Item = Option<(Option<FheUsize>, FheUsize)>> + '_ {
        scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x)), Some((count_y, start_y))) => {
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        start_y,
                    );
                    Some((self.add(count_x.as_ref(), count_y.as_ref()), next_start))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
    }

    /// A helper to turn unpadded encrypted string to a padded one
    /// for a compatibility with existing methods (as not all have unpadded versions yet)
    #[inline]
    fn pad_string(&self, unpadded: &FheString<Unpadded>) -> FheString<Padded> {
        let str_ref = unpadded.as_ref();
        let mut result = str_ref.to_vec();
        result.push(self.false_ct().into());
        FheString::new_unchecked(result)
    }
}
