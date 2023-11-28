use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::ciphertext::{FheAsciiChar, FheBool};

use super::ServerKey;

mod eq;
mod eq_ignore_case;
mod ge;
mod le;
mod ne;

impl ServerKey {
    /// A helper that compares two encrypted strings lexicographically.
    /// (It assumes that `fst` and `snd` have the same length.)
    /// The first component says if any characters were not equal.
    /// The second component says if `fst` is lexicographically greater than `snd`.
    #[inline]
    fn par_ge(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> (Option<FheBool>, FheBool) {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| {
                rayon::join(
                    || Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())),
                    || self.0.gt_parallelized(x.as_ref(), y.as_ref()),
                )
            })
            .reduce(
                || (None, self.true_ct()),
                |(previous_ne, previous_gt), (current_ne, current_gt)| {
                    rayon::join(
                        || self.or(previous_ne.as_ref(), current_ne.as_ref()),
                        || {
                            self.if_then_else(
                                previous_ne.as_ref(),
                                false,
                                &previous_gt,
                                &current_gt,
                            )
                        },
                    )
                },
            )
    }

    /// A helper that compares two encrypted strings lexicographically.
    /// (It assumes that `fst` and `snd` have the same length.)
    /// The first component says if any characters were not equal.
    /// The second component says if `fst` is lexicographically smaller than `snd`.
    #[inline]
    fn par_le(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> (Option<FheBool>, FheBool) {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| {
                rayon::join(
                    || Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())),
                    || self.0.lt_parallelized(x.as_ref(), y.as_ref()),
                )
            })
            .reduce(
                || (None, self.true_ct()),
                |(previous_ne, previous_lt), (current_ne, current_lt)| {
                    rayon::join(
                        || self.or(previous_ne.as_ref(), current_ne.as_ref()),
                        || {
                            self.if_then_else(
                                previous_ne.as_ref(),
                                false,
                                &previous_lt,
                                &current_lt,
                            )
                        },
                    )
                },
            )
    }

    /// A helper that checks that all elements of `fst` are not equal to `snd`.
    /// (It assumes that `fst` and `snd` have the same length.)
    #[inline]
    fn par_ne(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| Some(self.0.ne_parallelized(x.as_ref(), y.as_ref())))
            .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// A helper that checks that all elements of `fst` are not equal to zero.
    /// (used for checking the equality of padded `FheString` where we don't
    /// know the length of the string)
    #[inline]
    fn par_ne_zero(&self, fst: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .map(|x| Some(self.0.scalar_ne_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    /// A helper that checks that all elements of `fst` are equal to zero.
    /// (used for checking the equality of padded `FheString` where we don't
    /// know the length of the string)
    #[inline]
    fn par_eq_zero(&self, fst: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x.as_ref(), 0)))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.true_ct())
    }
}
