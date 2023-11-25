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

use crate::ciphertext::{FheAsciiChar, FheBool, FheUsize};
use crate::client_key::{ClientKey, PRECISION_BITS};

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
        const NUM_BLOCKS: usize = 4;
        Self(key, NUM_BLOCKS)
    }
}

/// 0c == \f == form feed
/// 0b == \v == vertical tab
const ASCII_WHITESPACES: [char; 6] = [' ', '\t', '\n', '\r', '\x0c', '\x0b'];

impl ServerKey {
    #[inline]
    fn is_whitespace(&self, c: &FheAsciiChar) -> FheBool {
        ASCII_WHITESPACES
            .par_iter()
            .map(|&x| Some(self.0.scalar_eq_parallelized(c.as_ref(), x as u8)))
            .reduce(|| None, |a, b| self.or(a.as_ref(), b.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn true_ct(&self) -> FheBool {
        self.0.create_trivial_radix(1, self.1)
    }

    #[inline]
    fn false_ct(&self) -> FheBool {
        self.0.create_trivial_zero_radix(self.1)
    }

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

    #[inline]
    fn or(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitor_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    #[inline]
    fn add(&self, a: Option<&FheUsize>, b: Option<&FheUsize>) -> Option<FheUsize> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.add_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

    #[inline]
    fn and_true(&self, a: Option<&FheBool>, b: Option<&FheBool>) -> Option<FheBool> {
        match (a, b) {
            (Some(a), Some(b)) => Some(self.0.bitand_parallelized(a, b)),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        }
    }

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

    #[inline]
    fn par_eq(&self, fst: &[FheAsciiChar], snd: &[FheAsciiChar]) -> FheBool {
        fst.par_iter()
            .zip(snd.par_iter())
            .map(|(x, y)| Some(self.0.eq_parallelized(x.as_ref(), y.as_ref())))
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }

    #[inline]
    fn par_eq_clear_cached(
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
            .map(|((i, x), y)| {
                let key = (i, *y);
                let result = cache.get(&key).map(|v| v.clone()).unwrap_or_else(|| {
                    let v = self.0.scalar_eq_parallelized(x.as_ref(), *y);
                    cache.insert(key, v.clone());
                    v
                });
                Some(result)
            })
            .reduce(|| None, |x, y| self.and_true(x.as_ref(), y.as_ref()))
            .unwrap_or_else(|| self.false_ct())
    }
}
