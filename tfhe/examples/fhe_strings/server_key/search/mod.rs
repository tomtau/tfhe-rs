use crate::ciphertext::{FheAsciiChar, FheOption, FheUsize};
use crate::server_key::ServerKey;
use dashmap::DashMap;
use rayon::prelude::*;

mod contains;
mod ends_with;
mod find;
mod rfind;
mod starts_with;

impl ServerKey {
    /// A helper that finds the first occurrence of the given pattern in the given encrypted string.
    /// Returns a tuple: a flag, i.e. encrypted `1` (true/Some) or `0` (false/None), and a byte
    /// index. If `left_match` is true, the index is the index of the first match.
    /// If `left_match` is false, the index is the index of the last match.
    #[inline]
    fn find_clear_pat_index(
        &self,
        fst: &[FheAsciiChar],
        pat: &str,
        left_match: bool,
    ) -> FheOption<FheUsize> {
        let cache = DashMap::new();
        let (found, index) = fst
            .par_windows(pat.len())
            .enumerate()
            .map(|(i, window)| {
                (
                    Some(self.par_eq_clear_unpadded_cached(i, window, pat, &cache)),
                    self.0.create_trivial_radix(i as u64, self.1),
                )
            })
            .reduce(
                || (None, self.0.create_trivial_radix(u64::MAX, self.1)),
                |(x_starts, x_i), (y_starts, y_i)| {
                    rayon::join(
                        || self.or(x_starts.as_ref(), y_starts.as_ref()),
                        || {
                            if left_match {
                                self.if_then_else(x_starts.as_ref(), false, &x_i, &y_i)
                            } else {
                                self.if_then_else(y_starts.as_ref(), false, &y_i, &x_i)
                            }
                        },
                    )
                },
            );
        (found.unwrap_or_else(|| self.false_ct()), index)
    }
}
