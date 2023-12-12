mod strip_prefix;
mod strip_suffix;
mod trim_end;
mod trim_start;

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize};
use dashmap::DashMap;
use rayon::prelude::*;

use super::ServerKey;

impl ServerKey {
    /// Returns a new [`FheString`] with leading and trailing whitespace removed.
    ///
    /// 'Whitespace' is defined as one of 6 ASCII characters (' ', '\t', '\n', '\r', '\v', '\f').
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
    ///
    /// let s = client_key.encrypt_str("\n Hello\tworld\t\n").unwrap();
    /// assert_eq!("Hello\tworld", client_key.decrypt_str(&server_key.trim(&s)));
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                  without modifying the original"]
    pub fn trim(&self, encrypted_str: &FheString) -> FheString {
        // TODO: do something better than this
        self.trim_start(&self.trim_end(encrypted_str))
    }

    /// A helper that checks the if encrypted chars at (i, i+1),
    /// i.e. window[0], window[1], are ASCII whitespace.
    /// it uses a cache to avoid re-computing the same thing.
    #[inline]
    fn check_whitespace(
        &self,
        cache_is_whitespace: &DashMap<usize, FheBool>,
        i: usize,
        window: &[FheAsciiChar],
    ) -> (FheBool, FheBool) {
        let left_whitespace = cache_is_whitespace
            .get(&i)
            .map(|v| v.clone())
            .unwrap_or_else(|| {
                let v = self.is_whitespace(&window[0]);
                cache_is_whitespace.insert(i, v.clone());
                v
            });
        let right_whitspace = cache_is_whitespace
            .get(&(i + 1))
            .map(|v| v.clone())
            .unwrap_or_else(|| {
                let v = self.is_whitespace(&window[1]);
                cache_is_whitespace.insert(i + 1, v.clone());
                v
            });
        (left_whitespace, right_whitspace)
    }

    /// A helper that returns the correct encrypted character if the prefix pattern / whitespaces
    /// were removed and the encrypted string needs to be shifted.
    fn shift_zero_prefix(
        &self,
        fst: &[FheAsciiChar],
        shifted_indices: &[FheUsize],
        i: usize,
    ) -> FheAsciiChar {
        (i..shifted_indices.len())
            .into_par_iter()
            .map(|j| {
                self.0.if_then_else_parallelized(
                    &self.0.scalar_eq_parallelized(&shifted_indices[j], i as u64),
                    fst[j].as_ref(),
                    &self.zero_ct(),
                )
            })
            .reduce(|| self.zero_ct(), |a, b| self.0.bitxor_parallelized(&a, &b))
            .into()
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["\n Hello\tworld\t\n"],
        1..=3
    )]
    fn test_trim(input: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);
        let s = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(input.trim(), client_key.decrypt_str(&server_key.trim(&s)));
    }
}
