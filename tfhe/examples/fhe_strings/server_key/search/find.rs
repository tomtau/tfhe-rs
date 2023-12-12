use rayon::prelude::*;

use crate::ciphertext::{FheOption, FheString, FheUsize, Pattern};
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and a byte index)
    /// that contains the byte index for the first character of the first match of the pattern in
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0` in the first tuple component) if the pattern doesn't
    /// match.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Examples
    ///
    /// ```
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, "a")),
    ///     Some(1)
    /// );
    /// let a = client_key.encrypt_str("a").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, a)),
    ///     Some(1)
    /// );
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, "z")),
    ///     None
    /// );
    /// let z = client_key.encrypt_str("z").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, z)),
    ///     None
    /// );
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn find<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheOption<FheUsize> {
        match (encrypted_str, pat.into()) {
            (FheString::Padded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return (self.true_ct(), self.zero_ct());
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return (self.false_ct(), self.zero_ct());
                }
                let fst = encrypted_str.as_ref();
                self.find_clear_pat_index(fst, pat, true)
            }
            (FheString::Padded(_), Pattern::Encrypted(pat @ FheString::Padded(_))) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return (self.true_ct(), self.zero_ct());
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| {
                        (
                            self.starts_with_encrypted_par(&fst[i..], snd),
                            self.0.create_trivial_radix(i as u64, self.1),
                        )
                    })
                    .reduce(
                        || (self.is_empty(pat), self.zero_ct()),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.0.boolean_bitor(&x_starts, &y_starts),
                                || self.0.if_then_else_parallelized(&x_starts, &x_i, &y_i),
                            )
                        },
                    )
            }
            (FheString::Unpadded(_), Pattern::Clear(pat)) => {
                if pat.is_empty() {
                    return (self.true_ct(), self.zero_ct());
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return (self.false_ct(), self.zero_ct());
                }
                let fst = encrypted_str.as_ref();
                self.find_clear_pat_index(fst, pat, true)
            }
            (FheString::Unpadded(_), Pattern::Encrypted(pat @ FheString::Unpadded(_))) => {
                let snd = pat.as_ref();
                if snd.is_empty() {
                    return (self.true_ct(), self.zero_ct());
                }
                let fst = encrypted_str.as_ref();
                self.unpadded_window_equals(snd, fst).reduce(
                    || (self.false_ct(), self.zero_ct()),
                    |(x_starts, x_i), (y_starts, y_i)| {
                        rayon::join(
                            || self.0.boolean_bitor(&x_starts, &y_starts),
                            || self.0.if_then_else_parallelized(&x_starts, &x_i, &y_i),
                        )
                    },
                )
            }
            // TODO: more effiecient versions for combinations of padded and unpadded
            (x, Pattern::Encrypted(y)) => {
                let px = self.pad_string(x);
                let py = self.pad_string(y);
                self.find(&px, &py)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["bananas"],
        ["a", "z"],
        1..=3
    )]
    fn test_find_padded(input: &str, pattern: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        assert_eq!(
            input.find(pattern),
            client_key.decrypt_option_usize(&server_key.find(&encrypted_str, pattern))
        );
        assert_eq!(
            input.find(pattern),
            client_key.decrypt_option_usize(&server_key.find(&encrypted_str, &encrypted_pattern))
        );
    }

    #[test_matrix(
        ["bananas"],
        ["a", "z"]
    )]
    fn test_find_unpadded(input: &str, pattern: &str) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);
        let encrypted_str = client_key.encrypt_str(input).unwrap();
        let encrypted_pattern = client_key.encrypt_str(pattern).unwrap();
        assert_eq!(
            input.find(pattern),
            client_key.decrypt_option_usize(&server_key.find(&encrypted_str, pattern))
        );
        assert_eq!(
            input.find(pattern),
            client_key.decrypt_option_usize(&server_key.find(&encrypted_str, &encrypted_pattern))
        );
    }
}
