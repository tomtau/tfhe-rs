use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::ciphertext::{FheOption, FheString, FheUsize, Padded, Pattern};
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns an encrypted option (a tuple: a flag, i.e. encrypted `1`, and a byte index)
    /// that contains the byte index for the first character of the last match of the pattern in
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
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let bananas = client_key.encrypt_str("bananas").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, "a")),
    ///     Some(5)
    /// );
    /// let a = client_key.encrypt_str("a").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_option_usize(&server_key.find(&bananas, a)),
    ///     Some(5)
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
    /// ```
    #[inline]
    pub fn rfind<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheOption<FheUsize> {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return (self.true_ct(), self.len(encrypted_str));
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return (self.false_ct(), self.false_ct());
                }
                let fst = encrypted_str.as_ref();
                self.find_clear_pat_index(fst, pat, false)
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                let len = self.len(encrypted_str);
                if snd.len() < 2 {
                    return (self.true_ct(), len);
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| {
                        (
                            self.starts_with_encrypted_par(&fst[i..], snd),
                            self.0.if_then_else_parallelized(
                                &self.0.scalar_eq_parallelized(fst[i].as_ref(), 0),
                                &len,
                                &self.0.create_trivial_radix(i as u64, self.1),
                            ),
                        )
                    })
                    .reduce(
                        || (self.is_empty(pat), len.clone()),
                        |(x_starts, x_i), (y_starts, y_i)| {
                            rayon::join(
                                || self.0.bitor_parallelized(&x_starts, &y_starts),
                                || self.0.if_then_else_parallelized(&y_starts, &y_i, &x_i),
                            )
                        },
                    )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["bananas"],
        ["a", "z"],
        1..=3
    )]
    fn test_rfind(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_pattern = client_key
            .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.rfind(pattern),
            client_key.decrypt_option_usize(&server_key.rfind(&encrypted_str, pattern))
        );
        assert_eq!(
            input.rfind(pattern),
            client_key.decrypt_option_usize(&server_key.rfind(&encrypted_str, &encrypted_pattern))
        );
    }
}
