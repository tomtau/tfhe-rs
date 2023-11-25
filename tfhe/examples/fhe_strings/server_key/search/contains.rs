use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;

use crate::ciphertext::{FheBool, FheString, Padded, Pattern};
use crate::server_key::ServerKey;

impl ServerKey {
    /// Returns an encrypted `true` (`1`) if the given pattern matches a sub-slice of
    /// `encrypted_str`.
    ///
    /// Returns an encrypted `false` (`0`) if it does not.
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
    /// assert!(client_key.decrypt_bool(&server_key.contains(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.contains(&bananas, nana)));
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, "apples")));
    /// let apples = client_key.encrypt_str("apples").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, &apples)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn contains<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => {
                if pat.is_empty() {
                    return self.true_ct();
                }
                if pat.len() > encrypted_str.as_ref().len() {
                    return self.false_ct();
                }
                let fst = encrypted_str.as_ref();
                fst.par_windows(pat.len())
                    .map(|window| Some(self.starts_with_clear_par(window, pat)))
                    .reduce(|| None, |x, y| self.or(x.as_ref(), y.as_ref()))
                    .unwrap_or_else(|| self.false_ct())
            }
            Pattern::Encrypted(pat) => {
                let snd = pat.as_ref();
                if snd.len() < 2 {
                    return self.true_ct();
                }
                let fst = encrypted_str.as_ref();
                (0..fst.len())
                    .into_par_iter()
                    .map(|i| self.starts_with_encrypted_par(&fst[i..], snd))
                    .reduce(
                        || self.is_empty(pat),
                        |x, y| self.0.bitor_parallelized(&x, &y),
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
        ["nana", "apples"],
        1..=3
    )]
    fn test_contains(input: &str, pattern: &str, padding_len: usize) {
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
            input.contains(pattern),
            client_key.decrypt_bool(&server_key.contains(&encrypted_str, pattern))
        );
        assert_eq!(
            input.contains(pattern),
            client_key.decrypt_bool(&server_key.contains(&encrypted_str, &encrypted_pattern))
        );
    }
}
