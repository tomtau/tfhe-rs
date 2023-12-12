use crate::ciphertext::{FheString, Pattern};
use crate::server_key::ServerKey;

use super::FheSplitResult;

impl ServerKey {
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
    ///
    /// let s = client_key.encrypt_str("cfg").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///     vec!["cfg"]
    /// );
    /// let s = client_key.encrypt_str("cfg=foo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///     vec!["cfg", "foo"]
    /// );
    /// let s = client_key.encrypt_str("cfg=foo=bar").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.rsplit_once(s, "=")),
    ///     vec!["cfg=foo", "bar"]
    /// );
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn rsplit_once<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        delimiter: P,
    ) -> FheSplitResult {
        let (_, pat_len, pattern_splits) = self.rsplitn_inner(encrypted_str, 2, delimiter);
        FheSplitResult::RSplitOnce(pat_len, pattern_splits)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["cfg", "cfg=foo", "cfg=foo=bar"],
        ["="],
        1..=3
    )]
    fn test_rsplit_once(input: &str, split_pattern: &str, padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
            .unwrap();

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let rsplit_once = input.rsplit_once(split_pattern);
        let expected = if let Some((x, y)) = rsplit_once {
            vec![x, y]
        } else {
            vec![input]
        };
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            expected,
            client_key.decrypt_split(server_key.rsplit_once(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            expected,
            client_key
                .decrypt_split(server_key.rsplit_once(&encrypted_str, &encrypted_split_pattern))
        );
    }
}
