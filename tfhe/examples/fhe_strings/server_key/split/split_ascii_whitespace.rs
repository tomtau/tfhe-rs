use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};

use crate::ciphertext::FheString;
use crate::server_key::ServerKey;

use super::{FheSplitResult, SplitFoundPattern};

impl ServerKey {
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
    ///     client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///     vec!["A", "few", "words"]
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
    /// let s = client_key
    ///     .encrypt_str(" Mary   had\ta little  \n\t lamb")
    ///     .unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///     vec!["Mary", "had", "a", "little", "lamb"]
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
    ///     client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///     vec![]
    /// );
    /// let s = client_key.encrypt_str("   ").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split_ascii_whitespace(s)),
    ///     vec![]
    /// );
    /// ```
    #[must_use = "this returns the split FheString as an iterator, \
                      without modifying the original"]
    #[inline]
    pub fn split_ascii_whitespace(&self, encrypted_str: &FheString) -> FheSplitResult {
        let enc_str = self.pad_string(encrypted_str); // TODO: is it necessary?
        let str_ref = enc_str.as_ref();
        let zero = self.false_ct();
        let mut split_sequence = SplitFoundPattern::new();
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
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn split_ascii_whitespace_test(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        assert_eq!(
            input.split_ascii_whitespace().collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split_ascii_whitespace(&encrypted_str))
        );
    }

    #[test_matrix(
        ["A few words",
        " Mary   had\ta little  \n\t lamb",
        // "",
        "   ",
        "    a  b c"],
        1..=3
    )]
    fn test_split_ascii_whitespace(input: &str, padding_len: usize) {
        split_ascii_whitespace_test(input, padding_len)
    }

    #[test_matrix(
        [""],
        1..=3
    )]
    fn test_split_ascii_whitespace_empty(input: &str, padding_len: usize) {
        split_ascii_whitespace_test(input, padding_len)
    }
}
