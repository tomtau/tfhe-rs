use crate::ciphertext::{FheString, Padded, Pattern};
use crate::server_key::ServerKey;

use super::FheSplitResult;

impl ServerKey {
    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// Equivalent to [`split`], except that the trailing substring
    /// is skipped if empty.
    ///
    /// [`split`]: ServerKey::split
    ///
    /// This method can be used for string data that is _terminated_,
    /// rather than _separated_ by a pattern.
    ///
    /// # Iterator behavior
    ///
    /// If the pattern allows a reverse search but its results might differ
    /// from a forward search, the [`rsplit_terminator`] method can be used.
    ///
    /// [`rsplit_terminator`]: ServerKey::rsplit_terminator
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("A.B.").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split_terminator(s, ".")),
    ///     vec!["A", "B"]
    /// );
    ///
    /// let s = client_key.encrypt_str("A..B..").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split_terminator(s, ".")),
    ///     vec!["A", "", "B", ""]
    /// );
    /// ```
    #[inline]
    pub fn split_terminator<'a, P: Into<Pattern<'a, Padded>>>(
        &'a self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.split_inner(encrypted_str, pat);
        //	                      ______
        //	                   <((((((\\\
        //	                   /      . }\
        //	                   ;--..--._|}
        //	(\                 '--/\--'  )
        //	 \\                | '-'  :'|
        //	  \\               . -==- .-|
        //	   \\               \.__.'   \--._
        //	   [\\          __.--|       //  _/'--.
        //	   \ \\       .'-._ ('-----'/ __/      \
        //	    \ \\     /   __>|      | '--.       |
        //	     \ \\   |   \   |     /    /       /
        //	      \ '\ /     \  |     |  _/       /
        //	       \  \       \ |     | /        /
        //	 snd    \  \      \        /
        FheSplitResult::SplitTerminator(pat_len, pattern_splits)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        [("Mary had a little lamb", " "),
        ("", "X"),
        ("lionXXtigerXleo", "X"),
        ("lion::tiger::leo", "::"),
        ("9999a99b9c", "9"),
        ("(///)", "/"),
        ("010", "0"),
        ("rust", ""),
        ("    a  b c", " "),
        ("banana", "ana"),
        ("foo:bar", "foo:"),
        ("foo:bar", "bar"),
        ("A9B9", "9"),
        ("A..B..", "."),],
        1..=3
    )]
    fn test_split_terminator((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
            .unwrap();
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            input.split_terminator(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split_terminator(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            input.split_terminator(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(
                server_key.split_terminator(&encrypted_str, &encrypted_split_pattern)
            )
        );
    }
}
