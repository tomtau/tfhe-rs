mod split;
mod trim;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tfhe::integer::ServerKey as IntegerServerKey;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number, Pattern},
    client_key::{ClientKey, NUM_BLOCKS},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ServerKey(IntegerServerKey);

impl From<&ClientKey> for ServerKey {
    fn from(key: &ClientKey) -> Self {
        Self(IntegerServerKey::new(key))
    }
}

impl From<IntegerServerKey> for ServerKey {
    fn from(key: IntegerServerKey) -> Self {
        Self(key)
    }
}

impl ServerKey {
    #[inline]
    fn true_ct(&self) -> FheBool {
        self.0.create_trivial_radix(1, NUM_BLOCKS)
    }

    #[inline]
    fn false_ct(&self) -> FheBool {
        self.0.create_trivial_zero_radix(NUM_BLOCKS)
    }

    #[inline]
    fn check_scalar_range(&self, encrypted_char: &FheAsciiChar, start: u8, end: u8) -> FheBool {
        let ge_from = self.0.scalar_ge_parallelized(encrypted_char, start);
        let le_to = self.0.scalar_le_parallelized(encrypted_char, end);
        self.0.bitand_parallelized(&ge_from, &le_to)
    }

    /// Returns `true` if the given pattern matches a sub-slice of
    /// this string slice.
    ///
    /// Returns `false` if it does not.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Examples
    ///
    /// ```
    /// let bananas = "bananas";
    ///
    /// assert!(bananas.contains("nana"));
    /// assert!(!bananas.contains("apples"));
    /// ```
    ///
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn contains<'a>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> bool {
        todo!()
    }

    /// Returns `true` if the given pattern matches a suffix of this
    /// string slice.
    ///
    /// Returns `false` if it does not.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Examples
    ///
    /// ```
    /// let bananas = "bananas";
    ///
    /// assert!(bananas.ends_with("anas"));
    /// assert!(!bananas.ends_with("nana"));
    /// ```
    pub fn ends_with<'a, P>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> bool {
        todo!()
    }

    /// Checks that two strings are an ASCII case-insensitive match.
    ///
    /// Same as `to_ascii_lowercase(a) == to_ascii_lowercase(b)`,
    /// but without allocating and copying temporaries.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!("Ferris".eq_ignore_ascii_case("FERRIS"));
    /// assert!("Ferrös".eq_ignore_ascii_case("FERRöS"));
    /// assert!(!"Ferrös".eq_ignore_ascii_case("FERRÖS"));
    /// ```
    #[must_use]
    #[inline]
    pub fn eq_ignore_case(
        &self,
        encrypted_str: &FheString,
        other_encrypted_str: &FheString,
    ) -> bool {
        todo!("eq_ignore_case")
    }

    /// Returns the byte index of the first character of this string slice that
    /// matches the pattern.
    ///
    /// Returns [`None`] if the pattern doesn't match.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard Gepardi";
    ///
    /// assert_eq!(s.find('L'), Some(0));
    /// assert_eq!(s.find('é'), Some(14));
    /// assert_eq!(s.find("pard"), Some(17));
    /// ```
    ///
    /// More complex patterns using point-free style and closures:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard";
    ///
    /// assert_eq!(s.find(char::is_whitespace), Some(5));
    /// assert_eq!(s.find(char::is_lowercase), Some(1));
    /// assert_eq!(s.find(|c: char| c.is_whitespace() || c.is_lowercase()), Some(1));
    /// assert_eq!(s.find(|c: char| (c < 'o') && (c > 'a')), Some(4));
    /// ```
    ///
    /// Not finding the pattern:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard";
    /// let x: &[_] = &['1', '2'];
    ///
    /// assert_eq!(s.find(x), None);
    /// ```
    #[inline]
    pub fn find<'a>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> Option<usize> {
        todo!()
    }

    /// Returns an encrypted `true` (`1`) if `encrypted_str` has a length of zero bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.is_empty(&s)));
    ///
    /// let s = client_key.encrypt_str("not empty").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.is_empty(&s)));
    /// ```
    #[must_use]
    #[inline]
    pub fn is_empty(&self, encrypted_str: &FheString) -> FheBool {
        self.0.scalar_eq_parallelized(&encrypted_str.as_ref()[0], 0)
    }

    /// Returns the length of `encrypted_str`.
    ///
    /// This length is in bytes (minus the null-terminating byte or any zero-padding bytes).
    /// In other words, it is what a human considers the length of the ASCII string.
    ///
    /// # Examples
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("foo").unwrap();
    /// let len = server_key.len(&s);
    /// assert_eq!(3, client_key.decrypt_usize(&len));
    /// ```
    #[must_use]
    #[inline]
    pub fn len(&self, encrypted_str: &FheString) -> FheUsize {
        encrypted_str
            .as_ref()
            .par_iter()
            .map(|x| self.0.scalar_ne_parallelized(x, 0))
            .reduce(|| self.false_ct(), |a, b| self.0.add_parallelized(&a, &b))
    }

    /// Creates a new [`String`] by repeating a string `n` times.
    ///
    /// # Panics
    ///
    /// This function will panic if the capacity would overflow.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// assert_eq!("abc".repeat(4), String::from("abcabcabcabc"));
    /// ```
    ///
    /// A panic upon overflow:
    ///
    /// ```should_panic
    /// // this will panic at runtime
    /// let huge = "0123456789abcdef".repeat(usize::MAX);
    /// ```
    #[must_use]
    pub fn repeat(&self, encrypted_str: &FheString, n: Number) -> String {
        todo!()
    }

    /// Replaces all matches of a pattern with another string.
    ///
    /// `replace` creates a new [`String`], and copies the data from this string slice into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "this is old";
    ///
    /// assert_eq!("this is new", s.replace("old", "new"));
    /// assert_eq!("than an old", s.replace("is", "an"));
    /// ```
    ///
    /// When the pattern doesn't match, it returns this string slice as [`String`]:
    ///
    /// ```
    /// let s = "this is old";
    /// assert_eq!(s, s.replace("cookie monster", "little lamb"));
    /// ```
    #[must_use = "this returns the replaced string as a new allocation, \
                  without modifying the original"]
    #[inline]
    pub fn replace<'a>(&self, encrypted_str: &FheString, from: Pattern<'a>, to: &str) -> String {
        todo!()
    }

    /// Replaces first N matches of a pattern with another string.
    ///
    /// `replacen` creates a new [`String`], and copies the data from this string slice into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice at most `count` times.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "foo foo 123 foo";
    /// assert_eq!("new new 123 foo", s.replacen("foo", "new", 2));
    /// assert_eq!("faa fao 123 foo", s.replacen('o', "a", 3));
    /// assert_eq!("foo foo new23 foo", s.replacen(char::is_numeric, "new", 1));
    /// ```
    ///
    /// When the pattern doesn't match, it returns this string slice as [`String`]:
    ///
    /// ```
    /// let s = "this is old";
    /// assert_eq!(s, s.replacen("cookie monster", "little lamb", 10));
    /// ```
    #[must_use = "this returns the replaced string as a new allocation, \
                  without modifying the original"]
    pub fn replacen<'a>(
        &'a self,
        encrypted_str: &FheString,
        pat: Pattern<'a>,
        to: &str,
        count: usize,
    ) -> String {
        todo!()
    }

    /// Returns the byte index for the first character of the last match of the pattern in
    /// this string slice.
    ///
    /// Returns [`None`] if the pattern doesn't match.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard Gepardi";
    ///
    /// assert_eq!(s.rfind('L'), Some(13));
    /// assert_eq!(s.rfind('é'), Some(14));
    /// assert_eq!(s.rfind("pard"), Some(24));
    /// ```
    ///
    /// More complex patterns with closures:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard";
    ///
    /// assert_eq!(s.rfind(char::is_whitespace), Some(12));
    /// assert_eq!(s.rfind(char::is_lowercase), Some(20));
    /// ```
    ///
    /// Not finding the pattern:
    ///
    /// ```
    /// let s = "Löwe 老虎 Léopard";
    /// let x: &[_] = &['1', '2'];
    ///
    /// assert_eq!(s.rfind(x), None);
    /// ```
    #[inline]
    pub fn rfind<'a>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> Option<usize> {
        todo!()
    }

    /// Returns an encrypted `true` (`1`) if the given pattern matches a prefix of this
    /// string slice.
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
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, "bana")));
    /// let bana = client_key.encrypt_str("bana").unwrap();
    /// assert!(client_key.decrypt_bool(&server_key.starts_with(&bananas, &bana)));
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, "nana")));
    /// let nana = client_key.encrypt_str("nana").unwrap();
    /// assert!(!client_key.decrypt_bool(&server_key.starts_with(&bananas, &nana)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    pub fn starts_with<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheBool {
        match pat.into() {
            Pattern::Clear(pat) => {
                if encrypted_str.as_ref().len() < pat.len() {
                    self.false_ct()
                } else {
                    encrypted_str
                        .as_ref()
                        .par_iter()
                        .zip(pat.as_bytes().par_iter())
                        .map(|(a, b)| self.0.scalar_eq_parallelized(a, *b as u64))
                        .reduce(|| self.true_ct(), |s, x| self.0.bitand_parallelized(&s, &x))
                }
            }
            Pattern::Encrypted(pat) => {
                if encrypted_str.as_ref().len() < pat.as_ref().len() {
                    self.false_ct()
                } else {
                    encrypted_str
                        .as_ref()
                        .par_iter()
                        .zip(pat.as_ref().par_iter())
                        .map(|(a, b)| {
                            let pattern_ended = self.0.scalar_eq_parallelized(b, 0);
                            self.0.if_then_else_parallelized(
                                &pattern_ended,
                                &self.true_ct(),
                                &self.0.eq_parallelized(&a, &b),
                            )
                        })
                        .reduce(|| self.true_ct(), |s, x| self.0.bitand_parallelized(&s, &x))
                }
            }
        }
    }

    /// Returns the lowercase equivalent of this encrypted string as a new [`FheString`].
    ///
    /// 'Lowercase' is defined as adding 32 to the uppercase character, otherwise it remains the same.
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
    /// let s = client_key.encrypt_str("HELLO").unwrap();
    /// assert_eq!("hello", client_key.decrypt_str(&server_key.to_lowercase(&s)));
    ///
    /// let s = client_key.encrypt_str("hello").unwrap();
    /// assert_eq!("hello", client_key.decrypt_str(&server_key.to_lowercase(&s)));
    /// ```
    #[must_use = "this returns the lowercase string as a new FheString, \
                  without modifying the original"]
    pub fn to_lowercase(&self, encrypted_str: &FheString) -> FheString {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'A' == 65, 'Z' == 90
                    let is_upper = self.check_scalar_range(x, 65, 90);
                    let converted = self.0.scalar_add_parallelized(x, 32);
                    // (is_upper & converted) | (!is_upper & x)
                    self.0.if_then_else_parallelized(&is_upper, &converted, x)
                })
                .collect(),
        )
    }

    /// Returns the uppercase equivalent of this encrypted string as a new [`FheString`].
    ///
    /// 'Uppercase' is defined as subtracting 32 from the lowercase character, otherwise it remains the same.
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
    /// let s = client_key.encrypt_str("hello").unwrap();
    /// assert_eq!("HELLO", client_key.decrypt_str(&server_key.to_uppercase(&s)));
    ///
    /// let s = client_key.encrypt_str("HELLO").unwrap();
    /// assert_eq!("HELLO", client_key.decrypt_str(&server_key.to_uppercase(&s)));
    /// ```
    #[must_use = "this returns the uppercase string as a new FheString, \
                  without modifying the original"]
    pub fn to_uppercase(&self, encrypted_str: &FheString) -> FheString {
        FheString::new_unchecked(
            encrypted_str
                .as_ref()
                .par_iter()
                .map(|x| {
                    // 'a' == 97, 'z' == 122
                    let is_lower = self.check_scalar_range(x, 97, 122);
                    let converted = self.0.scalar_sub_parallelized(x, 32);
                    // (is_lower & converted) | (!is_lower & x)
                    self.0.if_then_else_parallelized(&is_lower, &converted, x)
                })
                .collect(),
        )
    }

    /// Implementation of [`[T]::concat`](slice::concat)
    pub fn concat(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> FheString {
        todo!()
    }

    /// This method tests greater than or equal to (for `self` and `other`) and is used by the `>=`
    /// operator.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(1.0 >= 1.0, true);
    /// assert_eq!(1.0 >= 2.0, false);
    /// assert_eq!(2.0 >= 1.0, true);
    /// ```
    #[inline]
    #[must_use]
    pub fn ge(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> bool {
        todo!()
    }

    /// This method tests less than or equal to (for `self` and `other`) and is used by the `<=`
    /// operator.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(1.0 <= 1.0, true);
    /// assert_eq!(1.0 <= 2.0, true);
    /// assert_eq!(2.0 <= 1.0, false);
    /// ```
    #[inline]
    #[must_use]
    pub fn le(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> bool {
        todo!()
    }

    /// This method tests for `!=`. The default implementation is almost always
    /// sufficient, and should not be overridden without very good reason.
    #[inline]
    #[must_use]
    pub fn ne(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> bool {
        todo!()
    }

    /// This method tests for `self` and `other` values to be equal, and is used
    /// by `==`.
    #[must_use]
    pub fn eq(&self, encrypted_str: &FheString, other_encrypted_str: &FheString) -> bool {
        todo!()
    }
}
