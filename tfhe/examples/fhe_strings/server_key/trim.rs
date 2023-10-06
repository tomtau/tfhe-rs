use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelBridge,
    ParallelIterator,
};

use crate::ciphertext::{FheString, Pattern};

use super::ServerKey;

/// 0c == \f == form feed
/// 0b == \v == vertical tab
const ASCII_WHITESPACES: [char; 6] = [' ', '\t', '\n', '\r', '\x0c', '\x0b'];

impl ServerKey {
    /// Returns a string slice with the prefix removed.
    ///
    /// If the string starts with the pattern `prefix`, returns substring after the prefix, wrapped
    /// in `Some`.  Unlike `trim_start_matches`, this method removes the prefix exactly once.
    ///
    /// If the string does not start with `prefix`, returns `None`.
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
    /// assert_eq!("foo:bar".strip_prefix("foo:"), Some("bar"));
    /// assert_eq!("foo:bar".strip_prefix("bar"), None);
    /// assert_eq!("foofoo".strip_prefix("foo"), Some("foo"));
    /// ```
    #[must_use = "this returns the remaining substring as a new slice, \
                  without modifying the original"]
    pub fn strip_prefix<'a>(
        &self,
        encrypted_str: &FheString,
        prefix: Pattern<'a>,
    ) -> Option<&'a str> {
        todo!()
    }

    /// Returns a string slice with the suffix removed.
    ///
    /// If the string ends with the pattern `suffix`, returns the substring before the suffix,
    /// wrapped in `Some`.  Unlike `trim_end_matches`, this method removes the suffix exactly once.
    ///
    /// If the string does not end with `suffix`, returns `None`.
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
    /// assert_eq!("bar:foo".strip_suffix(":foo"), Some("bar"));
    /// assert_eq!("bar:foo".strip_suffix("bar"), None);
    /// assert_eq!("foofoo".strip_suffix("foo"), Some("foo"));
    /// ```
    #[must_use = "this returns the remaining substring as a new slice, \
                  without modifying the original"]
    pub fn strip_suffix<'a>(
        &self,
        encrypted_str: &FheString,
        suffix: Pattern<'a>,
    ) -> Option<&'a str> {
        todo!()
    }

    /// Returns a string slice with leading and trailing whitespace removed.
    ///
    /// 'Whitespace' is defined according to the terms of the Unicode Derived
    /// Core Property `White_Space`, which includes newlines.
    ///
    /// # Examples
    ///
    /// ```
    /// let s = "\n Hello\tworld\t\n";
    ///
    /// assert_eq!("Hello\tworld", s.trim());
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a slice, \
                  without modifying the original"]
    pub fn trim(&self, encrypted_str: &FheString) -> &str {
        todo!()
    }

    /// Returns a string slice with trailing whitespace removed.
    ///
    /// 'Whitespace' is defined according to the terms of the Unicode Derived
    /// Core Property `White_Space`, which includes newlines.
    ///
    /// # Text directionality
    ///
    /// A string is a sequence of bytes. `end` in this context means the last
    /// position of that byte string; for a left-to-right language like English or
    /// Russian, this will be right side, and for right-to-left languages like
    /// Arabic or Hebrew, this will be the left side.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "\n Hello\tworld\t\n";
    /// assert_eq!("\n Hello\tworld", s.trim_end());
    /// ```
    ///
    /// Directionality:
    ///
    /// ```
    /// let s = "  English  ";
    /// assert!(Some('h') == s.trim_end().chars().rev().next());
    ///
    /// let s = "  עברית  ";
    /// assert!(Some('ת') == s.trim_end().chars().rev().next());
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new FheString, \
                  without modifying the original"]
    pub fn trim_end(&self, encrypted_str: &FheString) -> FheString {
        todo!()
    }

    /// Returns a string slice with leading whitespace removed.
    ///
    /// 'Whitespace' is defined according to the terms of the Unicode Derived
    /// Core Property `White_Space`, which includes newlines.
    ///
    /// # Text directionality
    ///
    /// A string is a sequence of bytes. `start` in this context means the first
    /// position of that byte string; for a left-to-right language like English or
    /// Russian, this will be left side, and for right-to-left languages like
    /// Arabic or Hebrew, this will be the right side.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "\n Hello\tworld\t\n";
    /// assert_eq!("Hello\tworld\t\n", s.trim_start());
    /// ```
    ///
    /// Directionality:
    ///
    /// ```
    /// let s = "  English  ";
    /// assert!(Some('E') == s.trim_start().chars().next());
    ///
    /// let s = "  עברית  ";
    /// assert!(Some('ע') == s.trim_start().chars().next());
    /// ```
    #[inline]
    #[must_use = "this returns the trimmed string as a new slice, \
                  without modifying the original"]
    pub fn trim_start(&self, encrypted_str: &FheString) -> &str {
        todo!()
    }
}
