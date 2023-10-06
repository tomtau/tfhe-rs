use std::marker::PhantomData;

use crate::ciphertext::{FheString, Pattern};

use super::ServerKey;

pub struct RSplit<'a>(PhantomData<&'a ()>);
pub struct RSplitN<'a>(PhantomData<&'a ()>);
pub struct RSplitTerminator<'a>(PhantomData<&'a ()>);

pub struct Split<'a>(PhantomData<&'a ()>);
pub struct SplitAsciiWhitespace<'a>(PhantomData<&'a ()>);
pub struct SplitInclusive<'a>(PhantomData<&'a ()>);
pub struct SplitTerminator<'a>(PhantomData<&'a ()>);
pub struct SplitN<'a>(PhantomData<&'a ()>);

impl ServerKey {
    /// An iterator over substrings of the given string slice, separated by
    /// characters matched by a pattern and yielded in reverse order.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator requires that the pattern supports a reverse
    /// search, and it will be a [`DoubleEndedIterator`] if a forward/reverse
    /// search yields the same elements.
    ///
    /// For iterating from the front, the [`split`] method can be used.
    ///
    /// [`split`]: str::split
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let v: Vec<&str> = "Mary had a little lamb".rsplit(' ').collect();
    /// assert_eq!(v, ["lamb", "little", "a", "had", "Mary"]);
    ///
    /// let v: Vec<&str> = "".rsplit('X').collect();
    /// assert_eq!(v, [""]);
    ///
    /// let v: Vec<&str> = "lionXXtigerXleopard".rsplit('X').collect();
    /// assert_eq!(v, ["leopard", "tiger", "", "lion"]);
    ///
    /// let v: Vec<&str> = "lion::tiger::leopard".rsplit("::").collect();
    /// assert_eq!(v, ["leopard", "tiger", "lion"]);
    /// ```
    ///
    /// A more complex pattern, using a closure:
    ///
    /// ```
    /// let v: Vec<&str> = "abc1defXghi".rsplit(|c| c == '1' || c == 'X').collect();
    /// assert_eq!(v, ["ghi", "def", "abc"]);
    /// ```
    #[inline]
    pub fn rsplit<'a>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> RSplit<'a> {
        todo!()
    }

    /// Splits the string on the last occurrence of the specified delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!("cfg".rsplit_once('='), None);
    /// assert_eq!("cfg=foo".rsplit_once('='), Some(("cfg", "foo")));
    /// assert_eq!("cfg=foo=bar".rsplit_once('='), Some(("cfg=foo", "bar")));
    /// ```
    #[inline]
    pub fn rsplit_once<'a, P>(
        &self,
        encrypted_str: &FheString,
        delimiter: Pattern<'a>,
    ) -> Option<(&'a str, &'a str)> {
        todo!()
    }

    /// An iterator over substrings of this string slice, separated by a
    /// pattern, starting from the end of the string, restricted to returning
    /// at most `n` items.
    ///
    /// If `n` substrings are returned, the last substring (the `n`th substring)
    /// will contain the remainder of the string.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will not be double ended, because it is not
    /// efficient to support.
    ///
    /// For splitting from the front, the [`splitn`] method can be used.
    ///
    /// [`splitn`]: str::splitn
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let v: Vec<&str> = "Mary had a little lamb".rsplitn(3, ' ').collect();
    /// assert_eq!(v, ["lamb", "little", "Mary had a"]);
    ///
    /// let v: Vec<&str> = "lionXXtigerXleopard".rsplitn(3, 'X').collect();
    /// assert_eq!(v, ["leopard", "tiger", "lionX"]);
    ///
    /// let v: Vec<&str> = "lion::tiger::leopard".rsplitn(2, "::").collect();
    /// assert_eq!(v, ["leopard", "lion::tiger"]);
    /// ```
    ///
    /// A more complex pattern, using a closure:
    ///
    /// ```
    /// let v: Vec<&str> = "abc1defXghi".rsplitn(2, |c| c == '1' || c == 'X').collect();
    /// assert_eq!(v, ["ghi", "abc1def"]);
    /// ```
    #[inline]
    pub fn rsplitn<'a>(
        &self,
        encrypted_str: &FheString,
        n: usize,
        pat: Pattern<'a>,
    ) -> RSplitN<'a> {
        todo!()
    }

    /// An iterator over substrings of `self`, separated by characters
    /// matched by a pattern and yielded in reverse order.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// Equivalent to [`split`], except that the trailing substring is
    /// skipped if empty.
    ///
    /// [`split`]: str::split
    ///
    /// This method can be used for string data that is _terminated_,
    /// rather than _separated_ by a pattern.
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator requires that the pattern supports a
    /// reverse search, and it will be double ended if a forward/reverse
    /// search yields the same elements.
    ///
    /// For iterating from the front, the [`split_terminator`] method can be
    /// used.
    ///
    /// [`split_terminator`]: str::split_terminator
    ///
    /// # Examples
    ///
    /// ```
    /// let v: Vec<&str> = "A.B.".rsplit_terminator('.').collect();
    /// assert_eq!(v, ["B", "A"]);
    ///
    /// let v: Vec<&str> = "A..B..".rsplit_terminator(".").collect();
    /// assert_eq!(v, ["", "B", "", "A"]);
    ///
    /// let v: Vec<&str> = "A.B:C.D".rsplit_terminator(&['.', ':'][..]).collect();
    /// assert_eq!(v, ["D", "C", "B", "A"]);
    /// ```
    #[inline]
    pub fn rsplit_terminator<'a>(
        &'a self,
        encrypted_str: &FheString,
        pat: Pattern<'a>,
    ) -> RSplitTerminator<'a> {
        todo!()
    }

    /// An iterator over substrings of this string slice, separated by
    /// characters matched by a pattern.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will be a [`DoubleEndedIterator`] if the pattern
    /// allows a reverse search and forward/reverse search yields the same
    /// elements. This is true for, e.g., [`char`], but not for `&str`.
    ///
    /// If the pattern allows a reverse search but its results might differ
    /// from a forward search, the [`rsplit`] method can be used.
    ///
    /// [`rsplit`]: str::rsplit
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let v: Vec<&str> = "Mary had a little lamb".split(' ').collect();
    /// assert_eq!(v, ["Mary", "had", "a", "little", "lamb"]);
    ///
    /// let v: Vec<&str> = "".split('X').collect();
    /// assert_eq!(v, [""]);
    ///
    /// let v: Vec<&str> = "lionXXtigerXleopard".split('X').collect();
    /// assert_eq!(v, ["lion", "", "tiger", "leopard"]);
    ///
    /// let v: Vec<&str> = "lion::tiger::leopard".split("::").collect();
    /// assert_eq!(v, ["lion", "tiger", "leopard"]);
    ///
    /// let v: Vec<&str> = "abc1def2ghi".split(char::is_numeric).collect();
    /// assert_eq!(v, ["abc", "def", "ghi"]);
    ///
    /// let v: Vec<&str> = "lionXtigerXleopard".split(char::is_uppercase).collect();
    /// assert_eq!(v, ["lion", "tiger", "leopard"]);
    /// ```
    ///
    /// If the pattern is a slice of chars, split on each occurrence of any of the characters:
    ///
    /// ```
    /// let v: Vec<&str> = "2020-11-03 23:59".split(&['-', ' ', ':', '@'][..]).collect();
    /// assert_eq!(v, ["2020", "11", "03", "23", "59"]);
    /// ```
    ///
    /// A more complex pattern, using a closure:
    ///
    /// ```
    /// let v: Vec<&str> = "abc1defXghi".split(|c| c == '1' || c == 'X').collect();
    /// assert_eq!(v, ["abc", "def", "ghi"]);
    /// ```
    ///
    /// If a string contains multiple contiguous separators, you will end up
    /// with empty strings in the output:
    ///
    /// ```
    /// let x = "||||a||b|c".to_string();
    /// let d: Vec<_> = x.split('|').collect();
    ///
    /// assert_eq!(d, &["", "", "", "", "a", "", "b", "c"]);
    /// ```
    ///
    /// Contiguous separators are separated by the empty string.
    ///
    /// ```
    /// let x = "(///)".to_string();
    /// let d: Vec<_> = x.split('/').collect();
    ///
    /// assert_eq!(d, &["(", "", "", ")"]);
    /// ```
    ///
    /// Separators at the start or end of a string are neighbored
    /// by empty strings.
    ///
    /// ```
    /// let d: Vec<_> = "010".split("0").collect();
    /// assert_eq!(d, &["", "1", ""]);
    /// ```
    ///
    /// When the empty string is used as a separator, it separates
    /// every character in the string, along with the beginning
    /// and end of the string.
    ///
    /// ```
    /// let f: Vec<_> = "rust".split("").collect();
    /// assert_eq!(f, &["", "r", "u", "s", "t", ""]);
    /// ```
    ///
    /// Contiguous separators can lead to possibly surprising behavior
    /// when whitespace is used as the separator. This code is correct:
    ///
    /// ```
    /// let x = "    a  b c".to_string();
    /// let d: Vec<_> = x.split(' ').collect();
    ///
    /// assert_eq!(d, &["", "", "", "", "a", "", "b", "c"]);
    /// ```
    ///
    /// It does _not_ give you:
    ///
    /// ```,ignore
    /// assert_eq!(d, &["a", "b", "c"]);
    /// ```
    ///
    /// Use [`split_whitespace`] for this behavior.
    ///
    /// [`split_whitespace`]: str::split_whitespace
    #[inline]
    pub fn split<'a>(&self, encrypted_str: &FheString, pat: Pattern<'a>) -> Split<'a> {
        todo!()
    }

    /// Splits a string slice by ASCII whitespace.
    ///
    /// The iterator returned will return string slices that are sub-slices of
    /// the original string slice, separated by any amount of ASCII whitespace.
    ///
    /// To split by Unicode `Whitespace` instead, use [`split_whitespace`].
    ///
    /// [`split_whitespace`]: str::split_whitespace
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let mut iter = "A few words".split_ascii_whitespace();
    ///
    /// assert_eq!(Some("A"), iter.next());
    /// assert_eq!(Some("few"), iter.next());
    /// assert_eq!(Some("words"), iter.next());
    ///
    /// assert_eq!(None, iter.next());
    /// ```
    ///
    /// All kinds of ASCII whitespace are considered:
    ///
    /// ```
    /// let mut iter = " Mary   had\ta little  \n\t lamb".split_ascii_whitespace();
    /// assert_eq!(Some("Mary"), iter.next());
    /// assert_eq!(Some("had"), iter.next());
    /// assert_eq!(Some("a"), iter.next());
    /// assert_eq!(Some("little"), iter.next());
    /// assert_eq!(Some("lamb"), iter.next());
    ///
    /// assert_eq!(None, iter.next());
    /// ```
    ///
    /// If the string is empty or all ASCII whitespace, the iterator yields no string slices:
    /// ```
    /// assert_eq!("".split_ascii_whitespace().next(), None);
    /// assert_eq!("   ".split_ascii_whitespace().next(), None);
    /// ```
    #[must_use = "this returns the split string as an iterator, \
                  without modifying the original"]
    #[inline]
    pub fn split_ascii_whitespace(&self, encrypted_str: &FheString) -> SplitAsciiWhitespace<'_> {
        todo!()
    }

    /// An iterator over substrings of this string slice, separated by
    /// characters matched by a pattern. Differs from the iterator produced by
    /// `split` in that `split_inclusive` leaves the matched part as the
    /// terminator of the substring.
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
    /// let v: Vec<&str> = "Mary had a little lamb\nlittle lamb\nlittle lamb."
    ///     .split_inclusive('\n').collect();
    /// assert_eq!(v, ["Mary had a little lamb\n", "little lamb\n", "little lamb."]);
    /// ```
    ///
    /// If the last element of the string is matched,
    /// that element will be considered the terminator of the preceding substring.
    /// That substring will be the last item returned by the iterator.
    ///
    /// ```
    /// let v: Vec<&str> = "Mary had a little lamb\nlittle lamb\nlittle lamb.\n"
    ///     .split_inclusive('\n').collect();
    /// assert_eq!(v, ["Mary had a little lamb\n", "little lamb\n", "little lamb.\n"]);
    /// ```
    #[inline]
    pub fn split_inclusive<'a>(
        &self,
        encrypted_str: &FheString,
        pat: Pattern<'a>,
    ) -> SplitInclusive<'a> {
        todo!()
    }

    /// An iterator over substrings of the given string slice, separated by
    /// characters matched by a pattern.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// Equivalent to [`split`], except that the trailing substring
    /// is skipped if empty.
    ///
    /// [`split`]: str::split
    ///
    /// This method can be used for string data that is _terminated_,
    /// rather than _separated_ by a pattern.
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will be a [`DoubleEndedIterator`] if the pattern
    /// allows a reverse search and forward/reverse search yields the same
    /// elements. This is true for, e.g., [`char`], but not for `&str`.
    ///
    /// If the pattern allows a reverse search but its results might differ
    /// from a forward search, the [`rsplit_terminator`] method can be used.
    ///
    /// [`rsplit_terminator`]: str::rsplit_terminator
    ///
    /// # Examples
    ///
    /// ```
    /// let v: Vec<&str> = "A.B.".split_terminator('.').collect();
    /// assert_eq!(v, ["A", "B"]);
    ///
    /// let v: Vec<&str> = "A..B..".split_terminator(".").collect();
    /// assert_eq!(v, ["A", "", "B", ""]);
    ///
    /// let v: Vec<&str> = "A.B:C.D".split_terminator(&['.', ':'][..]).collect();
    /// assert_eq!(v, ["A", "B", "C", "D"]);
    /// ```
    #[inline]
    pub fn split_terminator<'a>(
        &'a self,
        encrypted_str: &FheString,
        pat: Pattern<'a>,
    ) -> SplitTerminator<'a> {
        todo!()
    }

    /// An iterator over substrings of the given string slice, separated by a
    /// pattern, restricted to returning at most `n` items.
    ///
    /// If `n` substrings are returned, the last substring (the `n`th substring)
    /// will contain the remainder of the string.
    ///
    /// The [pattern] can be a `&str`, [`char`], a slice of [`char`]s, or a
    /// function or closure that determines if a character matches.
    ///
    /// [`char`]: prim@char
    /// [pattern]: self::pattern
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will not be double ended, because it is
    /// not efficient to support.
    ///
    /// If the pattern allows a reverse search, the [`rsplitn`] method can be
    /// used.
    ///
    /// [`rsplitn`]: str::rsplitn
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let v: Vec<&str> = "Mary had a little lambda".splitn(3, ' ').collect();
    /// assert_eq!(v, ["Mary", "had", "a little lambda"]);
    ///
    /// let v: Vec<&str> = "lionXXtigerXleopard".splitn(3, "X").collect();
    /// assert_eq!(v, ["lion", "", "tigerXleopard"]);
    ///
    /// let v: Vec<&str> = "abcXdef".splitn(1, 'X').collect();
    /// assert_eq!(v, ["abcXdef"]);
    ///
    /// let v: Vec<&str> = "".splitn(1, 'X').collect();
    /// assert_eq!(v, [""]);
    /// ```
    ///
    /// A more complex pattern, using a closure:
    ///
    /// ```
    /// let v: Vec<&str> = "abc1defXghi".splitn(2, |c| c == '1' || c == 'X').collect();
    /// assert_eq!(v, ["abc", "defXghi"]);
    /// ```
    #[inline]
    pub fn splitn<'a>(&self, n: usize, pat: Pattern<'a>) -> SplitN<'a> {
        todo!()
    }
}
