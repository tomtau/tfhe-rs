use std::marker::PhantomData;

use rayon::prelude::{
    IntoParallelIterator, IntoParallelRefIterator, ParallelExtend, ParallelIterator,
};

use crate::ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, Pattern};

use super::ServerKey;

pub struct RSplit<'a>(PhantomData<&'a ()>);
pub struct RSplitN<'a>(PhantomData<&'a ()>);
pub struct RSplitTerminator<'a>(PhantomData<&'a ()>);

/// One of possible results of FHE splitting a string.
/// It has two encrypted components:
/// 1. `valid_split` which indicates whether the split is valid:
/// - None: valid, but the pattern was not found in the string
/// - Some(encrypted false/0): invalid, we skip processing/decrypting the rest of this result
/// - Some(encrypted true/1): valid
///
/// In `FheSplit`, the rightmost / the first valid returned string is the result of the split.
/// 2. `split_sequence` which is a sequence of encrypted strings. We decrypt if valid_split` is valid.
/// Each element of the sequence is either:
/// - encrypted None/0: we skip it (it's to account for splitting at 0-padded positions which don't occur in normal Rust std splits)
/// - encrypted Some: we decrypt it and include it
#[derive(Clone)]
pub struct FheSplitItem {
    /// None == pattern not found / no split done
    pub valid_split: Option<FheBool>,
    /// result of the split: encrypted Some if a valid string,
    /// encrypted None if not a valid string that shouldn't be included in results
    pub split_sequence: Vec<FheOption<FheString>>,
}

/// The iterator over the possible results of FHE splitting a string.
/// Unlike the Rust standard library's `Split` iterator, it is not lazy over string subslices, i.e.
/// it computes eagerly and returns all collected possible splits.
/// The way to process it is using [`ClientKey`]'s `decrypt_split` method, which will take the first/rightmost
/// valid [`FheSplitItem`] and decrypt it into a vector of strings
/// (which produces an equivalent result to calling the Rust standard library's split and collect methods).
pub struct FheSplit(Vec<FheSplitItem>);

impl Iterator for FheSplit {
    type Item = FheSplitItem;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop()
    }
}

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

    #[inline]
    fn empty_pattern_split_item(&self, valid: FheBool, str_ref: &[FheAsciiChar]) -> FheSplitItem {
        let zero = self.false_ct();
        let empty = FheString::new_unchecked(vec![zero.clone()]);

        let mut split_sequence = Vec::with_capacity(str_ref.len());
        let separator = (self.true_ct(), empty);
        split_sequence.push(separator.clone());
        split_sequence.par_extend(str_ref[..str_ref.len() - 1].par_iter().map(|c| {
            (
                self.0.scalar_ne_parallelized(c, 0),
                FheString::new_unchecked(vec![c.clone(), zero.clone()]),
            )
        }));
        split_sequence.push(separator);
        let split_item = FheSplitItem {
            valid_split: Some(valid),
            split_sequence,
        };
        split_item
    }

    /// An iterator over possible results of encrypted substrings of `encrypted_str`,
    /// separated by characters matched by a pattern.
    ///
    /// The pattern can be a clear `&str` or an encrypted &FheString.
    ///
    /// # Iterator behavior
    ///
    /// The returned iterator will be a [`Split`] and the first returned valid
    /// element is the result of the split operation.
    ///
    /// # Examples
    ///
    /// Simple patterns:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("Mary had a lamb").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   ["Mary", "had", "a", "lamb"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "X")),
    ///   [""]
    /// );
    /// let x = client_key.encrypt_str("X").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, &x)),
    ///   [""]
    /// );
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleo").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "X")),
    ///   ["lion", "", "tiger", "leo"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leo").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "::")),
    ///   ["lion", "tiger", "leo"]
    /// );
    /// ```
    ///
    /// If a string contains multiple contiguous separators, you will end up
    /// with empty strings in the output:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("||||a||b|c").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "|")),
    ///   ["", "", "", "", "a", "", "b", "c"]
    /// );
    /// ```
    ///
    /// Contiguous separators are separated by the empty string.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("(///)").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "/")),
    ///   ["(", "", "", ")"]
    /// );
    /// ```
    ///
    /// Separators at the start or end of a string are neighbored
    /// by empty strings.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("010").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "0")),
    ///   ["", "1", ""]
    /// );
    /// ```
    ///
    /// When the empty string is used as a separator, it separates
    /// every character in the string, along with the beginning
    /// and end of the string.
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("rust").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, "")),
    ///   ["", "r", "u", "s", "t", ""]
    /// );
    /// ```
    ///
    /// Contiguous separators can lead to possibly surprising behavior
    /// when whitespace is used as the separator. This code is correct:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("    a  b c").unwrap();
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   ["", "", "", "", "a", "", "b", "c"]
    /// );
    /// ```
    ///
    /// It does _not_ give you:
    ///
    /// ```,ignore
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   ["a", "b", "c"]
    /// );
    /// ```
    ///
    /// Use [`split_whitespace`] for this behavior.
    ///
    /// [`split_whitespace`]: ServerKey::split_whitespace
    #[inline]
    pub fn split<'a, P: Into<Pattern<'a>>>(&self, encrypted_str: &FheString, pat: P) -> FheSplit {
        let str_ref = encrypted_str.as_ref();
        let zero = self.false_ct();
        let empty = FheString::new_unchecked(vec![zero.clone()]);

        match pat.into() {
            Pattern::Clear(pat) if pat.is_empty() => {
                FheSplit(vec![self.empty_pattern_split_item(self.true_ct(), str_ref)])
            }
            Pattern::Clear(pat) => {
                let str_len = str_ref.len();
                let pat_len = pat.len();
                let mut possible_splits: Vec<(usize, FheSplitItem)> = vec![(
                    0,
                    FheSplitItem {
                        valid_split: None,
                        split_sequence: vec![],
                    },
                )];
                let (found_patterns, empty_split): (Vec<_>, FheSplitItem) = rayon::join(
                    || {
                        (0..str_len - 1)
                            .into_par_iter()
                            .map(|i| self.starts_with_clear_par(&str_ref[i..], pat))
                            .collect()
                    },
                    || {
                        let empty_str = self.is_empty(&encrypted_str);
                        FheSplitItem {
                            valid_split: Some(empty_str.clone()),
                            split_sequence: vec![(empty_str, empty)],
                        }
                    },
                );
                let mut i = 0;
                while i < str_len - 1 {
                    let n = possible_splits.len();
                    let new_items: Vec<_> = (0..n)
                        .into_par_iter()
                        .filter_map(|j| {
                            let start = possible_splits[j].0;
                            if start <= i {
                                let mut new_sub_result = (start, possible_splits[j].1.clone());
                                let pattern_found = &found_patterns[i];
                                let mut str_v = str_ref[start..i].to_vec();
                                str_v.push(zero.clone());
                                new_sub_result.1.valid_split = self.and_true(
                                    new_sub_result.1.valid_split.as_ref(),
                                    Some(&pattern_found),
                                );
                                new_sub_result
                                    .1
                                    .split_sequence
                                    .push((pattern_found.clone(), FheString::new_unchecked(str_v)));
                                new_sub_result.0 = i + pat_len;

                                Some(new_sub_result)
                            } else {
                                None
                            }
                        })
                        .collect();
                    possible_splits.par_extend(new_items);
                    i += 1;
                }
                FheSplit(
                    possible_splits
                        .into_par_iter()
                        .map(|mut sub_result| {
                            let start = sub_result.0;
                            if start < str_len {
                                let mut str_v = str_ref[start..].to_vec();
                                str_v.push(zero.clone());
                                let zero_str = self.or(
                                    Some(&self.0.scalar_ne_parallelized(&str_ref[start], 0)),
                                    sub_result.1.split_sequence.last().map(|x| &x.0),
                                );
                                sub_result.1.split_sequence.push((
                                    zero_str.expect("zero comparison"),
                                    FheString::new_unchecked(str_v),
                                ));
                            }
                            sub_result.1
                        })
                        .chain(rayon::iter::once(empty_split))
                        .collect(),
                )
            }
            Pattern::Encrypted(pat) => {
                let str_len = str_ref.len();
                let pat_ref = pat.as_ref();
                let mut possible_splits: Vec<(usize, FheSplitItem)> = vec![(
                    0,
                    FheSplitItem {
                        valid_split: None,
                        split_sequence: vec![],
                    },
                )];
                let ((found_patterns, empty_split), empty_pattern_split) = rayon::join(
                    || {
                        rayon::join(
                            || {
                                (0..str_len - 1)
                                    .into_par_iter()
                                    .map(|i| self.starts_with_encrypted_par(&str_ref[i..], pat_ref))
                                    .collect::<Vec<_>>()
                            },
                            || {
                                let empty_str = self.is_empty(&encrypted_str);
                                FheSplitItem {
                                    valid_split: Some(empty_str.clone()),
                                    split_sequence: vec![(empty_str, empty)],
                                }
                            },
                        )
                    },
                    || self.empty_pattern_split_item(self.is_empty(pat), str_ref),
                );
                let mut i = 0;
                while i < str_len - 1 {
                    let n = possible_splits.len();
                    let new_items: Vec<_> = (0..n)
                        .into_par_iter()
                        .filter_map(|j| {
                            let start = possible_splits[j].0;
                            if start <= i {
                                let mut new_sub_result = (start, possible_splits[j].1.clone());
                                let pattern_found = &found_patterns[i];
                                let mut str_v = str_ref[start..i].to_vec();
                                str_v.push(zero.clone());
                                new_sub_result.1.valid_split = self.and_true(
                                    new_sub_result.1.valid_split.as_ref(),
                                    Some(&pattern_found),
                                );
                                new_sub_result
                                    .1
                                    .split_sequence
                                    .push((pattern_found.clone(), FheString::new_unchecked(str_v)));
                                new_sub_result.0 = i + 1;

                                Some(new_sub_result)
                            } else {
                                None
                            }
                        })
                        .collect();
                    possible_splits.par_extend(new_items);
                    i += 1;
                }
                FheSplit(
                    possible_splits
                        .into_par_iter()
                        .map(|mut sub_result| {
                            let start = sub_result.0;
                            if start < str_len {
                                let mut str_v = str_ref[start..].to_vec();
                                str_v.push(zero.clone());
                                let zero_str = self.or(
                                    Some(&self.0.scalar_ne_parallelized(&str_ref[start], 0)),
                                    sub_result.1.split_sequence.last().map(|x| &x.0),
                                );
                                sub_result.1.split_sequence.push((
                                    zero_str.expect("zero comparison"),
                                    FheString::new_unchecked(str_v),
                                ));
                            }
                            sub_result.1
                        })
                        .chain(rayon::iter::once(empty_split))
                        .chain(rayon::iter::once(empty_pattern_split))
                        .collect(),
                )
            }
        }
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
