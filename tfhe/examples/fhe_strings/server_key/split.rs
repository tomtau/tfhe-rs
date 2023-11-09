use std::{collections::VecDeque, marker::PhantomData};

use rayon::prelude::*;

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Pattern},
    scan::scan,
};

use super::ServerKey;

pub struct RSplit<'a>(PhantomData<&'a ()>);
pub struct RSplitN<'a>(PhantomData<&'a ()>);
pub struct RSplitTerminator<'a>(PhantomData<&'a ()>);

/// The pattern length used for interpreting [`FheSplitResult`]
pub enum FhePatternLen {
    Plain(usize),
    Encrypted(FheUsize),
}

type SplitFoundPattern = VecDeque<(FheBool, FheAsciiChar)>;

/// The iterator over the results of FHE splitting a string.
/// Unlike the Rust standard library's `Split` iterator, it is not lazy over string subslices, i.e.
/// it computes eagerly and returns all collected splits.
/// The way to process it is using [`ClientKey`]'s `decrypt_split` method
/// (which produces an equivalent result to calling the Rust standard library's split and collect methods).
pub enum FheSplitResult {
    Split(FhePatternLen, SplitFoundPattern),
    SplitInclusive(SplitFoundPattern),
}

impl FheSplitResult {
    /// If the Split option should include "empty" matches, then this returns the pattern
    /// length, so that  [`ClientKey`]'s `decrypt_split` method knows how many zeroed-out characters
    /// correspond to the patterns vs the actual padded string length
    pub fn include_empty_matches(&self) -> Option<&FhePatternLen> {
        match self {
            FheSplitResult::Split(p, _) => Some(p),
            _ => None,
        }
    }
}

impl Iterator for FheSplitResult {
    type Item = (FheBool, FheAsciiChar);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            FheSplitResult::Split(_, x) => x.pop_front(),
            FheSplitResult::SplitInclusive(x) => x.pop_front(),
            _ => None,
        }
    }
}

pub struct SplitAsciiWhitespace<'a>(PhantomData<&'a ()>);
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
    pub fn split<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheSplitResult {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => {
                let zero = self.false_ct();
                let one = self.true_ct();
                let mut split_sequence = VecDeque::new();
                split_sequence.push_back((one.clone(), zero.clone()));
                split_sequence.par_extend(
                    str_ref
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x, 0), x.clone())),
                );
                split_sequence.push_back((one.clone(), zero));

                FheSplitResult::Split(FhePatternLen::Plain(0), split_sequence)
            }
            Pattern::Clear(p) if p.len() > str_ref.len() => {
                let zero = self.false_ct();
                FheSplitResult::Split(
                    FhePatternLen::Plain(p.len()),
                    str_ref
                        .par_iter()
                        .map(|x| (zero.clone(), x.clone()))
                        .collect(),
                )
            }
            Pattern::Clear(pat) => {
                let zero = self.false_ct();
                let mut split_sequence = VecDeque::new();
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_clear_par(&str_ref[i..], pat);
                    Some(self.0.scalar_mul_parallelized(&starts, pat.len() as u64))
                });
                let accumulated_starts = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &start_y,
                            );
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| {
                    x.map(|y| {
                        (
                            self.0.scalar_eq_parallelized(&y, pat.len() as u64),
                            self.0.scalar_gt_parallelized(&y, 0u64),
                        )
                    })
                })
                .collect::<Vec<_>>();
                split_sequence.par_extend(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter())
                        .map(|((starts, in_pattern), c)| {
                            (
                                starts,
                                self.0.if_then_else_parallelized(&in_pattern, &zero, c),
                            )
                        }),
                );
                FheSplitResult::Split(FhePatternLen::Plain(pat.len()), split_sequence)
            }
            Pattern::Encrypted(pat) => {
                let zero = self.false_ct();
                let (is_empty, orig_len) = rayon::join(|| self.is_empty(pat), || self.len(pat));
                let mut split_sequence = VecDeque::new();
                split_sequence.push_back((is_empty.clone(), zero.clone()));
                let pat_ref = pat.as_ref();
                let (pat_len, is_not_empty) = rayon::join(
                    || self.0.max_parallelized(&orig_len, &is_empty),
                    || self.0.bitnot_parallelized(&is_empty),
                );
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_encrypted_par(&str_ref[i..], pat_ref);
                    Some(self.0.mul_parallelized(&starts, &pat_len))
                });

                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &start_y,
                            );
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| {
                    x.map(|y| {
                        (
                            self.0.eq_parallelized(&y, &pat_len),
                            self.0.bitand_parallelized(
                                &self.0.scalar_gt_parallelized(&y, 0u64),
                                &is_not_empty,
                            ),
                        )
                    })
                })
                .collect();
                split_sequence.par_extend(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter())
                        .map(|((starts, in_pattern), c)| {
                            (
                                starts,
                                self.0.if_then_else_parallelized(&in_pattern, &zero, c),
                            )
                        }),
                );
                FheSplitResult::Split(FhePatternLen::Encrypted(orig_len), split_sequence)
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
    pub fn split_inclusive<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheSplitResult {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => {
                let zero = self.false_ct();
                let one = self.true_ct();
                let mut split_sequence = VecDeque::new();
                split_sequence.push_back((one.clone(), zero));
                split_sequence.par_extend(
                    str_ref
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x, 0), x.clone())),
                );
                FheSplitResult::SplitInclusive(split_sequence)
            }
            Pattern::Clear(p) if p.len() > str_ref.len() => {
                let zero = self.false_ct();
                FheSplitResult::SplitInclusive(
                    str_ref
                        .par_iter()
                        .map(|x| (zero.clone(), x.clone()))
                        .collect(),
                )
            }
            Pattern::Clear(pat) => {
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_clear_par(&str_ref[i..], pat);
                    Some(self.0.scalar_mul_parallelized(&starts, pat.len() as u64))
                });
                let accumulated_starts = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &start_y,
                            );
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| x.map(|y| self.0.scalar_eq_parallelized(&y, 1)))
                .collect::<Vec<_>>();
                FheSplitResult::SplitInclusive(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned())
                        .collect(),
                )
            }
            Pattern::Encrypted(pat) => {
                let zero = self.false_ct();
                let is_empty = self.is_empty(pat);
                let mut split_sequence = VecDeque::new();
                split_sequence.push_back((is_empty.clone(), zero));
                let pat_ref = pat.as_ref();
                let pat_len = self.0.max_parallelized(&self.len(pat), &is_empty);
                let pattern_starts = (0..str_len).into_par_iter().map(|i| {
                    let starts = self.starts_with_encrypted_par(&str_ref[i..], pat_ref);
                    Some(self.0.mul_parallelized(&starts, &pat_len))
                });

                let accumulated_starts: Vec<_> = scan(
                    pattern_starts,
                    |x, y| match (x, y) {
                        (Some(start_x), Some(start_y)) => {
                            let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                            let next_start = self.0.if_then_else_parallelized(
                                &in_pattern,
                                &self.0.scalar_sub_parallelized(start_x, 1),
                                &start_y,
                            );
                            Some(next_start)
                        }
                        (None, y) => y.clone(),
                        (x, None) => x.clone(),
                    },
                    None,
                )
                .filter_map(|x| x.map(|y| self.0.scalar_eq_parallelized(&y, 1)))
                .collect();
                split_sequence.par_extend(
                    accumulated_starts
                        .into_par_iter()
                        .zip(str_ref.into_par_iter().cloned()),
                );
                FheSplitResult::SplitInclusive(split_sequence)
            }
        }
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
