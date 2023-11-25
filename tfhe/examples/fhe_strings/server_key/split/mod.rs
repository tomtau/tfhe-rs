mod rsplit;
mod rsplit_once;
mod rsplit_terminator;
mod rsplitn;
mod split_ascii_whitespace;
mod split_inclusive;
mod split_terminator;
mod splitn;

use std::collections::VecDeque;

use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number, Padded, Pattern};
use crate::scan::scan;

use super::ServerKey;

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
/// (which produces an equivalent result to calling the Rust standard library's split and collect
/// methods).
pub enum FheSplitResult {
    RSplit(FhePatternLen, SplitFoundPattern),
    RSplitN(Option<FheBool>, FhePatternLen, SplitFoundPattern),
    RSplitOnce(FhePatternLen, SplitFoundPattern),
    RSplitTerminator(FhePatternLen, SplitFoundPattern),
    Split(FhePatternLen, SplitFoundPattern),
    SplitAsciiWhitespace(SplitFoundPattern),
    SplitInclusive(SplitFoundPattern),
    SplitN(Option<FheBool>, FhePatternLen, SplitFoundPattern),
    SplitTerminator(FhePatternLen, SplitFoundPattern),
}

impl FheSplitResult {
    pub fn reverse_results(&self) -> bool {
        matches!(
            self,
            FheSplitResult::RSplit(_, _)
                | FheSplitResult::RSplitN(_, _, _)
                | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    pub fn skip_empty_terminator(&self) -> bool {
        matches!(
            self,
            FheSplitResult::SplitTerminator(_, _) | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    pub fn zero_count(&self) -> Option<&FheBool> {
        match self {
            FheSplitResult::SplitN(z, _, _) | FheSplitResult::RSplitN(z, _, _) => z.as_ref(),
            _ => None,
        }
    }

    /// If the Split option should include "empty" matches, then this returns the pattern
    /// length, so that  [`ClientKey`]'s `decrypt_split` method knows how many zeroed-out characters
    /// correspond to the patterns vs the actual padded string length
    pub fn include_empty_matches(&self) -> Option<&FhePatternLen> {
        match self {
            FheSplitResult::Split(p, _)
            | FheSplitResult::SplitN(_, p, _)
            | FheSplitResult::RSplit(p, _)
            | FheSplitResult::RSplitN(_, p, _)
            | FheSplitResult::RSplitOnce(p, _)
            | FheSplitResult::RSplitTerminator(p, _)
            | FheSplitResult::SplitTerminator(p, _) => Some(p),
            _ => None,
        }
    }
}

impl Iterator for FheSplitResult {
    type Item = (FheBool, FheAsciiChar);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            FheSplitResult::Split(_, x)
            | FheSplitResult::SplitN(_, _, x)
            | FheSplitResult::SplitAsciiWhitespace(x)
            | FheSplitResult::SplitTerminator(_, x)
            | FheSplitResult::SplitInclusive(x)
            | FheSplitResult::RSplit(_, x)
            | FheSplitResult::RSplitOnce(_, x)
            | FheSplitResult::RSplitN(_, _, x)
            | FheSplitResult::RSplitTerminator(_, x) => x.pop_front(),
        }
    }
}

impl ServerKey {
    #[inline]
    fn empty_clear_pattern_split(
        &self,
        str_ref: &[FheAsciiChar],
        terminator: bool,
        max_count: Option<usize>,
    ) -> SplitFoundPattern {
        let zero = self.false_ct();
        let one = self.true_ct();
        let mut split_sequence = SplitFoundPattern::new();

        let mut count = 1;
        match max_count {
            Some(0) => return split_sequence,
            Some(1) => {
                split_sequence.push_back((
                    self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64),
                    zero.clone().into(),
                ));

                split_sequence.par_extend(str_ref.par_iter().map(|x| (zero.clone(), x.clone())));
                return split_sequence;
            }
            Some(c) => {
                let len = std::cmp::min(str_ref.len(), c - 2);
                split_sequence.push_back((one.clone(), zero.clone().into()));
                split_sequence.push_back((
                    self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64),
                    zero.clone().into(),
                ));

                split_sequence.par_extend(
                    str_ref[..len]
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x.as_ref(), 0), x.clone())),
                );
                count += len;
                if len < str_ref.len() {
                    split_sequence
                        .par_extend(str_ref[len..].par_iter().map(|x| (zero.clone(), x.clone())));
                }
            }
            _ => {
                split_sequence.push_back((one.clone(), zero.clone().into()));
                split_sequence.par_extend(
                    str_ref
                        .par_iter()
                        .map(|x| (self.0.scalar_ne_parallelized(x.as_ref(), 0), x.clone())),
                );
            }
        }
        if terminator && (max_count.is_none() || matches!(max_count, Some(c) if c < count)) {
            split_sequence.push_back((one, zero.into()));
        }
        split_sequence
    }

    #[inline]
    fn larger_clear_pattern_split(&self, str_ref: &[FheAsciiChar]) -> SplitFoundPattern {
        let zero = self.false_ct();
        str_ref
            .par_iter()
            .map(|x| (zero.clone(), x.clone()))
            .collect()
    }

    #[inline]
    fn clear_accumulated_starts<'a>(
        &'a self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &str,
        max_count: Option<&Number>,
    ) -> impl ParallelIterator<Item = Option<(Option<FheUsize>, FheUsize)>> + 'a {
        let pattern_starts = (0..str_len).into_par_iter().map(|i| {
            let starts = self.starts_with_clear_par(&str_ref[i..], pat);
            let starts_len = self.0.scalar_mul_parallelized(&starts, pat.len() as u64);
            Some((max_count.as_ref().map(|_| starts), starts_len))
        });
        scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x)), Some((count_y, start_y))) => {
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        start_y,
                    );
                    Some((self.add(count_x.as_ref(), count_y.as_ref()), next_start))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
    }

    #[inline]
    fn encrypted_split(
        &self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &FheString<Padded>,
        max_count: Option<Number>,
    ) -> (FheUsize, SplitFoundPattern) {
        let zero = self.false_ct();
        let (is_empty_pat, orig_len) = rayon::join(|| self.is_empty(pat), || self.len(pat));
        let empty_str_ref = self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64);

        let mut split_sequence = SplitFoundPattern::new();
        match &max_count {
            Some(Number::Clear(1)) => {
                split_sequence.push_back((empty_str_ref.clone(), zero.clone().into()));
            }
            Some(Number::Encrypted(mc)) => {
                let not_count_one = self.0.scalar_ne_parallelized(mc, 1u64);
                let and_empty_pat = self.0.bitand_parallelized(&is_empty_pat, &not_count_one);
                let or_empty_str_ref = self.0.bitor_parallelized(&and_empty_pat, &empty_str_ref);

                let and_empty_str_ref = self.0.bitand_parallelized(&and_empty_pat, &empty_str_ref);

                split_sequence.push_back((or_empty_str_ref, zero.clone().into()));
                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
            None => {
                split_sequence.push_back((is_empty_pat.clone(), zero.clone().into()));
            }
            _ => {
                let and_empty_str_ref = self.0.bitand_parallelized(&is_empty_pat, &empty_str_ref);
                split_sequence.push_back((is_empty_pat.clone(), zero.clone().into()));
                split_sequence.push_back((and_empty_str_ref, zero.clone().into()));
            }
        }

        let pat_ref = pat.as_ref();
        let (pat_len, is_not_empty_pat) = rayon::join(
            || self.0.max_parallelized(&orig_len, &is_empty_pat),
            || self.0.scalar_ne_parallelized(pat_ref[0].as_ref(), 0),
        );
        let pattern_starts = (0..str_len).into_par_iter().map(|i| {
            let (starts, ended) = rayon::join(
                || self.starts_with_encrypted_par(&str_ref[i..], pat_ref),
                || self.0.scalar_eq_parallelized(str_ref[i].as_ref(), 0),
            );
            let starts_len = self.0.mul_parallelized(&starts, &pat_len);
            Some((max_count.as_ref().map(|_| starts), starts_len, ended))
        });

        let adjust_max_count = match &max_count {
            Some(Number::Clear(mc)) => {
                let normal_count = self.0.create_trivial_radix(*mc as u64, self.1);
                let final_count = self.0.sub_parallelized(&normal_count, &is_empty_pat);

                Some(
                    self.0
                        .if_then_else_parallelized(&empty_str_ref, &zero, &final_count),
                )
            }
            Some(Number::Encrypted(mc)) => {
                let final_count = self.0.sub_parallelized(mc, &is_empty_pat);
                Some(
                    self.0
                        .if_then_else_parallelized(&empty_str_ref, &zero, &final_count),
                )
            }
            _ => None,
        };

        let accumulated_starts = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x, ended_x)), Some((count_y, start_y, ended_y))) => {
                    let (in_pattern, (ended, count)) = rayon::join(
                        || self.0.scalar_gt_parallelized(start_x, 1),
                        || {
                            (
                                self.0.add_parallelized(ended_x, ended_y),
                                self.add(count_x.as_ref(), count_y.as_ref()),
                            )
                        },
                    );
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        start_y,
                    );
                    Some((count, next_start, ended))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .filter_map(|x| {
            x.map(|(count, starts, ended)| {
                let count_not_reached = match (&adjust_max_count, count.as_ref()) {
                    (Some(mc), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
                    _ => None,
                };
                let ((pattern_starts, not_ended), in_pattern) = rayon::join(
                    || {
                        rayon::join(
                            || {
                                let pattern_starts = self.0.eq_parallelized(&starts, &pat_len);
                                if let Some(ref cnr) = count_not_reached {
                                    self.0.bitand_parallelized(cnr, &pattern_starts)
                                } else {
                                    pattern_starts
                                }
                            },
                            || self.0.scalar_le_parallelized(&ended, 1),
                        )
                    },
                    || {
                        let in_pattern = self.0.scalar_gt_parallelized(&starts, 0u64);
                        if let Some(ref cnr) = count_not_reached {
                            self.0.bitand_parallelized(cnr, &in_pattern)
                        } else {
                            in_pattern
                        }
                    },
                );
                (
                    self.0.bitand_parallelized(&pattern_starts, &not_ended),
                    self.0.bitand_parallelized(&in_pattern, &is_not_empty_pat),
                )
            })
        })
        .collect();
        split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
        (orig_len, split_sequence)
    }

    #[inline]
    fn split_compute<'a>(
        &'a self,
        accumulated_starts: Vec<(FheBool, FheBool)>,
        str_ref: &'a [FheAsciiChar],
        zero: &'a RadixCiphertext,
    ) -> impl ParallelIterator<Item = (FheBool, FheAsciiChar)> + 'a {
        accumulated_starts
            .into_par_iter()
            .zip(str_ref.into_par_iter())
            .map(|((starts, in_pattern), c)| {
                (
                    starts,
                    self.0
                        .if_then_else_parallelized(&in_pattern, zero, c.as_ref())
                        .into(),
                )
            })
    }

    #[inline]
    fn split_inner<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> (FhePatternLen, SplitFoundPattern) {
        let str_ref = encrypted_str.as_ref();
        let str_len = str_ref.len();
        match pat.into() {
            Pattern::Clear(p) if p.is_empty() => (
                FhePatternLen::Plain(0),
                self.empty_clear_pattern_split(str_ref, true, None),
            ),
            Pattern::Clear(p) if p.len() > str_ref.len() => (
                FhePatternLen::Plain(p.len()),
                self.larger_clear_pattern_split(str_ref),
            ),
            Pattern::Clear(pat) => {
                let zero = self.false_ct();
                let mut split_sequence = VecDeque::new();
                let accumulated_starts = self
                    .clear_accumulated_starts(str_len, str_ref, pat, None)
                    .filter_map(|x| {
                        x.map(|(_, y)| {
                            (
                                self.0.scalar_eq_parallelized(&y, pat.len() as u64),
                                self.0.scalar_gt_parallelized(&y, 0u64),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
                (FhePatternLen::Plain(pat.len()), split_sequence)
            }
            Pattern::Encrypted(pat) => {
                let (orig_len, split_sequence) = self.encrypted_split(str_len, str_ref, pat, None);
                (FhePatternLen::Encrypted(orig_len), split_sequence)
            }
        }
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
    ///     client_key.decrypt_split(server_key.split(s, " ")),
    ///     vec!["Mary", "had", "a", "lamb"]
    /// );
    ///
    /// let s = client_key.encrypt_str("").unwrap();
    /// assert_eq!(client_key.decrypt_split(server_key.split(s, "X")), vec![""]);
    /// let x = client_key.encrypt_str("X").unwrap();
    /// assert_eq!(client_key.decrypt_split(server_key.split(s, &x)), vec![""]);
    ///
    /// let s = client_key.encrypt_str("lionXXtigerXleo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split(s, "X")),
    ///     vec!["lion", "", "tiger", "leo"]
    /// );
    ///
    /// let s = client_key.encrypt_str("lion::tiger::leo").unwrap();
    /// assert_eq!(
    ///     client_key.decrypt_split(server_key.split(s, "::")),
    ///     vec!["lion", "tiger", "leo"]
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
    ///     client_key.decrypt_split(server_key.split(s, "|")),
    ///     vec!["", "", "", "", "a", "", "b", "c"]
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
    ///     client_key.decrypt_split(server_key.split(s, "/")),
    ///     vec!["(", "", "", ")"]
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
    ///     client_key.decrypt_split(server_key.split(s, "0")),
    ///     vec!["", "1", ""]
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
    ///     client_key.decrypt_split(server_key.split(s, "")),
    ///     vec!["", "r", "u", "s", "t", ""]
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
    ///     client_key.decrypt_split(server_key.split(s, " ")),
    ///     vec!["", "", "", "", "a", "", "b", "c"]
    /// );
    /// ```
    ///
    /// It does _not_ give you:
    ///
    /// ```,ignore
    /// assert_eq!(
    ///   client_key.decrypt_split(server_key.split(s, " ")),
    ///   vec!["a", "b", "c"]
    /// );
    /// ```
    ///
    /// Use [`split_ascii_whitespace`] for this behavior.
    ///
    /// [`split_ascii_whitespace`]: ServerKey::split_ascii_whitespace
    #[inline]
    pub fn split<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.split_inner(encrypted_str, pat);
        FheSplitResult::Split(pat_len, pattern_splits)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn split_test((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
            .unwrap();
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, &encrypted_split_pattern))
        );
    }

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
    ("foo:bar", "bar"),],
    1..=3
    )]
    fn test_split((input, split_pattern): (&str, &str), padding_len: usize) {
        split_test((input, split_pattern), padding_len)
    }

    #[test_matrix(
    1..=3
    )]
    fn test_split_empty(padding_len: usize) {
        split_test(("", ""), padding_len)
    }
}
