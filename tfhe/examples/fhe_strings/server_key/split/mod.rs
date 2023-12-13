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

use crate::ciphertext::{FheAsciiChar, FheBool, FheString, FheUsize, Number, Pattern};
use crate::scan::scan;

use super::ServerKey;

/// The pattern length used for interpreting [`FheSplitResult`]
/// When doing non-inclusive splits, the end sub-strings will be empty and with padded strings,
/// we wouldn't know how many empy substrings to include, so the pattern length is used for that.
#[derive(Clone)]
pub enum FhePatternLen {
    Plain(usize),
    Encrypted(FheUsize),
}

/// The length of the pattern and the length of the string to match the terminal.
pub type PatternLenAndEndLen = (FhePatternLen, FhePatternLen);

/// The result of splitting a string using FHE.
/// The first component is a boolean indicating whether the pattern was found or not at that
/// position. The second component is the original character (if the pattern was not found or it's
/// an inclusive split) or the zero character (if the pattern was found and it's a non-inclusive
/// split or it was a padding).
type SplitFoundPattern = VecDeque<(FheBool, FheAsciiChar)>;

/// The iterator over the results of FHE splitting a string.
/// Unlike the Rust standard library's `Split` iterator, it is not lazy over string subslices, i.e.
/// it computes eagerly and returns all collected splits.
/// `rsplit_once` in the standard library returns a tuple, while here we return a vector with two
/// elements. The way to process it is using [`ClientKey`]'s `decrypt_split` method
/// (which produces an equivalent result to calling the Rust standard library's split and collect
/// methods, plus the vector-tuple conversion in the case of `rsplit_once`).
///
/// This representation is a solution that tries to unify the different split methods in the
/// standard library, and be somewhat compatible with the FHE implementation. One small alternative
/// may be to have the "families" of the split methods separated and have different decryption
/// methods. Two more ideas were explored but discarded in the interest of practicality tradeoffs:
/// 1) Instead of decryption method composing the substrings, it was the server key method computing
///    all possible paths
/// and having the boolean flag to indicate which vector of substrings to use. This is interesting
/// that one can do more computations on the substrings, but it's not practical due to the
/// expotential blowup.
/// 2) Semi-lazy interactive decryption, where the server would just compute the matches and paths
///    up to some limit, pass back to the client
/// the intermediate results and the cached state, and the client would decide which intermediate
/// results to continue the computations from. This style would be more far off from the standard
/// library's split methods and it's unclear whether it would be useful.
#[derive(Clone)]
pub enum FheSplitResult {
    RSplit(PatternLenAndEndLen, SplitFoundPattern),
    RSplitN(Option<FheBool>, PatternLenAndEndLen, SplitFoundPattern),
    RSplitOnce(PatternLenAndEndLen, SplitFoundPattern),
    RSplitTerminator(PatternLenAndEndLen, SplitFoundPattern),
    Split(PatternLenAndEndLen, SplitFoundPattern),
    SplitAsciiWhitespace(SplitFoundPattern),
    SplitInclusive(FhePatternLen, SplitFoundPattern),
    SplitN(Option<FheBool>, PatternLenAndEndLen, SplitFoundPattern),
    SplitTerminator(PatternLenAndEndLen, SplitFoundPattern),
}

impl FheSplitResult {
    /// Indicates whether the decryption should reverse the computed substring order
    pub fn reverse_results(&self) -> bool {
        matches!(
            self,
            FheSplitResult::RSplit(_, _)
                | FheSplitResult::RSplitN(_, _, _)
                | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    /// Indicates whether the decryption should consider the empty pattern
    /// matching from the right
    pub fn is_right_match_empty(&self) -> bool {
        matches!(
            self,
            FheSplitResult::RSplit(_, _)
                | FheSplitResult::RSplitN(_, _, _)
                | FheSplitResult::RSplitOnce(_, _)
        )
    }

    /// Indicates whether the decryption should skip the last match (which would be an empty
    /// substring)
    pub fn skip_empty_terminator(&self) -> bool {
        matches!(
            self,
            FheSplitResult::SplitTerminator(_, _) | FheSplitResult::RSplitTerminator(_, _)
        )
    }

    /// Indicates a special case if the requested encrypted count was 0, which means empty vector
    /// should be returned
    pub fn zero_count(&self) -> Option<&FheBool> {
        match self {
            FheSplitResult::SplitN(z, _, _) | FheSplitResult::RSplitN(z, _, _) => z.as_ref(),
            _ => None,
        }
    }

    /// If the Split option should include "empty" matches, then this returns the pattern
    /// length, so that  [`ClientKey`]'s `decrypt_split` method knows how many zeroed-out characters
    /// correspond to the patterns vs the actual padded string length
    pub fn include_empty_matches(&self) -> Option<&PatternLenAndEndLen> {
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

    /// If the split option is inclusive, it needs to know whether the prefix before the first match
    /// is empty of if it was matched on an empty pattern.
    pub fn include_empty_prefix(&self) -> Option<&FhePatternLen> {
        match self {
            FheSplitResult::SplitInclusive(p, _) => Some(p),
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
            | FheSplitResult::SplitInclusive(_, x)
            | FheSplitResult::RSplit(_, x)
            | FheSplitResult::RSplitOnce(_, x)
            | FheSplitResult::RSplitN(_, _, x)
            | FheSplitResult::RSplitTerminator(_, x) => x.pop_front(),
        }
    }
}

impl ServerKey {
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let server_key = server_key::ServerKey::from(&client_key);
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
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[inline]
    pub fn split<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
    ) -> FheSplitResult {
        let (pat_len, pattern_splits) = self.split_inner(encrypted_str, pat, true);
        FheSplitResult::Split(pat_len, pattern_splits)
    }

    /// A helper that computes the trivial split where the clear pattern is larger than
    /// the encrypted string, i.e. it doesn't match / the original should be returned
    #[inline]
    fn larger_clear_pattern_split(&self, str_ref: &[FheAsciiChar]) -> SplitFoundPattern {
        let zero = self.false_ct();
        str_ref
            .par_iter()
            .map(|x| (zero.clone(), x.clone()))
            .collect()
    }

    /// A helper that computes the clear pattern matches on a given encrypted string
    /// See [`accumulate_clear_pat_starts`] for more details of the representation.
    ///
    /// [`accumulate_clear_pat_starts`]: ServerKey::accumulate_clear_pat_starts
    #[inline]
    fn clear_accumulated_starts<'a>(
        &'a self,
        str_len: usize,
        str_ref: &'a [FheAsciiChar],
        pat: &'a str,
        max_count: Option<&'a Number>,
    ) -> impl ParallelIterator<Item = Option<(Option<FheUsize>, FheUsize)>> + 'a {
        let pattern_starts = (0..str_len).into_par_iter().map(move |i| {
            let starts = self.starts_with_clear_par(&str_ref[i..], pat);
            let starts_radix = starts.into_radix(self.1, &self.0);
            let starts_len = self
                .0
                .scalar_mul_parallelized(&starts_radix, pat.len() as u64);
            Some((max_count.map(|_| starts_radix), starts_len))
        });
        self.accumulate_clear_pat_starts(pattern_starts, max_count)
    }

    /// A helper that computes the split of a padded encrypted pattern on a given encrypted string
    #[inline]
    fn encrypted_split(
        &self,
        str_len: usize,
        str_ref: &[FheAsciiChar],
        pat: &FheString,
        max_count: Option<Number>,
        terminator: bool,
    ) -> (FheUsize, SplitFoundPattern) {
        let pat = self.pad_string(pat); // TODO: unpadded pattern

        let zero = self.zero_ct();
        let (is_empty_pat, orig_len) = rayon::join(|| self.is_empty(&pat), || self.len(&pat));
        let is_empty_pat_radix = is_empty_pat.clone().into_radix(self.1, &self.0);
        let mut split_sequence = SplitFoundPattern::new();

        let pat_ref = pat.as_ref();
        let first_start = self.starts_with_encrypted_par(str_ref, pat_ref);
        let (pat_len, is_not_empty_pat) = rayon::join(
            || self.0.max_parallelized(&orig_len, &is_empty_pat_radix),
            || self.0.scalar_ne_parallelized(pat_ref[0].as_ref(), 0),
        );
        let pattern_starts = (0..str_len).into_par_iter().map(|i| {
            let (starts, ended) = rayon::join(
                || {
                    if i == 0 {
                        first_start.clone()
                    } else {
                        self.starts_with_encrypted_par(&str_ref[i..], pat_ref)
                    }
                },
                || {
                    self.0
                        .scalar_eq_parallelized(str_ref[i].as_ref(), 0)
                        .into_radix(self.1, &self.0)
                },
            );
            let starts_radix = starts.into_radix(self.1, &self.0);
            let starts_len = self.0.mul_parallelized(&starts_radix, &pat_len);
            Some((max_count.as_ref().map(|_| starts_radix), starts_len, ended))
        });

        let accumulated_starts = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x, ended_x)), Some((count_y, start_y, ended_y))) => self
                    .encrypted_pat_split_start_padded(
                        &max_count,
                        (count_x, start_x, ended_x),
                        (count_y, start_y, ended_y),
                    ),
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .filter_map(|x| {
            x.map(|(count, starts, ended)| {
                self.accumulate_enc_starts_split_padded(
                    &pat_len,
                    &is_not_empty_pat,
                    &max_count,
                    count,
                    &starts,
                    &ended,
                )
            })
        })
        .collect();
        split_sequence.par_extend(self.split_compute(accumulated_starts, str_ref, &zero));
        if terminator {
            let initial_ends = [
                self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64),
                str_ref
                    .get(1)
                    .map(|x| self.0.scalar_eq_parallelized(x.as_ref(), 0u64))
                    .unwrap_or_else(|| self.true_ct()),
            ];
            let less_one_l = self.0.boolean_bitor(&initial_ends[0], &initial_ends[1]);
            split_sequence.push_back((self.false_ct(), self.zero_ct().into()));
            split_sequence.push_back((
                self.0.boolean_bitand(&less_one_l, &is_empty_pat),
                self.zero_ct().into(),
            ));
        }
        (orig_len, split_sequence)
    }

    /// A helper that returns a tuple -- the first component is if the character is at the beginning
    /// of the pattern (provided the end of the padded string wasn't reached), the second component
    /// indicates if the character is inside a (non-empty) pattern
    #[inline]
    fn accumulate_enc_starts_split_padded(
        &self,
        pat_len: &FheUsize,
        is_not_empty_pat: &FheBool,
        max_count: &Option<Number>,
        count: Option<FheUsize>,
        starts: &FheUsize,
        ended: &FheUsize,
    ) -> (FheBool, FheBool) {
        let count_not_reached = match (&max_count, count.as_ref()) {
            (Some(Number::Encrypted(mc)), Some(c)) => Some(self.0.lt_parallelized(c, mc)),
            (Some(Number::Clear(mc)), Some(c)) => {
                Some(self.0.scalar_lt_parallelized(c, *mc as u64))
            }

            _ => None,
        };
        let ((pattern_starts, not_ended), in_pattern) = rayon::join(
            || {
                rayon::join(
                    || {
                        let pattern_starts = self.0.eq_parallelized(starts, pat_len);
                        if let Some(ref cnr) = count_not_reached {
                            self.0.boolean_bitand(cnr, &pattern_starts)
                        } else {
                            pattern_starts
                        }
                    },
                    || self.0.scalar_le_parallelized(ended, 1),
                )
            },
            || {
                let in_pattern = self.0.scalar_gt_parallelized(starts, 0u64);
                if let Some(ref cnr) = count_not_reached {
                    self.0.boolean_bitand(cnr, &in_pattern)
                } else {
                    in_pattern
                }
            },
        );
        (
            self.0.boolean_bitand(&pattern_starts, &not_ended),
            self.0.boolean_bitand(&in_pattern, is_not_empty_pat),
        )
    }

    /// A helper that processes the accumulated starts for computing the split
    /// the first component is the number of pattern matches (if max_count is set),
    /// the second is the number between the pattern length/1 and 0
    /// the third one counts the zeroes, i.e. it's greater than 0 if the end of the string was
    /// reached
    #[inline]
    fn encrypted_pat_split_start_padded(
        &self,
        max_count: &Option<Number>,
        (count_x, start_x, ended_x): (&Option<FheUsize>, &FheUsize, &FheUsize),
        (count_y, start_y, ended_y): (&Option<FheUsize>, &FheUsize, &FheUsize),
    ) -> Option<(Option<FheUsize>, FheUsize, FheUsize)> {
        let count_xy = self.add(count_x.as_ref(), count_y.as_ref());
        let ended = self.0.add_parallelized(ended_x, ended_y);
        let not_ended = self.0.scalar_le_parallelized(&ended, 1u64);
        let count_correct =
            if let (Some(count_xy), Some(count_x)) = (count_xy.as_ref(), count_x.as_ref()) {
                Some(
                    self.0
                        .if_then_else_parallelized(&not_ended, count_xy, count_x),
                )
            } else {
                None
            };
        let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
        let next_pattern = self.0.scalar_gt_parallelized(start_y, 0);

        let mut start_y_not_ended = self.0.boolean_bitand(&next_pattern, &not_ended);
        let next_count = if let (Some(adjusted_max_count), Some(count_x), Some(count_correct)) =
            (max_count, count_x, count_correct)
        {
            let ncount = self
                .0
                .if_then_else_parallelized(&in_pattern, count_x, &count_correct);
            let (min_next_count, not_reached_max_count) = match adjusted_max_count {
                Number::Encrypted(mc) => rayon::join(
                    || self.0.min_parallelized(&ncount, mc),
                    || self.0.le_parallelized(&ncount, mc),
                ),
                Number::Clear(mc) => rayon::join(
                    || self.0.scalar_min_parallelized(&ncount, *mc as u64),
                    || self.0.scalar_le_parallelized(&ncount, *mc as u64),
                ),
            };
            self.0
                .boolean_bitand_assign(&mut start_y_not_ended, &not_reached_max_count);
            Some(min_next_count)
        } else {
            None
        };

        let next_start_y =
            self.0
                .if_then_else_parallelized(&start_y_not_ended, start_y, &self.zero_ct());
        let next_start = self.0.if_then_else_parallelized(
            &in_pattern,
            &self.0.scalar_sub_parallelized(start_x, 1),
            &next_start_y,
        );
        Some((next_count, next_start, ended))
    }

    /// A helper that processes the accumulated starts for computing the non-inclusive split
    #[inline]
    fn split_compute<'a>(
        &'a self,
        accumulated_starts: Vec<(FheBool, FheBool)>,
        str_ref: &'a [FheAsciiChar],
        zero: &'a FheUsize,
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

    /// A helper that returns the split pattern length and the split sequence
    #[inline]
    fn split_inner<'a, P: Into<Pattern<'a>>>(
        &self,
        encrypted_str: &FheString,
        pat: P,
        include_terminal: bool,
    ) -> (PatternLenAndEndLen, SplitFoundPattern) {
        match encrypted_str {
            FheString::Padded(_) => {
                let str_real_len = self.len(encrypted_str);
                let str_ref = encrypted_str.as_ref();
                let str_len = str_ref.len();
                match pat.into() {
                    Pattern::Clear(p) if p.is_empty() => {
                        // TODO: more efficient way
                        let empty_pat =
                            FheString::new_unchecked_padded(vec![self.zero_ct().into()]);
                        self.split_inner(
                            encrypted_str,
                            Pattern::Encrypted(&empty_pat),
                            include_terminal,
                        )
                    }
                    Pattern::Clear(p) if p.len() > str_ref.len() => (
                        (
                            FhePatternLen::Plain(p.len()),
                            FhePatternLen::Encrypted(str_real_len),
                        ),
                        self.larger_clear_pattern_split(str_ref),
                    ),
                    Pattern::Clear(pat) => {
                        let zero = self.zero_ct();
                        let mut split_sequence = VecDeque::new();
                        let mut accumulated_starts = self
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
                        let empty_str_ref =
                            self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64);
                        accumulated_starts[0] = (
                            self.0
                                .boolean_bitor(&accumulated_starts[0].0, &empty_str_ref),
                            accumulated_starts[0].1.clone(),
                        );
                        split_sequence.par_extend(self.split_compute(
                            accumulated_starts,
                            str_ref,
                            &zero,
                        ));
                        (
                            (
                                FhePatternLen::Plain(pat.len()),
                                FhePatternLen::Encrypted(str_real_len),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(pat) => {
                        let (orig_len, split_sequence) =
                            self.encrypted_split(str_len, str_ref, pat, None, include_terminal);
                        (
                            (
                                FhePatternLen::Encrypted(orig_len),
                                FhePatternLen::Encrypted(str_real_len),
                            ),
                            split_sequence,
                        )
                    }
                }
            }
            FheString::Unpadded(_) => {
                let str_ref = encrypted_str.as_ref();
                let one = self.true_ct();

                let zero = self.zero_ct();
                match pat.into() {
                    Pattern::Clear(p) if str_ref.is_empty() && p.is_empty() => {
                        let mut split_sequence = VecDeque::new();
                        split_sequence.push_back((one.clone(), zero.clone().into()));
                        if include_terminal {
                            split_sequence.push_back((one.clone(), zero.clone().into()));
                        }
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(p) if str_ref.is_empty() && p.as_ref().is_empty() => {
                        let mut split_sequence = VecDeque::new();
                        split_sequence.push_back((one.clone(), zero.clone().into()));
                        if include_terminal {
                            split_sequence.push_back((one.clone(), zero.clone().into()));
                        }
                        (
                            (
                                FhePatternLen::Plain(p.as_ref().len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Clear(p) if p.len() > str_ref.len() => {
                        let split_sequence = self.larger_clear_pattern_split(str_ref);
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Encrypted(FheString::Unpadded(p)) if p.len() > str_ref.len() => {
                        let split_sequence = self.larger_clear_pattern_split(str_ref);
                        (
                            (
                                FhePatternLen::Plain(p.len()),
                                FhePatternLen::Plain(str_ref.len()),
                            ),
                            split_sequence,
                        )
                    }
                    Pattern::Clear(p) => self.split_inner(
                        &self.pad_string(encrypted_str),
                        Pattern::Clear(p),
                        include_terminal,
                    ),
                    Pattern::Encrypted(p) => self.split_inner(
                        &self.pad_string(encrypted_str),
                        &self.pad_string(p),
                        include_terminal,
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn split_padded_test((input, split_pattern): (&str, &str), padding_len: usize) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len)
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
    ("1111111", "11"),
    ("123123123", "123"),
    ("12121212121", "1212"),
    ("banana", "ana"),
    ("foo:bar", "foo:"),
    ("foo:bar", "bar"),],
    1..=3
    )]
    fn test_split_padded((input, split_pattern): (&str, &str), padding_len: usize) {
        split_padded_test((input, split_pattern), padding_len)
    }

    #[test_matrix(
    1..=3
    )]
    fn test_split_padded_empty(padding_len: usize) {
        split_padded_test(("", ""), padding_len)
    }

    #[test_matrix(
        [("", "a"),
        ("", "")]
    )]
    fn test_split_unpadded((input, split_pattern): (&str, &str)) {
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

        let encrypted_str = client_key.encrypt_str(input).unwrap();
        let encrypted_split_pattern = client_key.encrypt_str(split_pattern).unwrap();
        println!("clear: {input} {split_pattern}");
        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern}");

        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, &encrypted_split_pattern))
        );
    }
}
