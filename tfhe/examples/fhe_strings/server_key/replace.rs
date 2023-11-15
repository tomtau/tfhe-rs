use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::{
    ciphertext::{FheAsciiChar, FheString, Number, Padded, Pattern},
    scan::scan,
};

use super::ServerKey;

impl ServerKey {
    #[inline]
    fn replace_empty_from_pat_clear(
        &self,
        str_ref: &[FheAsciiChar],
        to_pat: &str,
        max_count: Option<usize>,
    ) -> FheString<Padded> {
        let to_pat_enc = to_pat.as_bytes().par_iter().map(|x| {
            self.0
                .create_trivial_radix::<u64, RadixCiphertext>(*x as u64, self.1)
                .into()
        });
        let mut result = Vec::with_capacity(str_ref.len() * to_pat.len());
        result.par_extend(to_pat_enc.clone());
        let mut count = 1;
        // TODO: zero-out after the string end
        for c in str_ref[..str_ref.len() - 1].iter() {
            result.push(c.clone());
            match max_count {
                Some(c) if count < c => {
                    result.par_extend(to_pat_enc.clone());
                    count += 1
                }
                None => {
                    result.par_extend(to_pat_enc.clone());
                }
                _ => {}
            }
        }
        result.push(str_ref[str_ref.len() - 1].clone());
        FheString::new_unchecked(result)
    }

    #[inline]
    fn replace_same_len_pat_clear(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        to_pat: &str,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        let to_pat_enc: Vec<_> = to_pat
            .as_bytes()
            .par_iter()
            .map(|x| {
                self.0
                    .create_trivial_radix::<u64, RadixCiphertext>(*x as u64, self.1)
            })
            .collect();
        let pattern_starts = str_ref.par_windows(from_pat.len()).map(|window| {
            let starts = self.starts_with_clear_par(window, from_pat);
            let starts_len = self
                .0
                .scalar_mul_parallelized(&starts, from_pat.len() as u64);
            Some((max_count.as_ref().map(|_| starts), starts_len))
        });
        let accumulated_starts: Vec<_> = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((count_x, start_x)), Some((count_y, start_y))) => {
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        &start_y,
                    );
                    Some((self.add(count_x.as_ref(), count_y.as_ref()), next_start))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .flat_map(|x| {
            x.map(|(count, starts)| {
                let (basic_cond, extra_cond) = rayon::join(
                    || {
                        self.0
                            .scalar_eq_parallelized(&starts, from_pat.len() as u64)
                    },
                    || match (count, max_count.as_ref()) {
                        (Some(count), Some(Number::Clear(mc))) => {
                            Some(self.0.scalar_le_parallelized(&count, *mc as u64))
                        }
                        (Some(count), Some(Number::Encrypted(mc))) => {
                            Some(self.0.le_parallelized(&count, mc))
                        }
                        _ => None,
                    },
                );
                if let Some(cond) = extra_cond {
                    self.0.bitand_parallelized(&basic_cond, &cond)
                } else {
                    basic_cond
                }
            })
        })
        .collect();
        let mut result = str_ref.to_vec();
        for (i, starts) in accumulated_starts.iter().enumerate() {
            for j in i..i + from_pat.len() {
                result[j] = self
                    .0
                    .if_then_else_parallelized(starts, &to_pat_enc[j - i], result[j].as_ref())
                    .into();
            }
        }
        FheString::new_unchecked(result)
    }

    #[inline]
    fn replace_diff_len_pat_clear(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        to_pat: &str,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        let max_len = if from_pat.len() > to_pat.len() {
            str_ref.len()
        } else {
            (str_ref.len() - 1) * (to_pat.len() - from_pat.len() + 1) + 1
        };
        let mut result = Vec::with_capacity(max_len);
        let to_pat_enc: Vec<_> = to_pat
            .as_bytes()
            .par_iter()
            .map(|x| {
                self.0
                    .create_trivial_radix::<u64, RadixCiphertext>(*x as u64, self.1)
            })
            .collect();
        let pattern_starts = (0..str_ref.len()).into_par_iter().map(|i| {
            let window = &str_ref[i..std::cmp::min(str_ref.len(), i + from_pat.len())];
            let starts = self.starts_with_clear_par(window, from_pat);
            Some((
                self.0
                    .scalar_mul_parallelized(&starts, from_pat.len() as u64),
                starts,
            ))
        });
        let accumulated_starts: Vec<_> = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((start_x, count_x)), Some((start_y, count_y))) => {
                    let mut count_xy = self.0.add_parallelized(count_x, count_y);
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let mut start_y = start_y.clone();
                    match max_count.as_ref() {
                        Some(Number::Clear(count)) => {
                            let (min_next_count, not_reached_max_count) = rayon::join(
                                || self.0.scalar_min_parallelized(&count_xy, *count as u64),
                                || self.0.scalar_le_parallelized(&count_xy, *count as u64),
                            );
                            count_xy = min_next_count;
                            self.0
                                .bitand_assign_parallelized(&mut start_y, &not_reached_max_count);
                        }
                        Some(Number::Encrypted(count)) => {
                            let (min_next_count, not_reached_max_count) = rayon::join(
                                || self.0.min_parallelized(&count_xy, count),
                                || self.0.le_parallelized(&count_xy, count),
                            );
                            count_xy = min_next_count;

                            self.0
                                .bitand_assign_parallelized(&mut start_y, &not_reached_max_count);
                        }
                        _ => {}
                    }
                    let next_count =
                        self.0
                            .if_then_else_parallelized(&in_pattern, &count_x, &count_xy);

                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        &start_y,
                    );
                    Some((next_start, next_count))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .flatten()
        .collect();
        let mut pattern_found_count = accumulated_starts
            .last()
            .cloned()
            .map(|(_, y)| y)
            .unwrap_or_else(|| self.false_ct());
        match max_count {
            Some(Number::Clear(count)) => {
                pattern_found_count = self
                    .0
                    .scalar_min_parallelized(&pattern_found_count, count as u64);
            }
            Some(Number::Encrypted(count)) => {
                pattern_found_count = self.0.min_parallelized(&pattern_found_count, &count);
            }
            _ => {}
        }
        let shifted_indices: Vec<_> = (0..str_ref.len() - 1)
            .into_par_iter()
            .zip(accumulated_starts)
            .map(|(i, (starts, count))| {
                if from_pat.len() > to_pat.len() {
                    let shift_len = from_pat.len() - to_pat.len();
                    let lhs = self
                        .0
                        .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1);
                    let rhs = self.0.scalar_mul_parallelized(&count, shift_len as u64);
                    (starts, self.0.sub_parallelized(&lhs, &rhs))
                } else {
                    let shift_len = to_pat.len() - from_pat.len();
                    let lhs = self.0.scalar_mul_parallelized(&count, shift_len as u64);
                    (starts, self.0.scalar_add_parallelized(&lhs, i as u64))
                }
            })
            .collect::<Vec<_>>();
        result.par_extend(
            (0..max_len)
                .into_par_iter()
                .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
        );
        for i in 0..max_len - 1 {
            let (to_fill, remaining_pat) = rayon::join(
                || self.0.scalar_eq_parallelized(result[i].as_ref(), 0 as u64),
                || self.0.scalar_gt_parallelized(&pattern_found_count, 0),
            );
            let cond = self.0.bitand_parallelized(&to_fill, &remaining_pat);
            for j in 0..to_pat_enc.len() {
                if i + j >= result.len() {
                    break;
                }
                result[i + j] = self
                    .0
                    .if_then_else_parallelized(&cond, &to_pat_enc[j], result[i + j].as_ref())
                    .into();
            }
            self.0
                .sub_assign_parallelized(&mut pattern_found_count, &cond);
        }
        FheString::new_unchecked(result)
    }

    #[inline]
    fn replace_pat_encrypted(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &FheString<Padded>,
        to_pat: &FheString<Padded>,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        let from_pat_ref = from_pat.as_ref();
        let to_pat_ref = to_pat.as_ref();
        let max_len = (str_ref.len() - 1) * to_pat_ref.len() + 1;
        let mut result = Vec::with_capacity(max_len);

        let ((from_pat_len, to_pat_len), to_pat_notzeroes) = rayon::join(
            || rayon::join(|| self.len(from_pat), || self.len(to_pat)),
            || {
                to_pat_ref[..to_pat_ref.len() - 1]
                    .par_iter()
                    .map(|x| self.0.scalar_ne_parallelized(x.as_ref(), 0 as u64))
                    .collect::<Vec<_>>()
            },
        );

        let (pattern_starts, (from_pat_gt, shrink_shift_len, grow_shift_len)) = rayon::join(
            || {
                (0..str_ref.len()).into_par_iter().map(|i| {
                    let (starts, not_ended) = rayon::join(
                        || self.starts_with_encrypted_par(&str_ref[i..], from_pat_ref),
                        || self.0.scalar_ne_parallelized(str_ref[i].as_ref(), 0),
                    );
                    Some((
                        self.0.mul_parallelized(&starts, &from_pat_len),
                        starts,
                        not_ended,
                    ))
                })
            },
            || {
                let from_pat_gt = self.0.gt_parallelized(&from_pat_len, &to_pat_len);
                let shrink_shift_len = self.0.sub_parallelized(&from_pat_len, &to_pat_len);
                let grow_shift_len = self.0.sub_parallelized(&to_pat_len, &from_pat_len);
                (from_pat_gt, shrink_shift_len, grow_shift_len)
            },
        );
        let accumulated_starts: Vec<_> = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((start_x, count_x, not_ended_x)), Some((start_y, count_y, not_ended_y))) => {
                    let count = self.0.add_parallelized(count_x, count_y);
                    let not_ended = self.0.bitor_parallelized(not_ended_x, not_ended_y);
                    let count_correct = self
                        .0
                        .if_then_else_parallelized(&not_ended, &count, count_x);
                    let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
                    let next_pattern = self.0.scalar_gt_parallelized(start_y, 0);

                    let mut next_count =
                        self.0
                            .if_then_else_parallelized(&in_pattern, &count_x, &count_correct);
                    let mut start_y_not_ended =
                        self.0.bitand_parallelized(&next_pattern, not_ended_y);

                    match max_count.as_ref() {
                        Some(Number::Clear(count)) => {
                            let (min_next_count, not_reached_max_count) = rayon::join(
                                || self.0.scalar_min_parallelized(&next_count, *count as u64),
                                || self.0.scalar_le_parallelized(&next_count, *count as u64),
                            );
                            next_count = min_next_count;
                            self.0.bitand_assign_parallelized(
                                &mut start_y_not_ended,
                                &not_reached_max_count,
                            );
                        }
                        Some(Number::Encrypted(count)) => {
                            let (min_next_count, not_reached_max_count) = rayon::join(
                                || self.0.min_parallelized(&next_count, count),
                                || self.0.le_parallelized(&next_count, count),
                            );
                            next_count = min_next_count;

                            self.0.bitand_assign_parallelized(
                                &mut start_y_not_ended,
                                &not_reached_max_count,
                            );
                        }
                        _ => {}
                    }
                    let next_start_y = self.0.if_then_else_parallelized(
                        &start_y_not_ended,
                        &start_y,
                        &self.false_ct(),
                    );
                    let next_start = self.0.if_then_else_parallelized(
                        &in_pattern,
                        &self.0.scalar_sub_parallelized(start_x, 1),
                        &next_start_y,
                    );
                    Some((next_start, next_count, not_ended_y.clone()))
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .flatten()
        .collect();

        let mut pattern_found_count = accumulated_starts
            .last()
            .cloned()
            .map(|(_, y, _)| y)
            .unwrap_or_else(|| self.false_ct());

        let shifted_indices: Vec<_> = (0..str_ref.len() - 1)
            .into_par_iter()
            .zip(accumulated_starts)
            .map(|(i, (starts, count, _))| {
                let (shrink_index, grow_index) = rayon::join(
                    || {
                        let lhs = self
                            .0
                            .create_trivial_radix::<u64, RadixCiphertext>(i as u64, self.1);
                        let rhs = self.0.mul_parallelized(&count, &shrink_shift_len);
                        self.0.sub_parallelized(&lhs, &rhs)
                    },
                    || {
                        let lhs = self.0.mul_parallelized(&count, &grow_shift_len);
                        self.0.scalar_add_parallelized(&lhs, i as u64)
                    },
                );
                (
                    starts,
                    self.0
                        .if_then_else_parallelized(&from_pat_gt, &shrink_index, &grow_index),
                )
            })
            .collect::<Vec<_>>();

        result.par_extend(
            (0..max_len)
                .into_par_iter()
                .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
        );

        for i in 0..max_len {
            let (to_fill, remaining_pat) = rayon::join(
                || self.0.scalar_eq_parallelized(result[i].as_ref(), 0 as u64),
                || self.0.scalar_gt_parallelized(&pattern_found_count, 0),
            );
            let cond = self.0.bitand_parallelized(&to_fill, &remaining_pat);
            for j in 0..to_pat_ref.len() - 1 {
                if i + j >= result.len() {
                    break;
                }
                let sub_cond = self.0.bitand_parallelized(&cond, &to_pat_notzeroes[j]);
                result[i + j] = self
                    .0
                    .if_then_else_parallelized(
                        &sub_cond,
                        to_pat_ref[j].as_ref(),
                        result[i + j].as_ref(),
                    )
                    .into();
            }
            self.0
                .sub_assign_parallelized(&mut pattern_found_count, &cond);
        }
        FheString::new_unchecked(result)
    }

    /// Replaces all matches of a pattern with another string.
    ///
    /// `replace` creates a new [`FheString`], and copies the data from `encrypted_str` into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice.
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
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is new", client_key.decrypt_str(&server_key.replace(&s, "old", "new")));
    /// assert_eq!("than an old", client_key.decrypt_str(&server_key.replace(&s, "is", "an")));
    /// let old = client_key.encrypt_str("old").unwrap();
    /// let new = client_key.encrypt_str("new").unwrap();
    /// let is = client_key.encrypt_str("is").unwrap();
    /// let an = client_key.encrypt_str("an").unwrap();
    /// assert_eq!("this is new", client_key.decrypt_str(&server_key.replace(&s, &old, &new)));
    /// assert_eq!("than an old", client_key.decrypt_str(&server_key.replace(&s, &is, &an)));
    /// ```
    ///
    /// When the pattern doesn't match, it returns `encrypted_str` as [`FheString`]:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replace(&s, "X", "Y")));
    /// let x = client_key.encrypt_str("X").unwrap();
    /// let y = client_key.encrypt_str("Y").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replace(&s, &x, &y)));
    /// ```
    /// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
    /// API not fully fleshed out and ready to be stabilized
    /// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
    #[must_use = "this returns the replaced FheString as a new allocation, \
                      without modifying the original"]
    #[inline]
    pub fn replace<'a, P: Into<Pattern<'a, Padded>>>(
        &self,
        encrypted_str: &FheString<Padded>,
        from: P,
        to: P,
    ) -> FheString<Padded> {
        let str_ref = encrypted_str.as_ref();
        match (from.into(), to.into()) {
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if from_pat.is_empty() && to_pat.is_empty() =>
            {
                encrypted_str.clone()
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) if from_pat.is_empty() => {
                self.replace_empty_from_pat_clear(str_ref, to_pat, None)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if to_pat.len() == from_pat.len() =>
            {
                self.replace_same_len_pat_clear(str_ref, from_pat, to_pat, None)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) => {
                self.replace_diff_len_pat_clear(str_ref, from_pat, to_pat, None)
            }
            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat)) => {
                self.replace_pat_encrypted(str_ref, from_pat, to_pat, None)
            }
            _ => {
                // since both `from` and `to` need to be `P`
                unreachable!("mixed replacement patterns are not supported")
            }
        }
    }

    /// Replaces first N matches of a pattern with another string.
    ///
    /// `replacen` creates a new [`FheString`], and copies the data from  `encrypted_str` into it.
    /// While doing so, it attempts to find matches of a pattern. If it finds any, it
    /// replaces them with the replacement string slice at most `count` times.
    ///
    /// `count` can either be a [`Number::Clear`] or a [`Number::Encrypted`].
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// let s = "foo foo 123 foo";
    /// assert_eq!("new new 123 foo", s.replacen("foo", "new", 2));
    /// assert_eq!("faa fao 123 foo", s.replacen('o', "a", 3));

    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("foo foo 123 foo").unwrap();
    /// assert_eq!("new new 123 foo", client_key.decrypt_str(&server_key.replacen(&s, "foo", "new", 2)));
    /// let foo = client_key.encrypt_str("foo").unwrap();
    /// let new = client_key.encrypt_str("new").unwrap();
    /// let count2 = client_key.encrypt_usize(2);
    /// assert_eq!("new new 123 foo", client_key.decrypt_str(&server_key.replacen(&s, foo, new, count2)));
    /// assert_eq!("faa fao 123 foo", client_key.decrypt_str(&server_key.replacen(&s, "o", "a", 3)));
    /// let o = client_key.encrypt_str("o").unwrap();
    /// let a = client_key.encrypt_str("a").unwrap();
    /// let count3 = client_key.encrypt_usize(3);
    /// assert_eq!("faa fao 123 foo", client_key.decrypt_str(&server_key.replacen(&s, "o", "a", count3)));
    /// ```
    ///
    /// When the pattern doesn't match, it returns this string slice as [`String`]:
    ///
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replacen(&s, "cookie monster", "little lamb", 10)));
    /// let cm = client_key.encrypt_str("cookie monster").unwrap();
    /// let ll = client_key.encrypt_str("little lamb").unwrap();
    /// let count10 = client_key.encrypt_usize(10);
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replacen(&s, &cm, &ll, count10)));
    /// ```
    #[must_use = "this returns the replaced `FheString` as a new allocation, \
                      without modifying the original"]
    pub fn replacen<'a, P: Into<Pattern<'a, Padded>>, N: Into<Number>>(
        &'a self,
        encrypted_str: &FheString<Padded>,
        from: P,
        to: P,
        count: N,
    ) -> FheString<Padded> {
        let str_ref = encrypted_str.as_ref();
        match (from.into(), to.into(), count.into()) {
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), Number::Clear(count))
                if (from_pat.is_empty() && to_pat.is_empty()) || count == 0 =>
            {
                encrypted_str.clone()
            }
            // TODO: CLear/Clear/Encrypted works via replace_diff_len_pat_clear, but may can be made more efficient?
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), Number::Clear(count))
                if from_pat.is_empty() =>
            {
                self.replace_empty_from_pat_clear(str_ref, to_pat, Some(count))
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), n)
                if to_pat.len() == from_pat.len() =>
            {
                self.replace_same_len_pat_clear(str_ref, from_pat, to_pat, Some(n))
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), n) => {
                self.replace_diff_len_pat_clear(str_ref, from_pat, to_pat, Some(n))
            }
            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat), n) => {
                self.replace_pat_encrypted(str_ref, from_pat, to_pat, Some(n))
            }
            (Pattern::Clear(_), Pattern::Encrypted(_), _) => {
                // since both `from` and `to` need to be `P`
                unreachable!("mixed replacement patterns are not supported")
            }
            (Pattern::Encrypted(_), Pattern::Clear(_), _) => {
                // since both `from` and `to` need to be `P`
                unreachable!("mixed replacement patterns are not supported")
            }
        }
    }
}
