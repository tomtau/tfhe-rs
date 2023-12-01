use rayon::prelude::*;
use tfhe::integer::RadixCiphertext;

use crate::ciphertext::{
    FheAsciiChar, FheBool, FheString, FheUsize, Number, Padded, Pattern, Unpadded,
};
use crate::scan::scan;

use super::ServerKey;

impl ServerKey {
    #[inline]
    fn replace_empty_from_pat_unpadded_clear(
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
        for c in str_ref.iter() {
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
        result.push(self.false_ct().into());
        FheString::new_unchecked(result)
    }

    /// A helper that intersperses `to_pat` between each character in `str_ref`
    /// up to `max_count` times.
    /// Assumes that `to_pat` is ASCII.
    #[inline]
    fn replace_empty_from_pat_padded_clear(
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

    /// A helper that replaces each occurence of `from_pat` with `to_pat` in
    /// `str_ref` up to `max_count` times.
    /// Assumes that `from_pat` and `to_pat` have the same length.
    /// Assumes that `from_pat` is not empty.
    /// Assumes that `from_pat` is not longer than `str_ref`.
    /// Assumes that `from_pat` and `to_pat` are ASCII.
    #[inline]
    fn replace_same_len_pat_clear(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        to_pat: &str,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        let to_pat_enc: Vec<_> = self.encrypt_clear_pat(to_pat);
        let pattern_starts = str_ref.par_windows(from_pat.len()).map(|window| {
            let starts = self.starts_with_clear_par(window, from_pat);
            let starts_len = self
                .0
                .scalar_mul_parallelized(&starts, from_pat.len() as u64);
            Some((max_count.as_ref().map(|_| starts), starts_len))
        });
        let accumulated_starts: Vec<_> =
            self.accumulate_clear_pat_starts(pattern_starts)
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
                                    let count_not_reached = self.0.le_parallelized(&count, mc);
                                    let max_count_gt_zero =
                                        self.0.scalar_gt_parallelized(mc, 0_u64);
                                    Some(self.0.bitand_parallelized(
                                        &count_not_reached,
                                        &max_count_gt_zero,
                                    ))
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
    fn replace_same_len_pat_unpadded_encrypted(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &FheString<Unpadded>,
        to_pat: &FheString<Unpadded>,
        max_count: Option<Number>,
    ) -> FheString<Unpadded> {
        let to_pat_enc = to_pat.as_ref();
        let from_pat_enc = from_pat.as_ref();
        let pattern_starts = str_ref.par_windows(from_pat_enc.len()).map(|window| {
            let starts = self.par_eq(window, from_pat_enc);
            let starts_len = self
                .0
                .scalar_mul_parallelized(&starts, from_pat_enc.len() as u64);
            Some((max_count.as_ref().map(|_| starts), starts_len))
        });
        let accumulated_starts: Vec<_> =
            self.accumulate_clear_pat_starts(pattern_starts)
                .flat_map(|x| {
                    x.map(|(count, starts)| {
                        let (basic_cond, extra_cond) = rayon::join(
                            || {
                                self.0
                                    .scalar_eq_parallelized(&starts, from_pat_enc.len() as u64)
                            },
                            || match (count, max_count.as_ref()) {
                                (Some(count), Some(Number::Clear(mc))) => {
                                    Some(self.0.scalar_le_parallelized(&count, *mc as u64))
                                }
                                (Some(count), Some(Number::Encrypted(mc))) => {
                                    let count_not_reached = self.0.le_parallelized(&count, mc);
                                    let max_count_gt_zero =
                                        self.0.scalar_gt_parallelized(mc, 0_u64);
                                    Some(self.0.bitand_parallelized(
                                        &count_not_reached,
                                        &max_count_gt_zero,
                                    ))
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
            for j in i..i + from_pat_enc.len() {
                result[j] = self
                    .0
                    .if_then_else_parallelized(
                        starts,
                        to_pat_enc[j - i].as_ref(),
                        result[j].as_ref(),
                    )
                    .into();
            }
        }
        FheString::new_unchecked(result)
    }

    /// A helper that encrypts a clear pattern.
    /// Assumes that the pattern is ASCII.
    #[inline]
    fn encrypt_clear_pat(&self, pat: &str) -> Vec<RadixCiphertext> {
        pat.as_bytes()
            .par_iter()
            .map(|x| {
                self.0
                    .create_trivial_radix::<u64, RadixCiphertext>(*x as u64, self.1)
            })
            .collect()
    }

    /// A helper that replaces each occurrence of `from_pat` with `to_pat` in `str_ref`.
    /// Assumes that the patterns are ASCII.
    #[inline]
    fn replace_diff_len_pat_clear(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        to_pat: &str,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        if let Some(Number::Clear(0)) = max_count {
            return FheString::new_unchecked(str_ref.to_vec());
        }
        let gt_than_zero = if let Some(Number::Encrypted(n)) = max_count.as_ref() {
            Some(self.0.scalar_gt_parallelized(n, 0))
        } else {
            None
        };
        let max_len = if from_pat.len() > to_pat.len() {
            str_ref.len()
        } else {
            (str_ref.len() - 1) * (to_pat.len() - from_pat.len() + 1) + 1
        };
        let mut result = Vec::with_capacity(max_len);
        let to_pat_enc = self.encrypt_clear_pat(to_pat);
        let pattern_starts = (0..str_ref.len()).into_par_iter().map(|i| {
            let window = &str_ref[i..std::cmp::min(str_ref.len(), i + from_pat.len())];
            let mut starts = self.starts_with_clear_par(window, from_pat);
            if let Some(gt_z) = gt_than_zero.as_ref() {
                self.0.bitand_assign_parallelized(&mut starts, gt_z);
            }
            Some((
                self.0
                    .scalar_mul_parallelized(&starts, from_pat.len() as u64),
                starts,
            ))
        });
        let accumulated_starts: Vec<_> = scan(
            pattern_starts,
            |x, y| match (x, y) {
                (Some((start_x, count_x)), Some((start_y, count_y))) => self
                    .accumulate_clear_pat_starts_diff_len_padded(
                        &max_count, &start_x, count_x, start_y, count_y,
                    ),
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
        let shifted_indices: Vec<_> = self.calculate_clear_pattern_shifted_indices(
            str_ref,
            from_pat,
            to_pat,
            accumulated_starts,
        );
        result.par_extend(
            (0..max_len)
                .into_par_iter()
                .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
        );
        self.fill_pattern(max_len, &mut result, &to_pat_enc, pattern_found_count);
        self.patch_empty_from_pattern(str_ref, from_pat, gt_than_zero, &mut result, &to_pat_enc);
        FheString::new_unchecked(result)
    }

    /// A helper that fills each 0 that matched "from pattern"
    /// in `result` with the corresponding character from `to_pat_enc`.
    #[inline]
    fn fill_pattern(
        &self,
        max_len: usize,
        result: &mut Vec<FheAsciiChar>,
        to_pat_enc: &Vec<RadixCiphertext>,
        mut pattern_found_count: FheBool,
    ) {
        // TODO: can this be parallelized?
        for i in 0..max_len - 1 {
            let (to_fill, remaining_pat) = rayon::join(
                || self.0.scalar_eq_parallelized(result[i].as_ref(), 0u64),
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
    }

    /// A helper that patches the case when `from_pat` is empty.
    #[inline]
    fn patch_empty_from_pattern(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        gt_than_zero: Option<RadixCiphertext>,
        result: &mut Vec<FheAsciiChar>,
        to_pat_enc: &Vec<RadixCiphertext>,
    ) {
        // TODO: extract to an optimized function to handle just this case instead of doing it in `replace_diff_len_pat_clear`?
        if from_pat.is_empty() {
            let zero = self.false_ct();
            let mut str_ref_empty = self.0.scalar_eq_parallelized(str_ref[0].as_ref(), 0u64);
            if let Some(gtz) = gt_than_zero {
                self.0.bitand_assign_parallelized(&mut str_ref_empty, &gtz);
            }
            for i in 0..result.len() {
                if i < to_pat_enc.len() {
                    result[i] = self
                        .0
                        .if_then_else_parallelized(
                            &str_ref_empty,
                            &to_pat_enc[i],
                            result[i].as_ref(),
                        )
                        .into();
                } else {
                    result[i] = self
                        .0
                        .if_then_else_parallelized(&str_ref_empty, &zero, result[i].as_ref())
                        .into();
                }
            }
        }
    }

    /// A helper that calculates the shifted indices depending
    /// on the difference in length between `from_pat` and `to_pat`
    /// and the accumulated count of starts of `from_pat` at a given index.
    #[inline]
    fn calculate_clear_pattern_shifted_indices(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat: &str,
        to_pat: &str,
        accumulated_starts: Vec<(FheUsize, FheUsize)>,
    ) -> Vec<(FheBool, FheUsize)> {
        (0..str_ref.len() - 1)
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
            .collect()
    }

    /// A helper for accumulating the pattern overlaps and counts.
    /// See [`accumulate_clear_pat_starts`] for this behavior.
    ///
    /// [`accumulate_clear_pat_starts`]: ServerKey::accumulate_clear_pat_starts
    #[inline]
    fn accumulate_clear_pat_starts_diff_len_padded(
        &self,
        max_count: &Option<Number>,
        start_x: &FheUsize,
        count_x: &FheUsize,
        start_y: &FheUsize,
        count_y: &FheUsize,
    ) -> Option<(FheUsize, FheUsize)> {
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
        let next_count = self
            .0
            .if_then_else_parallelized(&in_pattern, count_x, &count_xy);

        let next_start = self.0.if_then_else_parallelized(
            &in_pattern,
            &self.0.scalar_sub_parallelized(start_x, 1),
            &start_y,
        );
        Some((next_start, next_count))
    }

    /// A helper to replace each occurrence of the padded encrypted
    /// `from_pat` with the encrypted `to_pat` in the encrypted `encrypted_str`
    /// up to `max_count` times.
    #[inline]
    fn replace_pat_encrypted(
        &self,
        encrypted_str: &FheString<Padded>,
        from_pat: &FheString<Padded>,
        to_pat: &FheString<Padded>,
        max_count: Option<Number>,
    ) -> FheString<Padded> {
        if let Some(Number::Clear(0)) = max_count {
            return encrypted_str.clone();
        }
        let str_ref_empty = self.is_empty(encrypted_str);
        let str_ref = encrypted_str.as_ref();
        let gt_than_zero = if let Some(Number::Encrypted(n)) = max_count.as_ref() {
            let gt_than_zero = self.0.scalar_gt_parallelized(n, 0);
            Some(gt_than_zero)
        } else {
            None
        };
        // Adjust the count if the padded pattern is empty.
        let adjusted_max_count =
            self.adjust_empty_pattern_pat_max_acount(max_count, &str_ref_empty);

        let from_pat_ref = from_pat.as_ref();
        let to_pat_ref = to_pat.as_ref();
        let max_len = str_ref.len() * to_pat_ref.len() + 1;
        let mut result = Vec::with_capacity(max_len);

        let ((from_pat_len, to_pat_len), to_pat_notzeroes) = rayon::join(
            || rayon::join(|| self.len(from_pat), || self.len(to_pat)),
            || {
                to_pat_ref[..to_pat_ref.len() - 1]
                    .par_iter()
                    .map(|x| self.0.scalar_ne_parallelized(x.as_ref(), 0_u64))
                    .collect::<Vec<_>>()
            },
        );

        let (pattern_starts, (from_pat_gt, shrink_shift_len, grow_shift_len)) = rayon::join(
            || {
                (0..str_ref.len()).into_par_iter().map(|i| {
                    self.enc_padded_pat_start(
                        &str_ref,
                        gt_than_zero.as_ref(),
                        from_pat_ref,
                        &from_pat_len,
                        i,
                    )
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
                    self.accumulate_enc_pat_starts_padded(
                        &adjusted_max_count,
                        &start_x,
                        count_x,
                        not_ended_x,
                        start_y,
                        count_y,
                        not_ended_y,
                    )
                }
                (None, y) => y.clone(),
                (x, None) => x.clone(),
            },
            None,
        )
        .flatten()
        .collect();

        let pattern_found_count = accumulated_starts
            .last()
            .cloned()
            .map(|(_, y, _)| y)
            .unwrap_or_else(|| self.false_ct());

        let shifted_indices: Vec<_> = self.calculate_enc_pat_shifted_indices(
            str_ref,
            &from_pat_gt,
            &shrink_shift_len,
            &grow_shift_len,
            accumulated_starts,
        );

        result.par_extend(
            (0..max_len)
                .into_par_iter()
                .map(|i| self.find_shifted_index_char(i, str_ref, &shifted_indices)),
        );

        self.fill_enc_pattern(
            to_pat_ref,
            max_len,
            &mut result,
            &to_pat_notzeroes,
            pattern_found_count,
        );
        FheString::new_unchecked(result)
    }

    /// A helper to replace 0 characters in the encrypted `encrypted_str`
    /// with the encrypted `to_pat` in the encrypted `encrypted_str`
    #[inline]
    fn fill_enc_pattern(
        &self,
        to_pat_ref: &[FheAsciiChar],
        max_len: usize,
        result: &mut Vec<FheAsciiChar>,
        to_pat_notzeroes: &Vec<RadixCiphertext>,
        mut pattern_found_count: FheUsize,
    ) {
        // TODO: can this be parallelized?
        for i in 0..max_len {
            let (to_fill, remaining_pat) = rayon::join(
                || self.0.scalar_eq_parallelized(result[i].as_ref(), 0_u64),
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
    }

    /// A helper that calculates the shifted indices depending
    /// on the difference in length between `from_pat` and `to_pat`
    /// (as they are encrypted with padding and we don't know their length difference,
    /// we use homomorphic cmux to decide which index to use)
    #[inline]
    fn calculate_enc_pat_shifted_indices(
        &self,
        str_ref: &[FheAsciiChar],
        from_pat_gt: &FheUsize,
        shrink_shift_len: &FheUsize,
        grow_shift_len: &FheUsize,
        accumulated_starts: Vec<(FheUsize, FheUsize, FheBool)>,
    ) -> Vec<(FheUsize, FheUsize)> {
        (0..str_ref.len() - 1)
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
                        .if_then_else_parallelized(from_pat_gt, &shrink_index, &grow_index),
                )
            })
            .collect::<Vec<_>>()
    }

    /// A helper that calculated if the encrypted pattern starts at the given index
    /// and if the padded string is not ended at the given index.
    #[inline]
    fn enc_padded_pat_start(
        &self,
        str_ref: &[FheAsciiChar],
        gt_than_zero: Option<&FheBool>,
        from_pat_ref: &[FheAsciiChar],
        from_pat_len: &FheUsize,
        i: usize,
    ) -> Option<(FheUsize, FheUsize, FheBool)> {
        let (mut starts, not_ended) = rayon::join(
            || self.starts_with_encrypted_par(&str_ref[i..], from_pat_ref),
            || self.0.scalar_ne_parallelized(str_ref[i].as_ref(), 0),
        );
        if let Some(gt_z) = gt_than_zero {
            self.0.bitand_assign_parallelized(&mut starts, gt_z);
        }
        Some((
            self.0.mul_parallelized(&starts, &from_pat_len),
            starts,
            not_ended,
        ))
    }

    /// A helper for accumulating the pattern overlaps and counts.
    /// See [`accumulate_clear_pat_starts`] for this behavior.
    /// Besides the count, it also returns the `not_ended` flag
    /// to help with the padding in encrypted strings.
    ///
    /// [`accumulate_clear_pat_starts`]: ServerKey::accumulate_clear_pat_starts
    #[inline]
    fn accumulate_enc_pat_starts_padded(
        &self,
        adjusted_max_count: &FheUsize,
        start_x: &FheUsize,
        count_x: &FheUsize,
        not_ended_x: &FheBool,
        start_y: &FheUsize,
        count_y: &FheUsize,
        not_ended_y: &FheBool,
    ) -> Option<(FheUsize, FheUsize, FheBool)> {
        let count = self.0.add_parallelized(count_x, count_y);
        let not_ended = self.0.bitor_parallelized(not_ended_x, not_ended_y);
        let count_correct = self
            .0
            .if_then_else_parallelized(&not_ended, &count, count_x);
        let in_pattern = self.0.scalar_gt_parallelized(start_x, 1);
        let next_pattern = self.0.scalar_gt_parallelized(start_y, 0);

        let mut next_count = self
            .0
            .if_then_else_parallelized(&in_pattern, count_x, &count_correct);
        let mut start_y_not_ended = self.0.bitand_parallelized(&next_pattern, not_ended_y);

        let (min_next_count, not_reached_max_count) = rayon::join(
            || self.0.min_parallelized(&next_count, &adjusted_max_count),
            || self.0.le_parallelized(&next_count, &adjusted_max_count),
        );
        next_count = min_next_count;

        self.0
            .bitand_assign_parallelized(&mut start_y_not_ended, &not_reached_max_count);

        let next_start_y =
            self.0
                .if_then_else_parallelized(&start_y_not_ended, start_y, &self.false_ct());
        let next_start = self.0.if_then_else_parallelized(
            &in_pattern,
            &self.0.scalar_sub_parallelized(start_x, 1),
            &next_start_y,
        );
        Some((next_start, next_count, not_ended_y.clone()))
    }

    /// A helper to adjust the maximum count if the padded input string is empty.
    #[inline]
    fn adjust_empty_pattern_pat_max_acount(
        &self,
        max_count: Option<Number>,
        str_ref_empty: &FheBool,
    ) -> FheBool {
        match max_count {
            Some(Number::Clear(mc)) => {
                let enc_mc = self.0.create_trivial_radix(mc as u64, self.1);
                self.0
                    .if_then_else_parallelized(&str_ref_empty, &self.true_ct(), &enc_mc)
            }
            Some(Number::Encrypted(mc)) => {
                self.0
                    .if_then_else_parallelized(&str_ref_empty, &self.true_ct(), &mc)
            }
            None => {
                let enc_mc = self.0.create_trivial_radix(u64::MAX, self.1);
                self.0
                    .if_then_else_parallelized(&str_ref_empty, &self.true_ct(), &enc_mc)
            }
        }
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
    /// assert_eq!(
    ///     "this is new",
    ///     client_key.decrypt_str(&server_key.replace(&s, "old", "new"))
    /// );
    /// assert_eq!(
    ///     "than an old",
    ///     client_key.decrypt_str(&server_key.replace(&s, "is", "an"))
    /// );
    /// let old = client_key.encrypt_str("old").unwrap();
    /// let new = client_key.encrypt_str("new").unwrap();
    /// let is = client_key.encrypt_str("is").unwrap();
    /// let an = client_key.encrypt_str("an").unwrap();
    /// assert_eq!(
    ///     "this is new",
    ///     client_key.decrypt_str(&server_key.replace(&s, &old, &new))
    /// );
    /// assert_eq!(
    ///     "than an old",
    ///     client_key.decrypt_str(&server_key.replace(&s, &is, &an))
    /// );
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
    /// assert_eq!(
    ///     "this is old",
    ///     client_key.decrypt_str(&server_key.replace(&s, "X", "Y"))
    /// );
    /// let x = client_key.encrypt_str("X").unwrap();
    /// let y = client_key.encrypt_str("Y").unwrap();
    /// assert_eq!(
    ///     "this is old",
    ///     client_key.decrypt_str(&server_key.replace(&s, &x, &y))
    /// );
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
                self.replace_empty_from_pat_padded_clear(str_ref, to_pat, None)
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
                self.replace_pat_encrypted(encrypted_str, from_pat, to_pat, None)
            }
            _ => {
                // since both `from` and `to` need to be `P`
                unreachable!("mixed replacement patterns are not supported")
            }
        }
    }

    #[must_use = "this returns the replaced FheString as a new allocation, \
                      without modifying the original"]
    #[inline]
    pub fn replace_unpadded<'a, P: Into<Pattern<'a, Unpadded>>>(
        &self,
        encrypted_str: &FheString<Unpadded>,
        from: P,
        to: P,
    ) -> FheString<Padded> {
        let str_ref = encrypted_str.as_ref();
        match (from.into(), to.into()) {
            (Pattern::Clear(from_pat), _) if !from_pat.is_empty() && str_ref.is_empty() =>
            // unpadded
            {
                self.pad_string(encrypted_str)
            }
            (Pattern::Encrypted(from_pat), _)
                if !from_pat.as_ref().is_empty() && str_ref.is_empty() =>
            // unpadded
            {
                self.pad_string(encrypted_str)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if from_pat.is_empty() && to_pat.is_empty() =>
            {
                // unpadded
                self.pad_string(encrypted_str)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) if from_pat.is_empty() => {
                // padding needed for count
                self.replace_empty_from_pat_unpadded_clear(str_ref, to_pat, None)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat))
                if to_pat.len() == from_pat.len() =>
            {
                // unpadded
                self.replace_same_len_pat_clear(str_ref, from_pat, to_pat, None)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat)) => {
                // padding needed
                self.replace_diff_len_pat_clear(str_ref, from_pat, to_pat, None)
            }
            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat))
                if from_pat.as_ref().len() == to_pat.as_ref().len() =>
            {
                // unpadded
                self.pad_string(
                    &self.replace_same_len_pat_unpadded_encrypted(str_ref, from_pat, to_pat, None),
                )
            }

            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat)) => self
                .replace_pat_encrypted(
                    &self.pad_string(encrypted_str),
                    &self.pad_string(from_pat),
                    &self.pad_string(to_pat),
                    None,
                ),
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
    /// assert_eq!("new new 123 foo", client_key.decrypt_str(&server_key.replacen(&s, "foo", "new",
    /// 2))); let foo = client_key.encrypt_str("foo").unwrap();
    /// let new = client_key.encrypt_str("new").unwrap();
    /// let count2 = client_key.encrypt_usize(2);
    /// assert_eq!("new new 123 foo", client_key.decrypt_str(&server_key.replacen(&s, foo, new,
    /// count2))); assert_eq!("faa fao 123 foo", client_key.decrypt_str(&server_key.replacen(&s,
    /// "o", "a", 3))); let o = client_key.encrypt_str("o").unwrap();
    /// let a = client_key.encrypt_str("a").unwrap();
    /// let count3 = client_key.encrypt_usize(3);
    /// assert_eq!("faa fao 123 foo", client_key.decrypt_str(&server_key.replacen(&s, "o", "a",
    /// count3))); ```
    ///
    /// When the pattern doesn't match, it returns this string slice as [`String`]:
    /// ```
    /// let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    /// let client_key = client_key::ClientKey::from(ck);
    /// let server_key = server_key::ServerKey::from(sk);
    ///
    /// let s = client_key.encrypt_str("this is old").unwrap();
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replacen(&s, "cookie monster",
    /// "little lamb", 10))); let cm = client_key.encrypt_str("cookie monster").unwrap();
    /// let ll = client_key.encrypt_str("little lamb").unwrap();
    /// let count10 = client_key.encrypt_usize(10);
    /// assert_eq!("this is old", client_key.decrypt_str(&server_key.replacen(&s, &cm, &ll,
    /// count10))); ```
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
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), _)
                if (from_pat.is_empty() && to_pat.is_empty()) =>
            {
                encrypted_str.clone()
            }
            (_, _, Number::Clear(0)) => encrypted_str.clone(),
            // TODO: CLear/Clear/Encrypted works via replace_diff_len_pat_clear, but may can be made
            // more efficient?
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), Number::Clear(count))
                if from_pat.is_empty() =>
            {
                self.replace_empty_from_pat_padded_clear(str_ref, to_pat, Some(count))
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
                self.replace_pat_encrypted(encrypted_str, from_pat, to_pat, Some(n))
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

    #[must_use = "this returns the replaced `FheString` as a new allocation, \
                      without modifying the original"]
    pub fn replacen_unpadded<'a, P: Into<Pattern<'a, Unpadded>>, N: Into<Number>>(
        &'a self,
        encrypted_str: &FheString<Unpadded>,
        from: P,
        to: P,
        count: N,
    ) -> FheString<Padded> {
        let str_ref = encrypted_str.as_ref();
        match (from.into(), to.into(), count.into()) {
            (Pattern::Clear(from_pat), _, _) if !from_pat.is_empty() && str_ref.is_empty() =>
            // unpadded
            {
                self.pad_string(encrypted_str)
            }
            (Pattern::Encrypted(from_pat), _, _)
                if !from_pat.as_ref().is_empty() && str_ref.is_empty() =>
            // unpadded
            {
                self.pad_string(encrypted_str)
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), _)
                if (from_pat.is_empty() && to_pat.is_empty()) =>
            {
                // unpadded
                self.pad_string(encrypted_str)
            }
            (_, _, Number::Clear(0)) =>
            // unpadded
            {
                self.pad_string(encrypted_str)
            }
            // TODO: CLear/Clear/Encrypted works via replace_diff_len_pat_clear, but may can be made
            // more efficient?
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), Number::Clear(count))
                if from_pat.is_empty() =>
            {
                // padding needed for count
                self.replace_empty_from_pat_unpadded_clear(str_ref, to_pat, Some(count))
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), n)
                if to_pat.len() == from_pat.len() =>
            {
                // unpadded
                let padded = self.pad_string(encrypted_str);
                self.replace_same_len_pat_clear(padded.as_ref(), from_pat, to_pat, Some(n))
            }
            (Pattern::Clear(from_pat), Pattern::Clear(to_pat), n) => {
                // padded
                let padded = self.pad_string(encrypted_str);
                self.replace_diff_len_pat_clear(padded.as_ref(), from_pat, to_pat, Some(n))
            }
            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat), n)
                if from_pat.as_ref().len() == to_pat.as_ref().len() =>
            {
                // unpadded
                self.pad_string(&self.replace_same_len_pat_unpadded_encrypted(
                    str_ref,
                    from_pat,
                    to_pat,
                    Some(n),
                ))
            }

            (Pattern::Encrypted(from_pat), Pattern::Encrypted(to_pat), n) => self
                .replace_pat_encrypted(
                    &self.pad_string(encrypted_str),
                    &self.pad_string(from_pat),
                    &self.pad_string(to_pat),
                    Some(n),
                ),
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

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn replace_test_padded(input: &str, (pattern, replacement): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        println!("clear: {input} {pattern} {replacement} {padding_len}");

        assert_eq!(
            input.replace(pattern, replacement),
            client_key.decrypt_str(&server_key.replace(&encrypted_str, pattern, replacement))
        );
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        let encrypted_replacement = client_key
            .encrypt_str_padded(replacement, padding_len)
            .unwrap();
        println!("encrypted: {input} {pattern} {replacement} {padding_len}");
        assert_eq!(
            input.replace(pattern, replacement),
            client_key.decrypt_str(&server_key.replace(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement
            ))
        );
    }

    #[inline]
    fn replace_test_unpadded(input: &str, (pattern, replacement): (&str, &str)) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key.encrypt_str_unpadded(input).unwrap();
        println!("clear: {input} {pattern} {replacement}");

        assert_eq!(
            input.replace(pattern, replacement),
            client_key.decrypt_str(&server_key.replace_unpadded(
                &encrypted_str,
                pattern,
                replacement
            ))
        );
        let encrypted_pattern = client_key.encrypt_str_unpadded(pattern).unwrap();
        let encrypted_replacement = client_key.encrypt_str_unpadded(replacement).unwrap();
        println!("encrypted: {input} {pattern} {replacement}");
        assert_eq!(
            input.replace(pattern, replacement),
            client_key.decrypt_str(&server_key.replace_unpadded(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement
            ))
        );
    }

    #[test_matrix(
        ["this is old"],
        [("old","new"), ("is", "an"), ("x", "y")],
        1..=3
    )]
    fn test_replace_padded(input: &str, (pattern, replacement): (&str, &str), padding_len: usize) {
        replace_test_padded(input, (pattern, replacement), padding_len);
    }

    #[test_matrix(
        ["aaabaaab"],
        [("a", "c"), ("aa", "c"), ("aa", "cc"), ("aaa", "c")],
        1..=3
    )]
    fn test_replace_shrink_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        padding_len: usize,
    ) {
        replace_test_padded(input, (pattern, replacement), padding_len);
    }

    #[test_matrix(
        ["cabcab"],
        [("c", "aa"), ("cab", "")],
        1..=3
    )]
    fn test_replace_expand_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        padding_len: usize,
    ) {
        replace_test_padded(input, (pattern, replacement), padding_len);
    }

    #[test_matrix(
        ["banana"],
        [("ana", "anas")],
        1..=3
    )]
    fn test_replace_multi_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        padding_len: usize,
    ) {
        replace_test_padded(input, (pattern, replacement), padding_len);
    }

    #[test_matrix(
        [""],
        [("", "x"), ("a", "")],
        1..=3
    )]
    fn test_replace_empty_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        padding_len: usize,
    ) {
        replace_test_padded(input, (pattern, replacement), padding_len);
    }

    #[test_matrix(
        ["this is old"],
        [("old","new"), ("is", "an"), ("x", "y")]
    )]
    fn test_replace_unpadded(input: &str, (pattern, replacement): (&str, &str)) {
        replace_test_unpadded(input, (pattern, replacement));
    }

    #[test_matrix(
        [""],
        [("", "x"), ("a", "")]
    )]
    fn test_replace_empty_unpadded(input: &str, (pattern, replacement): (&str, &str)) {
        replace_test_unpadded(input, (pattern, replacement));
    }

    #[inline]
    fn replacen_test_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        n: usize,
        padding_len: usize,
    ) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_padded(input, padding_len).unwrap();
        let encrypted_n = client_key.encrypt_usize(n);
        println!("clear clear: {input} {pattern} {replacement} {padding_len} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen(&encrypted_str, pattern, replacement, n))
        );
        println!("clear encrypted: {input} {pattern} {replacement} {padding_len} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen(
                &encrypted_str,
                pattern,
                replacement,
                encrypted_n.clone()
            ))
        );
        let encrypted_pattern = client_key.encrypt_str_padded(pattern, padding_len).unwrap();
        let encrypted_replacement = client_key
            .encrypt_str_padded(replacement, padding_len)
            .unwrap();
        println!("encrypted clear: {input} {pattern} {replacement} {padding_len} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement,
                n,
            ))
        );
        println!("encrypted encrypted: {input} {pattern} {replacement} {padding_len} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement,
                encrypted_n
            ))
        );
    }

    #[test_matrix(
        ["foo foo 123 foo", "this is old"],
        [("foo", "new"), ("o", "a"), ("cookie monster", "little lambda")],
        [2, 3, 10],
        1..=3
    )]
    fn test_replacen_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        n: usize,
        padding_len: usize,
    ) {
        replacen_test_padded(input, (pattern, replacement), n, padding_len)
    }

    #[test_matrix(
        ["rust", ""],
        [("", "r")],
        0..=3,
        1..=3
    )]
    fn test_replacen_empty_padded(
        input: &str,
        (pattern, replacement): (&str, &str),
        n: usize,
        padding_len: usize,
    ) {
        replacen_test_padded(input, (pattern, replacement), n, padding_len);
        replacen_test_padded(input, (replacement, pattern), n, padding_len)
    }

    #[inline]
    fn replacen_test_unpadded(input: &str, (pattern, replacement): (&str, &str), n: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str_unpadded(input).unwrap();
        let encrypted_n = client_key.encrypt_usize(n);
        println!("clear clear: {input} {pattern} {replacement} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen_unpadded(
                &encrypted_str,
                pattern,
                replacement,
                n
            ))
        );
        println!("clear encrypted: {input} {pattern} {replacement} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen_unpadded(
                &encrypted_str,
                pattern,
                replacement,
                encrypted_n.clone()
            ))
        );
        let encrypted_pattern = client_key.encrypt_str_unpadded(pattern).unwrap();
        let encrypted_replacement = client_key.encrypt_str_unpadded(replacement).unwrap();
        println!("encrypted clear: {input} {pattern} {replacement} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen_unpadded(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement,
                n,
            ))
        );
        println!("encrypted encrypted: {input} {pattern} {replacement} {n}");
        assert_eq!(
            input.replacen(pattern, replacement, n),
            client_key.decrypt_str(&server_key.replacen_unpadded(
                &encrypted_str,
                &encrypted_pattern,
                &encrypted_replacement,
                encrypted_n
            ))
        );
    }

    #[test_matrix(
        ["foo foo 123 foo", "this is old"],
        [("foo", "new"), ("o", "a")],
        [2, 3, 10]
    )]
    fn test_replacen_unpadded(input: &str, (pattern, replacement): (&str, &str), n: usize) {
        replacen_test_unpadded(input, (pattern, replacement), n)
    }

    #[test_matrix(
        ["rust", ""],
        [("", "r")],
        0..=3
    )]
    fn test_replacen_empty_unpadded(input: &str, (pattern, replacement): (&str, &str), n: usize) {
        replacen_test_unpadded(input, (pattern, replacement), n);
        replacen_test_unpadded(input, (replacement, pattern), n)
    }
}
