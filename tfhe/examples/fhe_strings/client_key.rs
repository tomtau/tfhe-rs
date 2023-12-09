use serde::{Deserialize, Serialize};
use tfhe::integer::{gen_keys, ClientKey as IntegerClientKey};
use tfhe::shortint::ShortintParameterSet;

use crate::ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, FheUsize};
use crate::server_key::{FhePatternLen, FheSplitResult};

/// Number of bits of precision, used to determine the number of blocks
pub(crate) const PRECISION_BITS: usize = 8;

/// A wrapper around the TFHE integer client key and the number of blocks
#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey(IntegerClientKey, usize);

impl ClientKey {
    /// Create a new client key from the given shortint parameters
    pub fn new<P>(params: P) -> Self
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        let key = gen_keys(params).0;
        let num_blocks = PRECISION_BITS / key.parameters().message_modulus().0.ilog2() as usize;
        Self(key, num_blocks)
    }

    /// An internal helper to encrypt a single byte
    pub(crate) fn encrypt_byte(&self, byte: u8) -> FheAsciiChar {
        self.0.encrypt_radix(byte as u64, self.1).into()
    }

    /// Encrypts a single number
    pub fn encrypt_usize(&self, size: usize) -> FheUsize {
        self.0.encrypt_radix(size as u64, self.1)
    }

    /// Decrypts a single boolean (encrypted 0 or 1)
    pub fn decrypt_bool(&self, byte: &FheBool) -> bool {
        self.0.decrypt_radix::<u64>(byte) != 0
    }

    /// Decrypts a single number
    pub fn decrypt_usize(&self, size: &FheUsize) -> usize {
        self.0.decrypt_radix::<u64>(size) as usize // FIXME: 32-bit archs?
    }

    /// Decrypts an encrypted option with an encrypted usize payload
    pub fn decrypt_option_usize(&self, size: &FheOption<FheUsize>) -> Option<usize> {
        if self.decrypt_bool(&size.0) {
            Some(self.decrypt_usize(&size.1))
        } else {
            None
        }
    }

    /// Decrypts an encrypted option with an encrypted string payload
    pub fn decrypt_option_str(&self, size: &FheOption<FheString>) -> Option<String> {
        if self.decrypt_bool(&size.0) {
            Some(self.decrypt_str(&size.1))
        } else {
            None
        }
    }

    /// Decrypts a result of a split operation and returns the constructed decrypted
    /// substrings collected in a vector.
    /// See [`FheSplitResult`] for more information.
    pub fn decrypt_split(&self, split: FheSplitResult) -> Vec<String> {
        let zero_count = split
            .zero_count()
            .map(|x| self.decrypt_bool(x))
            .unwrap_or(false);
        if zero_count {
            return vec![];
        }
        let include_empty_prefix = split.include_empty_prefix().map(|x| match &x {
            FhePatternLen::Plain(y) => *y,
            FhePatternLen::Encrypted(y) => self.decrypt_usize(y),
        });
        let include_empty = split.include_empty_matches().map(|x| match &x.0 {
            FhePatternLen::Plain(y) => *y,
            FhePatternLen::Encrypted(y) => self.decrypt_usize(y),
        });
        let is_right_match_empty = split.is_right_match_empty();
        let end_len = split.include_empty_matches().map(|x| match &x.1 {
            FhePatternLen::Plain(y) => *y,
            FhePatternLen::Encrypted(y) => self.decrypt_usize(y),
        });
        let end_len_match = include_empty.and_then(|orig_len| {
            let adjust_len = std::cmp::max(orig_len, 1);
            end_len.map(|x| x.saturating_sub(adjust_len))
        });
        let skip_terminator = split.skip_empty_terminator();

        if let (Some(pat), Some(end_l)) = (include_empty, end_len) {
            if pat > end_l {
                let substr = String::from_iter(split.clone().filter_map(|x| {
                    let char: u64 = self.0.decrypt_radix(x.1.as_ref());
                    if char == 0 {
                        None
                    } else {
                        Some(char as u8 as char)
                    }
                }));
                if end_l > 0 || !skip_terminator {
                    return vec![substr];
                } else {
                    return vec![];
                }
            }
        }
        let reverse_result = split.reverse_results();
        let whitespace_skip = matches!(split, FheSplitResult::SplitAsciiWhitespace(_));
        let mut result = Vec::new();
        let mut current = "".to_string();
        let mut last_found = false;

        let mut split_iter = split.into_iter().enumerate();

        while let Some((i, (found, char))) = split_iter.next() {
            let char: u64 = self.0.decrypt_radix(char.as_ref());
            let found_dec = self.decrypt_bool(&found);
            if found_dec && i == 0 && !whitespace_skip {
                match include_empty_prefix {
                    Some(l) if l > 0 => {
                        current.push(char as u8 as char);
                        for _ in 0..l.saturating_sub(1) {
                            let (_, (_, char)) = split_iter.next().unwrap();
                            let char: u64 = self.0.decrypt_radix(char.as_ref());
                            current.push(char as u8 as char);
                        }
                    }
                    _ => {}
                }

                result.push(current.clone());
                current = "".to_string();
            } else if found_dec && i != 0 {
                match include_empty_prefix {
                    Some(l) if l > 0 => {
                        current.push(char as u8 as char);
                        for _ in 0..l.saturating_sub(1) {
                            let (_, (_, char)) = split_iter.next().unwrap();
                            let char: u64 = self.0.decrypt_radix(char.as_ref());
                            current.push(char as u8 as char);
                        }
                    }
                    _ => {}
                }

                if !current.is_empty() || !whitespace_skip {
                    result.push(current.clone());
                }
                current = "".to_string();
                last_found |= found_dec
                    && (Some(i) == end_len_match
                        || (Some(i - 1) == end_len_match
                            && is_right_match_empty
                            && matches!(include_empty, Some(0))));
            }
            if char != 0 && (matches!(include_empty_prefix, None | Some(0)) || !found_dec) {
                current.push(char as u8 as char);
            }
        }

        if !current.is_empty()
            || current.is_empty()
                && last_found
                && !skip_terminator
                && !whitespace_skip
                && include_empty.is_some()
        {
            result.push(current);
        }
        if reverse_result {
            result.reverse();
        }
        result
    }

    /// Encrypts a string with no padding
    pub fn encrypt_str(
        &self,
        s: &str,
    ) -> Result<FheString, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new(self, s)
    }

    /// Encrypts a string with a specified padding
    pub fn encrypt_str_padded(
        &self,
        s: &str,
        padding_len: usize,
    ) -> Result<FheString, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new_with_padding(self, s, padding_len)
    }

    /// Decrypts an encrypted string
    pub fn decrypt_str(&self, s: &FheString) -> String {
        String::from_iter(s.as_ref().iter().map_while(|byte| {
            let b: u64 = self.0.decrypt_radix(byte.as_ref());
            if b > 0 && b <= 255 {
                Some(b as u8 as char)
            } else {
                None
            }
        }))
    }
}

impl From<IntegerClientKey> for ClientKey {
    fn from(key: IntegerClientKey) -> Self {
        let num_blocks = PRECISION_BITS / key.parameters().message_modulus().0.ilog2() as usize;
        Self(key, num_blocks)
    }
}

impl AsRef<IntegerClientKey> for ClientKey {
    fn as_ref(&self) -> &IntegerClientKey {
        &self.0
    }
}
