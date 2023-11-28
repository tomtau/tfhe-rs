use serde::{Deserialize, Serialize};
use tfhe::integer::{gen_keys, ClientKey as IntegerClientKey};
use tfhe::shortint::ShortintParameterSet;

use crate::ciphertext::{
    FheAsciiChar, FheBool, FheOption, FheString, FheStringPadding, FheUsize, Padded, Unpadded,
};
use crate::server_key::{FhePatternLen, FheSplitResult};

pub(crate) const PRECISION_BITS: usize = 8;

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey(IntegerClientKey, usize);

impl ClientKey {
    pub fn new<P>(params: P) -> Self
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        let key = gen_keys(params).0;
        let num_blocks = PRECISION_BITS / key.parameters().message_modulus().0.ilog2() as usize;
        Self(key, num_blocks)
    }

    pub(crate) fn encrypt_byte(&self, byte: u8) -> FheAsciiChar {
        self.0.encrypt_radix(byte as u64, self.1).into()
    }

    pub fn encrypt_usize(&self, size: usize) -> FheUsize {
        self.0.encrypt_radix(size as u64, self.1)
    }

    pub fn decrypt_bool(&self, byte: &FheBool) -> bool {
        self.0.decrypt_radix::<u64>(byte) != 0
    }

    pub fn decrypt_usize(&self, size: &FheUsize) -> usize {
        self.0.decrypt_radix::<u64>(size) as usize // FIXME: 32-bit archs?
    }

    pub fn decrypt_option_usize(&self, size: &FheOption<FheUsize>) -> Option<usize> {
        if self.decrypt_bool(&size.0) {
            Some(self.decrypt_usize(&size.1))
        } else {
            None
        }
    }

    pub fn decrypt_option_str(&self, size: &FheOption<FheString<Padded>>) -> Option<String> {
        if self.decrypt_bool(&size.0) {
            Some(self.decrypt_str(&size.1))
        } else {
            None
        }
    }

    pub fn decrypt_split(&self, split: FheSplitResult) -> Vec<String> {
        let zero_count = split
            .zero_count()
            .map(|x| self.decrypt_bool(x))
            .unwrap_or(false);
        if zero_count {
            return vec![];
        }
        let include_empty = split.include_empty_matches().map(|x| match x {
            FhePatternLen::Plain(y) => *y,
            FhePatternLen::Encrypted(y) => self.decrypt_usize(y),
        });
        let reverse_result = split.reverse_results();
        let skip_terminator = split.skip_empty_terminator();
        let whitespace_skip = matches!(split, FheSplitResult::SplitAsciiWhitespace(_));
        let mut result = Vec::new();
        let mut current = "".to_string();
        let mut last_found = false;
        let mut split_iter = split.into_iter().enumerate();
        let mut any_non_zero = false;
        while let Some((i, (found, char))) = split_iter.next() {
            let char: u64 = self.0.decrypt_radix(char.as_ref());
            let found_dec = self.decrypt_bool(&found);
            any_non_zero |= char != 0;
            last_found = found_dec || (char == 0 && last_found);

            if found_dec {
                if char != 0 {
                    current.push(char as u8 as char);
                }
                if !current.is_empty() || include_empty.is_some() || (i == 0 && !whitespace_skip) {
                    result.push(current.clone());
                    current = "".to_string();
                }
                if let Some(l) = include_empty {
                    for _ in 0..l.saturating_sub(1) {
                        let _ = split_iter.next();
                    }
                }
            } else if char != 0 {
                current.push(char as u8 as char);
            }
        }
        if (((last_found && any_non_zero) || result.is_empty())
            && matches!(include_empty, Some(l) if l > 0))
            || !current.is_empty()
        {
            result.push(current);
        }
        if skip_terminator && result.last().map(|x| x.is_empty()).unwrap_or(false) {
            result.pop();
        }
        if reverse_result {
            result.reverse();
        }
        result
    }

    pub fn encrypt_str_unpadded(
        &self,
        s: &str,
    ) -> Result<FheString<Unpadded>, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new(self, s)
    }

    pub fn encrypt_str(
        &self,
        s: &str,
    ) -> Result<FheString<Padded>, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new_with_padding(self, s, 1) // FIXME: unpadded
    }

    pub fn encrypt_str_padded(
        &self,
        s: &str,
        padding_len: usize,
    ) -> Result<FheString<Padded>, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new_with_padding(self, s, padding_len)
    }

    pub fn decrypt_str<P: FheStringPadding>(&self, s: &FheString<P>) -> String {
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
