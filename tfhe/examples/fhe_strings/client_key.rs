use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};
use tfhe::{
    integer::{gen_keys, ClientKey as IntegerClientKey},
    shortint::ShortintParameterSet,
};

use crate::{
    ciphertext::{FheAsciiChar, FheBool, FheOption, FheString, FheUsize},
    server_key::FheSplit,
};

#[derive(Serialize, Deserialize, Clone)]
pub struct ClientKey(IntegerClientKey);

pub(crate) const NUM_BLOCKS: usize = 4;

impl ClientKey {
    pub fn new<P>(params: P) -> Self
    where
        P: TryInto<ShortintParameterSet>,
        <P as TryInto<ShortintParameterSet>>::Error: std::fmt::Debug,
    {
        Self(gen_keys(params).0)
    }

    pub(crate) fn encrypt_byte(&self, byte: u8) -> FheAsciiChar {
        self.0.encrypt_radix(byte as u64, NUM_BLOCKS)
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

    pub fn decrypt_option_str(&self, size: &FheOption<FheString>) -> Option<String> {
        if self.decrypt_bool(&size.0) {
            Some(self.decrypt_str(&size.1))
        } else {
            None
        }
    }

    pub fn decrypt_split(&self, split: FheSplit) -> Vec<String> {
        let mut result = Vec::new();
        for split_item in split {
            if let Some(b) = split_item.valid_split {
                if !self.decrypt_bool(&b) {
                    continue;
                }
                for s in split_item.split_sequence {
                    if let Some(s) = self.decrypt_option_str(&s) {
                        result.push(s);
                    }
                }
                return result;
            } else {
                for s in split_item.split_sequence {
                    if let Some(s) = self.decrypt_option_str(&s) {
                        result.push(s);
                    }
                }
                return result;
            }
        }
        result
    }

    pub fn encrypt_str(
        &self,
        s: &str,
    ) -> Result<FheString, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new(self, s)
    }

    pub fn encrypt_str_padded(
        &self,
        s: &str,
        padding_len: NonZeroUsize,
    ) -> Result<FheString, Box<dyn std::error::Error + Sync + Send>> {
        FheString::new_with_padding(self, s, padding_len)
    }

    pub fn decrypt_str(&self, s: &FheString) -> String {
        String::from_iter(s.as_ref().iter().map_while(|byte| {
            let b: u64 = self.0.decrypt_radix(byte);
            if b > 0 && b < 255 {
                Some(b as u8 as char)
            } else {
                None
            }
        }))
    }
}

impl From<IntegerClientKey> for ClientKey {
    fn from(key: IntegerClientKey) -> Self {
        Self(key)
    }
}

impl AsRef<IntegerClientKey> for ClientKey {
    fn as_ref(&self) -> &IntegerClientKey {
        &self.0
    }
}
