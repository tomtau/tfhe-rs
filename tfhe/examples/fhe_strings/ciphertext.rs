use std::num::NonZeroUsize;

use tfhe::integer::RadixCiphertext;

use crate::client_key::ClientKey;

pub type FheBool = RadixCiphertext;
pub type FheUsize = RadixCiphertext;
pub type FheOption<T> = (FheBool, T);

/// A FHE wrapper for an ASCII character.
#[derive(Clone)]
pub struct FheAsciiChar(RadixCiphertext);

impl From<RadixCiphertext> for FheAsciiChar {
    fn from(c: RadixCiphertext) -> Self {
        Self(c)
    }
}

impl AsRef<RadixCiphertext> for FheAsciiChar {
    fn as_ref(&self) -> &RadixCiphertext {
        &self.0
    }
}

impl AsMut<RadixCiphertext> for FheAsciiChar {
    fn as_mut(&mut self) -> &mut RadixCiphertext {
        &mut self.0
    }
}

/// A FHE wrapper for a string of ASCII characters.
#[derive(Clone)]
pub struct FheString(Vec<FheAsciiChar>);

impl FheString {
    pub fn new(
        client_key: &ClientKey,
        s: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Self::new_with_padding(client_key, s, 1.try_into()?)
    }

    pub fn new_with_padding(
        client_key: &ClientKey,
        s: &str,
        padding_len: NonZeroUsize,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if !s.is_ascii() {
            return Err("content contains non-ascii characters".into());
        }
        let mut enc_s: Vec<FheAsciiChar> = s
            .as_bytes()
            .iter()
            .map(|byte| client_key.encrypt_byte(*byte))
            .collect();
        for _ in 0..padding_len.get() {
            enc_s.push(client_key.encrypt_byte(0));
        }
        Ok(Self(enc_s))
    }

    pub(crate) fn new_unchecked(enc_s: Vec<FheAsciiChar>) -> Self {
        Self(enc_s)
    }
}

impl AsRef<[FheAsciiChar]> for FheString {
    fn as_ref(&self) -> &[FheAsciiChar] {
        &self.0
    }
}

impl AsMut<[FheAsciiChar]> for FheString {
    fn as_mut(&mut self) -> &mut [FheAsciiChar] {
        &mut self.0
    }
}

pub enum Pattern<'a> {
    Clear(&'a str),
    Encrypted(&'a FheString),
}

impl<'a> From<&'a str> for Pattern<'a> {
    fn from(s: &'a str) -> Self {
        Self::Clear(s)
    }
}

impl<'a> From<&'a FheString> for Pattern<'a> {
    fn from(s: &'a FheString) -> Self {
        Self::Encrypted(s)
    }
}

pub enum Number {
    Clear(usize),
    Encrypted(RadixCiphertext),
}

impl From<usize> for Number {
    fn from(n: usize) -> Self {
        Self::Clear(n)
    }
}

impl From<RadixCiphertext> for Number {
    fn from(n: RadixCiphertext) -> Self {
        Self::Encrypted(n)
    }
}
