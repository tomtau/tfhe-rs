use std::{marker::PhantomData, num::NonZeroUsize};

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

#[derive(Clone)]
pub struct Unpadded;
#[derive(Clone)]
pub struct Padded;
pub trait FheStringPadding {}
impl FheStringPadding for Unpadded {}
impl FheStringPadding for Padded {}

/// A FHE wrapper for a string of ASCII characters.
#[derive(Clone)]
pub struct FheString<P: FheStringPadding>(Vec<FheAsciiChar>, PhantomData<P>);

impl FheString<Padded> {
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
        Ok(Self(enc_s, PhantomData {}))
    }

    pub(crate) fn new_unchecked(enc_s: Vec<FheAsciiChar>) -> Self {
        Self(enc_s, PhantomData {})
    }
}

impl<P: FheStringPadding> AsRef<[FheAsciiChar]> for FheString<P> {
    fn as_ref(&self) -> &[FheAsciiChar] {
        &self.0
    }
}

impl<P: FheStringPadding> AsMut<[FheAsciiChar]> for FheString<P> {
    fn as_mut(&mut self) -> &mut [FheAsciiChar] {
        &mut self.0
    }
}

pub enum Pattern<'a, P: FheStringPadding> {
    Clear(&'a str),
    Encrypted(&'a FheString<P>),
}

impl<'a, P: FheStringPadding> From<&'a str> for Pattern<'a, P> {
    fn from(s: &'a str) -> Self {
        Self::Clear(s)
    }
}

impl<'a, P: FheStringPadding> From<&'a FheString<P>> for Pattern<'a, P> {
    fn from(s: &'a FheString<P>) -> Self {
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
