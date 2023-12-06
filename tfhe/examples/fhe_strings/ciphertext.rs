use rayon::iter::{IntoParallelIterator, ParallelExtend, ParallelIterator};
use tfhe::integer::RadixCiphertext;

use crate::client_key::ClientKey;

/// An alias for a FHE ciphertext representing 0 or 1
/// (to assist the refactoring to 0.5 which has a dedicated BooleanBlock type)
pub type FheBool = RadixCiphertext;
/// An alias for encrypted indices or other integer values
pub type FheUsize = RadixCiphertext;
/// An alias for encrypted options, i.e. a FHE bool and a FHE value
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
/// Currently, there are two variants for padded (the original bounty)
/// and the unpadded version (the bounty edit).
/// Both of these variants can be used in follow-up operations;
/// it'd also be possible to have an additional variant that represents
/// an encrypted string that's not properly padded (e.g. has a 0-characters in the beginning).
/// This variant wouldn't work with follow-up operations, but would be useful for
/// one-off operations (e.g. `strip_prefix` or `trim_start`) where it'd save some
/// operations that are done to properly shift the encrypted string.
#[derive(Clone)]
pub enum FheString {
    /// No 0 characters are present in the encrypted string.
    Unpadded(Vec<FheAsciiChar>),
    /// The encrypted string is padded with one or more 0 characters.
    Padded(Vec<FheAsciiChar>),
}

impl FheString {
    /// An internal helper that creates a new unpadded encrypted
    /// string without checking the input.
    pub(crate) fn new_unchecked_padded(enc_s: Vec<FheAsciiChar>) -> Self {
        Self::Padded(enc_s)
    }

    /// An internal helper that creates a new padded encrypted
    /// string without checking the input.
    pub(crate) fn new_unchecked_unpadded(enc_s: Vec<FheAsciiChar>) -> Self {
        Self::Unpadded(enc_s)
    }

    /// Creates a new unpadded encrypted string from a plain string slice.
    pub fn new(
        client_key: &ClientKey,
        s: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if !s.is_ascii() {
            return Err("content contains non-ascii characters".into());
        }
        if s.contains('\0') {
            return Err("content contains 0-character, use the padded version instead".into());
        }
        let enc_s: Vec<FheAsciiChar> = s
            .as_bytes()
            .into_par_iter()
            .map(|byte| client_key.encrypt_byte(*byte))
            .collect();
        Ok(Self::Unpadded(enc_s))
    }

    /// Creates a new padded encrypted string from a plain string slice.
    pub fn new_with_padding(
        client_key: &ClientKey,
        s: &str,
        padding_len: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if !s.is_ascii() {
            return Err("content contains non-ascii characters".into());
        }
        if padding_len == 0 {
            return Err(
                "padding length must be greater than 0 (for the unpadded version, use `new`)"
                    .into(),
            );
        }
        let mut enc_s: Vec<FheAsciiChar> = s
            .as_bytes()
            .into_par_iter()
            .map(|byte| client_key.encrypt_byte(*byte))
            .collect();
        enc_s.par_extend(
            (0..padding_len)
                .into_par_iter()
                .map(|_| client_key.encrypt_byte(0)),
        );
        Ok(Self::Padded(enc_s))
    }
}

impl AsRef<[FheAsciiChar]> for FheString {
    fn as_ref(&self) -> &[FheAsciiChar] {
        match self {
            Self::Unpadded(enc_s) => enc_s,
            Self::Padded(enc_s) => enc_s,
        }
    }
}

impl AsMut<[FheAsciiChar]> for FheString {
    fn as_mut(&mut self) -> &mut [FheAsciiChar] {
        match self {
            Self::Unpadded(enc_s) => enc_s,
            Self::Padded(enc_s) => enc_s,
        }
    }
}

/// Patterns used in string operations.
/// Possible extensions:
/// TODO: add a single plain `char` or `u8`
/// TODO: add a single encrypted `FheAsciiChar`
/// TODO: add a slice of plain `char`s or `u8`s
/// TODO: add a slice of encrypted `FheAsciiChar`s
/// TODO: add a closure that takes a `FheAsciiChar` and returns a `FheBool`
/// TODO: (encrypted closure as an encrypted bytecode plus an interpreter?)
/// TODO: `use std::str::pattern::Pattern;` use of unstable library feature 'pattern':
/// API not fully fleshed out and ready to be stabilized
/// see issue #27721 <https://github.com/rust-lang/rust/issues/27721> for more information
pub enum Pattern<'a> {
    Clear(&'a str),
    Encrypted(&'a FheString),
}

/// TODO: `TryFrom` and check it's ASCII-only?
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

/// A wrapper for a number to be used in some string operations.
pub enum Number {
    /// A plaintext number.
    Clear(usize),
    /// An encrypted number.
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
