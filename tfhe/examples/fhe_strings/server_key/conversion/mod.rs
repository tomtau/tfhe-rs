use crate::ciphertext::FheAsciiChar;

use super::ServerKey;

mod to_lower;
mod to_upper;

impl ServerKey {
    const ASCII_CASE_SHIFT: u64 = 32;

    /// A helper to convert the given encrypted character to lowercase.
    #[inline]
    pub(super) fn char_to_lower(&self, c: &FheAsciiChar) -> FheAsciiChar {
        // 'A' == 65, 'Z' == 90
        let (is_upper, converted) = rayon::join(
            || self.check_scalar_range(c, 65, 90),
            || {
                self.0
                    .scalar_add_parallelized(c.as_ref(), ServerKey::ASCII_CASE_SHIFT)
            },
        );
        // (is_upper & converted) | (!is_upper & x)
        self.0
            .if_then_else_parallelized(&is_upper, &converted, c.as_ref())
            .into()
        // This could also be done as x + (is_upper*32)
    }
}
