use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelExtend,
    ParallelIterator,
};

use crate::ciphertext::{FheString, FheStringPadding, Padded, Unpadded};

use super::ServerKey;

impl ServerKey {
    /// Returns the concatenation of this encrypted string and another as a new [`FheString`]
    /// and is equivalent to the `+` operator.
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
    /// let s1 = client_key.encrypt_str("hello").unwrap();
    /// let s2 = client_key.encrypt_str("world").unwrap();
    /// assert_eq!(
    ///     "helloworld",
    ///     client_key.decrypt_str(&server_key.concat(&s1, &s2))
    /// );
    /// ```
    pub fn concat(
        &self,
        encrypted_str: &FheString<Padded>,
        other_encrypted_str: &FheString<Padded>,
    ) -> FheString<Padded> {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();

        if fst.len() < 2 {
            return other_encrypted_str.clone();
        } else if snd.len() < 2 {
            return encrypted_str.clone();
        }
        let fst_ended = fst[..fst.len() - 1]
            .iter()
            .map(|x| Some(self.0.scalar_eq_parallelized(x.as_ref(), 0)));
        let mut result = Vec::with_capacity(fst.len() + snd.len() - 1);
        result.par_extend(fst[..fst.len() - 1].par_iter().cloned());
        result.par_extend(snd.par_iter().cloned());
        // TODO: can the fold be parallelized? (unsure about the identity and associativity)
        FheString::new_unchecked(
            fst_ended
                .enumerate()
                .fold(
                    (result, None),
                    |(mut result, previous_ended), (i, ended)| {
                        let cond = self.and_true(
                            previous_ended
                                .as_ref()
                                .map(|x| self.0.bitnot_parallelized(x))
                                .as_ref(),
                            ended.as_ref(),
                        );
                        result[i..].par_iter_mut().enumerate().for_each(|(j, x)| {
                            if j < snd.len() {
                                *x = self
                                    .if_then_else(cond.as_ref(), false, snd[j].as_ref(), x.as_ref())
                                    .into();
                            } else {
                                *x = self
                                    .if_then_else(
                                        cond.as_ref(),
                                        false,
                                        &self.false_ct(),
                                        x.as_ref(),
                                    )
                                    .into();
                            }
                        });
                        (result, ended)
                    },
                )
                .0,
        )
    }

    pub fn concat_unpadded<P: FheStringPadding>(
        &self,
        encrypted_str: &FheString<Unpadded>,
        other_encrypted_str: &FheString<P>,
    ) -> FheString<P> {
        let fst = encrypted_str.as_ref();
        let snd = other_encrypted_str.as_ref();
        let mut result = Vec::with_capacity(fst.len() + snd.len());
        result.par_extend(fst.par_iter().cloned());
        result.par_extend(snd.par_iter().cloned());
        FheString::new_unchecked(result)
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["hello"],
        ["world"],
        1..=3
    )]
    fn test_concat(input_a: &str, input_b: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s1 = client_key.encrypt_str_padded(input_a, padding_len).unwrap();
        let s2 = client_key.encrypt_str_padded(input_b, padding_len).unwrap();
        assert_eq!(
            input_a.to_owned() + input_b,
            client_key.decrypt_str(&server_key.concat(&s1, &s2))
        );
    }
}
