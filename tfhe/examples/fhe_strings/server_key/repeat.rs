#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        "abc",
        0..=4,
        1..=3
    )]
    fn test_repeat(input: &str, n: usize, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        // let encrypted_n = client_key.encrypt_usize(n);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();

        assert_eq!(
            input.repeat(n),
            client_key.decrypt_str(&server_key.repeat(&encrypted_str, n))
        );
        // assert_eq!(
        //     input.repeat(n),
        //     client_key.decrypt_str(&server_key.repeat(&encrypted_str, encrypted_n.clone()))
        // );
    }
}
