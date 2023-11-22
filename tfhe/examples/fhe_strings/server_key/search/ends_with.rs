#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        ["bananas"],
        ["anas", "nana", "ana"],
        1..=3
    )]
    fn test_ends_with(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_pattern = client_key
            .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, pattern))
        );
        assert_eq!(
            input.ends_with(pattern),
            client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, &encrypted_pattern))
        );
    }
}
