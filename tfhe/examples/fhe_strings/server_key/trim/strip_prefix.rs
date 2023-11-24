#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["foo9bar", "foofoo"],
        ["foo9", "bar", "foo"],
        1..=3
    )]
    fn test_strip_prefix(input: &str, pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, pattern))
                .as_deref()
        );
        let encrypted_pattern = client_key
            .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.strip_prefix(pattern),
            client_key
                .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, &encrypted_pattern,))
                .as_deref()
        );
    }
}
