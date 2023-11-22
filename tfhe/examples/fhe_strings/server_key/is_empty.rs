#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        1..=3
    )]
    fn test_is_empty(padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "";
        let input2 = "not_empty";
        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_str2 = client_key
            .encrypt_str_padded(input2, padding_len.try_into().unwrap())
            .unwrap();

        assert_eq!(
            input.is_empty(),
            client_key.decrypt_bool(&server_key.is_empty(&encrypted_str))
        );
        assert_eq!(
            input2.is_empty(),
            client_key.decrypt_bool(&server_key.is_empty(&encrypted_str2))
        );
    }
}
