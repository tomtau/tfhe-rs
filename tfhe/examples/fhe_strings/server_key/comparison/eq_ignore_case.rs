#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        "ferris",
        "FERRIS",
        1..=3
    )]
    fn test_eq_ignore_case(input1: &str, input2: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str2 = client_key.encrypt_str(input2).unwrap();
        let encrypted_str = client_key
            .encrypt_str_padded(input1, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input1.eq_ignore_ascii_case(input2),
            client_key.decrypt_bool(&server_key.eq_ignore_case(&encrypted_str, &encrypted_str2))
        );
    }
}
