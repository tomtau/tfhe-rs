#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

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

        let s1 = client_key
            .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
            .unwrap();
        let s2 = client_key
            .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input_a.to_owned() + input_b,
            client_key.decrypt_str(&server_key.concat(&s1, &s2))
        );
    }
}
