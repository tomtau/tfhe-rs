#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        ["\n Hello\tworld\t\n"],
        1..=3
    )]
    fn test_trim_start(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let s = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.trim_start(),
            client_key.decrypt_str(&server_key.trim_start(&s))
        );
    }
}
