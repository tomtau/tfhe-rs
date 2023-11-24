#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[test_matrix(
        ["cfg", "cfg=foo", "cfg=foo=bar"],
        ["="],
        1..=3
    )]
    fn test_rsplit_once(input: &str, split_pattern: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
            .unwrap();

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let rsplit_once = input.rsplit_once(split_pattern);
        let expected = if let Some((x, y)) = rsplit_once {
            vec![x, y]
        } else {
            vec![input]
        };
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            expected,
            client_key.decrypt_split(server_key.rsplit_once(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            expected,
            client_key
                .decrypt_split(server_key.rsplit_once(&encrypted_str, &encrypted_split_pattern))
        );
    }
}
