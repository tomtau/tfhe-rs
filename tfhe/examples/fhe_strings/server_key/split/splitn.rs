#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn splitn_test((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_n = client_key.encrypt_usize(n);
        println!("clear clear: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(&encrypted_str, n, split_pattern))
        );
        println!("clear encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                encrypted_n.clone(),
                split_pattern
            ))
        );
        println!("encrypted clear: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                n,
                &encrypted_split_pattern
            ))
        );
        println!("encrypted encrypted: {input} {split_pattern} {padding_len} {n}");
        assert_eq!(
            input.splitn(n, split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.splitn(
                &encrypted_str,
                encrypted_n,
                &encrypted_split_pattern
            ))
        );
    }

    #[test_matrix(
        [("Mary had a little lamb", 3, " "),
        ("", 3, "X"),
        ("lionXXtigerXleopard", 1, "X"),
        ("abcXdef", 1, "X"),],
        1..=3
    )]
    fn test_splitn((input, n, split_pattern): (&str, usize, &str), padding_len: usize) {
        splitn_test((input, n, split_pattern), padding_len)
    }

    #[test_matrix(
        ["rust", ""],
        0..=3,
        1..=3
    )]
    fn test_splitn_empty(input: &str, n: usize, padding_len: usize) {
        splitn_test((input, n, ""), padding_len)
    }
}
