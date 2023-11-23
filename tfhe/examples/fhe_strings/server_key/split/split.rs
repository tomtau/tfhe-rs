#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[inline]
    fn split_test((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
            .unwrap();
        println!("clear: {input} {split_pattern} {padding_len}");
        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, split_pattern))
        );
        println!("encrypted: {input} {split_pattern} {padding_len}");

        assert_eq!(
            input.split(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split(&encrypted_str, &encrypted_split_pattern))
        );
    }

    #[test_matrix(
        [("Mary had a little lamb", " "),
        ("", "X"),
        ("lionXXtigerXleo", "X"),
        ("lion::tiger::leo", "::"),
        ("9999a99b9c", "9"),
        ("(///)", "/"),
        ("010", "0"),
        ("rust", ""),
        ("    a  b c", " "),
        ("banana", "ana"),
        ("foo:bar", "foo:"),
        ("foo:bar", "bar"),],
        1..=3
    )]
    fn test_split((input, split_pattern): (&str, &str), padding_len: usize) {
        split_test((input, split_pattern), padding_len)
    }

    #[test_matrix(
        1..=3
    )]
    fn test_split_empty(padding_len: usize) {
        split_test(("", ""), padding_len)
    }
}
