#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test_matrix(
        [("Mary had a little lamb\nlittle lamb\nlittle lamb.", "\n"),
        ("Mary had a little lamb\nlittle lamb\nlittle lamb.\n", "\n"),
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
    fn test_split_inclusive((input, split_pattern): (&str, &str), padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        let encrypted_split_pattern = client_key
            .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.split_inclusive(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split_inclusive(&encrypted_str, split_pattern))
        );
        assert_eq!(
            input.split_inclusive(split_pattern).collect::<Vec<_>>(),
            client_key.decrypt_split(
                server_key.split_inclusive(&encrypted_str, &encrypted_split_pattern)
            )
        );
    }
}
