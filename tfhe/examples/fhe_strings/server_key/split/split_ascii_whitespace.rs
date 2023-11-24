#[cfg(test)]
mod test {
    use test_case::test_matrix;
    use tfhe::integer::gen_keys;
    use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    use crate::{client_key, server_key};

    #[inline]
    fn split_ascii_whitespace_test(input: &str, padding_len: usize) {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key
            .encrypt_str_padded(input, padding_len.try_into().unwrap())
            .unwrap();
        assert_eq!(
            input.split_ascii_whitespace().collect::<Vec<_>>(),
            client_key.decrypt_split(server_key.split_ascii_whitespace(&encrypted_str))
        );
    }

    #[test_matrix(
        ["A few words",
        " Mary   had\ta little  \n\t lamb",
        // "",
        "   ",
        "    a  b c"],
        1..=3
    )]
    fn test_split_ascii_whitespace(input: &str, padding_len: usize) {
        split_ascii_whitespace_test(input, padding_len)
    }

    #[test_matrix(
        [""],
        1..=3
    )]
    fn test_split_ascii_whitespace_empty(input: &str, padding_len: usize) {
        split_ascii_whitespace_test(input, padding_len)
    }
}
