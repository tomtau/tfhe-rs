mod ciphertext;
mod client_key;
mod server_key;

use std::{
    io::{self, Error},
    time::Instant,
};

use clap::{Arg, ArgAction, Command};
use env_logger::Env;
use log::{error, info};
use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

fn main() -> io::Result<()> {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);
    let command = Command::new("Homomorphic string operations")
        .arg(
            Arg::new("input_string")
                .short('i')
                .long("input-string")
                .required(true)
                .help("The input string to encrypt and run string operations on")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("pattern")
                .short('p')
                .long("pattern")
                .required(true)
                .help("The string pattern to use in some string operations")
                .action(ArgAction::Set),
        );
    let matches = command.get_matches();
    if let (Some(input_string), Some(pattern)) = (
        matches.get_one::<String>("input_string"),
        matches.get_one::<String>("pattern"),
    ) {
        info!("input_string: {input_string}");
        info!("pattern: {pattern}");

        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let encrypted_str = client_key.encrypt_str(&input_string).map_err(|e| {
            error!("Failed to encrypt input string: {e}");
            Error::new(io::ErrorKind::Other, e)
        })?;
        let encrypted_pattern = client_key.encrypt_str(&pattern).map_err(|e| {
            error!("Failed to encrypt input pattern: {e}");
            Error::new(io::ErrorKind::Other, e)
        })?;

        let now = Instant::now();
        let is_empty = server_key.is_empty(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_is_empty = client_key.decrypt_bool(&is_empty);
        info!("`is_empty` FHE: {decrypted_is_empty} (took {elapsed:?})");
        info!("`is_empty` std: {}", input_string.is_empty());

        let now = Instant::now();
        let len = server_key.len(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_len = client_key.decrypt_usize(&len);
        info!("`len` FHE: {decrypted_len} (took {elapsed:?})");
        info!("`len` std: {}", input_string.len());

        let now = Instant::now();
        let lowercase = server_key.to_lowercase(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_lowercase = client_key.decrypt_str(&lowercase);
        info!("`to_lowercase` FHE: {decrypted_lowercase} (took {elapsed:?})");
        info!("`to_lowercase` std: {}", input_string.to_lowercase());

        let now = Instant::now();
        let uppercase = server_key.to_uppercase(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_uppercase = client_key.decrypt_str(&uppercase);
        info!("`to_uppercase` FHE: {decrypted_uppercase} (took {elapsed:?})");
        info!("`to_uppercase` std: {}", input_string.to_uppercase());

        let now = Instant::now();
        let starts_with_clear = server_key.starts_with(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_starts_with_clear = client_key.decrypt_bool(&starts_with_clear);
        info!(
            "`starts_with` FHE: {decrypted_starts_with_clear} (took {elapsed:?}) (clear pattern)"
        );
        let now = Instant::now();
        let starts_with_encrypted = server_key.starts_with(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_starts_with_encrypted = client_key.decrypt_bool(&starts_with_encrypted);
        info!("`starts_with` FHE: {decrypted_starts_with_encrypted} (took {elapsed:?}) (encrypted pattern)");
        info!("`starts_with` std: {}", input_string.starts_with(pattern));

        Ok(())
    } else {
        error!("Missing required arguments");
        Err(Error::new(
            io::ErrorKind::Other,
            "Missing required arguments",
        ))
    }
}
