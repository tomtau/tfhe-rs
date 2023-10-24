mod ciphertext;
mod client_key;
mod scan;
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
        let input_string2 = matches
            .get_one::<String>("input_string2")
            .map(|s| s.to_owned())
            .unwrap_or_else(|| "".to_string());
        info!("input_string: {input_string}");
        info!("pattern  (or the second string for comparisons): {pattern}");
        info!("input_string2: {input_string2}");

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
        let encrypted_str2 = client_key
            .encrypt_str_padded(&input_string2, 2usize.try_into().unwrap())
            .map_err(|e| {
                error!("Failed to encrypt input string2: {e}");
                Error::new(io::ErrorKind::Other, e)
            })?;

        let now = Instant::now();
        let contains = server_key.contains(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_contains_clear = client_key.decrypt_bool(&contains);
        info!("`contains` FHE: {decrypted_contains_clear} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let contains = server_key.contains(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_contains_encrypted = client_key.decrypt_bool(&contains);
        info!(
            "`contains` FHE: {decrypted_contains_encrypted} (took {elapsed:?}) (encrypted pattern)"
        );
        info!(
            "`contains` std: {}",
            input_string.contains(pattern.as_str())
        );

        let now = Instant::now();
        let ends_with = server_key.ends_with(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_ends_with_clear = client_key.decrypt_bool(&ends_with);
        info!("`ends_with` FHE: {decrypted_ends_with_clear} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let contains = server_key.ends_with(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_ends_with_encrypted = client_key.decrypt_bool(&contains);
        info!(
            "`ends_with` FHE: {decrypted_ends_with_encrypted} (took {elapsed:?}) (encrypted pattern)"
        );
        info!(
            "`ends_with` std: {}",
            input_string.ends_with(pattern.as_str())
        );

        let now = Instant::now();
        let find = server_key.find(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_find_clear = client_key.decrypt_option_usize(&find);
        info!("`find` FHE: {decrypted_find_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let find = server_key.find(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_find_encrypted = client_key.decrypt_option_usize(&find);
        info!("`find` FHE: {decrypted_find_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!("`find` std: {:?}", input_string.find(pattern.as_str()));

        let now = Instant::now();
        let eq_ignore_case = server_key.eq_ignore_case(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_eq_ignore_case = client_key.decrypt_bool(&eq_ignore_case);
        info!("`eq_ignore_case` FHE: {decrypted_eq_ignore_case} (took {elapsed:?})");
        info!(
            "`eq_ignore_case` std: {}",
            input_string.eq_ignore_ascii_case(&pattern)
        );

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
        let replace_clear =
            server_key.replace(&encrypted_str, pattern.as_str(), input_string2.as_str());
        let elapsed = now.elapsed();
        let decrypted_replace_clear = client_key.decrypt_str(&replace_clear);
        info!("`replace` FHE: {decrypted_replace_clear} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let replace_encrypted =
            server_key.replace(&encrypted_str, &encrypted_pattern, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_replace_encrypted = client_key.decrypt_str(&replace_encrypted);
        info!(
            "`replace` FHE: {decrypted_replace_encrypted} (took {elapsed:?}) (encrypted pattern)"
        );
        info!(
            "`replace` std: {}",
            input_string.replace(pattern, input_string2.as_str())
        );

        let now = Instant::now();
        let rfind = server_key.rfind(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rfind_clear = client_key.decrypt_option_usize(&rfind);
        info!("`rfind` FHE: {decrypted_rfind_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let rfind = server_key.rfind(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rfind_encrypted = client_key.decrypt_option_usize(&rfind);
        info!("`rfind` FHE: {decrypted_rfind_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!("`rfind` std: {:?}", input_string.rfind(pattern.as_str()));

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

        let now = Instant::now();
        let le = server_key.le(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_le = client_key.decrypt_bool(&le);
        info!("`le` FHE: {decrypted_le} (took {elapsed:?})");
        info!("`le` std: {}", input_string <= pattern);

        let now = Instant::now();
        let ge = server_key.ge(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_ge = client_key.decrypt_bool(&ge);
        info!("`ge` FHE: {decrypted_ge} (took {elapsed:?})");
        info!("`ge` std: {}", input_string >= pattern);

        let now = Instant::now();
        let eq = server_key.eq(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_eq = client_key.decrypt_bool(&eq);
        info!("`eq` FHE: {decrypted_eq} (took {elapsed:?})");
        info!("`eq` std: {}", input_string == pattern);

        let now = Instant::now();
        let ne = server_key.ne(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_ne = client_key.decrypt_bool(&ne);
        info!("`ne` FHE: {decrypted_ne} (took {elapsed:?})");
        info!("`ne` std: {}", input_string != pattern);

        let now = Instant::now();
        let concatted = server_key.concat(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_concatted = client_key.decrypt_str(&concatted);
        info!("`concat` FHE: {decrypted_concatted} (took {elapsed:?})");
        info!("`concat` std: {}", input_string.to_owned() + pattern);

        let now = Instant::now();
        let strip_prefix = server_key.strip_prefix(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_strip_prefix_clear = client_key.decrypt_option_str(&strip_prefix);
        info!("`strip_prefix` FHE: {decrypted_strip_prefix_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let strip_prefix = server_key.strip_prefix(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_strip_prefix_encrypted = client_key.decrypt_option_str(&strip_prefix);
        info!("`strip_prefix` FHE: {decrypted_strip_prefix_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!(
            "`strip_prefix` std: {:?}",
            input_string.strip_prefix(pattern.as_str())
        );

        let now = Instant::now();
        let strip_suffix = server_key.strip_suffix(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_strip_suffix_clear = client_key.decrypt_option_str(&strip_suffix);
        info!("`strip_suffix` FHE: {decrypted_strip_suffix_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let strip_suffix = server_key.strip_suffix(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_strip_suffix_encrypted = client_key.decrypt_option_str(&strip_suffix);
        info!("`strip_suffix` FHE: {decrypted_strip_suffix_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!(
            "`strip_suffix` std: {:?}",
            input_string.strip_suffix(pattern.as_str())
        );

        let now = Instant::now();
        let trimmed = server_key.trim(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_trimmed = client_key.decrypt_str(&trimmed);
        info!("`trim` FHE: `{decrypted_trimmed}` (took {elapsed:?})");
        info!("`trim` std: `{}`", input_string.trim());

        let now = Instant::now();
        let end_trimmed = server_key.trim_end(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_end_trimmed = client_key.decrypt_str(&end_trimmed);
        info!("`trim_end` FHE: `{decrypted_end_trimmed}` (took {elapsed:?})");
        info!("`trim_end` std: `{}`", input_string.trim_end());

        let now = Instant::now();
        let start_trimmed = server_key.trim_start(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_start_trimmed = client_key.decrypt_str(&start_trimmed);
        info!("`trim_start` FHE: `{decrypted_start_trimmed}` (took {elapsed:?})");
        info!("`trim_start` std: `{}`", input_string.trim_start());

        let now = Instant::now();
        let split = server_key.split(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_split_clear = client_key.decrypt_split(split);
        info!("`split` FHE: {decrypted_split_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let split = server_key.split(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_split_encrypted = client_key.decrypt_split(split);
        info!("`split` FHE: {decrypted_split_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!(
            "`split` std: {:?}",
            input_string.split(pattern).collect::<Vec<_>>()
        );

        Ok(())
    } else {
        error!("Missing required arguments");
        Err(Error::new(
            io::ErrorKind::Other,
            "Missing required arguments",
        ))
    }
}
