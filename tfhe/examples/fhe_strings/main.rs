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
use tfhe::shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

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
        )
        .arg(
            Arg::new("input_string2")
                .short('s')
                .long("input-string2")
                .required(false)
                .help("The second string to use in some string operations")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("number")
                .short('n')
                .long("number")
                .required(false)
                .value_parser(clap::value_parser!(usize))
                .help("The number to use in some string operations")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("skip_encrypted_number")
                .short('e')
                .long("skip-encrypted-number")
                .required(false)
                .value_parser(clap::value_parser!(bool))
                .help("Skip the operations with the encrypted number (to save time)")
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
        let n = matches
            .get_one::<usize>("number")
            .map(|n| *n)
            .unwrap_or_else(|| 2);
        let skip_n = matches
            .get_one::<bool>("skip_encrypted_number")
            .map(|n| *n)
            .unwrap_or_else(|| true);
        info!("input_string: {input_string}");
        info!("pattern  (or the second string for comparisons): {pattern}");
        info!("input_string2: {input_string2}");
        info!("number: {n}");
        info!("skip_encrypted_number: {skip_n}");

        // let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::new(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let server_key = server_key::ServerKey::from(&client_key);

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
        let encrypted_n = client_key.encrypt_usize(n);

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
        let eq_ignore_case = server_key.eq_ignore_case(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_eq_ignore_case = client_key.decrypt_bool(&eq_ignore_case);
        info!("`eq_ignore_case` FHE: {decrypted_eq_ignore_case} (took {elapsed:?})");
        info!(
            "`eq_ignore_case` std: {}",
            input_string.eq_ignore_ascii_case(&input_string2)
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
        let repeat = server_key.repeat(&encrypted_str, n);
        let elapsed = now.elapsed();
        let decrypted_repeat_clear = client_key.decrypt_str(&repeat);
        info!("`repeat` FHE: {decrypted_repeat_clear} (took {elapsed:?}) (clear number)");
        if !skip_n {
            let now = Instant::now();
            let repeat = server_key.repeat(&encrypted_str, encrypted_n.clone());
            let elapsed = now.elapsed();
            let decrypted_repeat_encrypted = client_key.decrypt_str(&repeat);
            info!(
                "`repeat` FHE: {decrypted_repeat_encrypted} (took {elapsed:?}) (encrypted number)"
            );
        }
        info!("`repeat` std: {}", input_string.repeat(n));

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
        let replacen_clear_clear =
            server_key.replacen(&encrypted_str, pattern.as_str(), input_string2.as_str(), n);
        let elapsed = now.elapsed();
        let decrypted_replacen_clear_clear = client_key.decrypt_str(&replacen_clear_clear);
        info!("`replacen` FHE: {decrypted_replacen_clear_clear} (took {elapsed:?}) (clear pattern, clear number)");
        let now = Instant::now();
        let replacen_clear_encrypted = server_key.replacen(
            &encrypted_str,
            pattern.as_str(),
            input_string2.as_str(),
            encrypted_n.clone(),
        );
        let elapsed = now.elapsed();
        let decrypted_replacen_clear_encrypted = client_key.decrypt_str(&replacen_clear_encrypted);
        info!("`replacen` FHE: {decrypted_replacen_clear_encrypted} (took {elapsed:?}) (clear pattern, encrypted number)");
        let now = Instant::now();
        let replacen_encrypted_clear =
            server_key.replacen(&encrypted_str, &encrypted_pattern, &encrypted_str2, n);
        let elapsed = now.elapsed();
        let decrypted_replacen_encrypted_clear = client_key.decrypt_str(&replacen_encrypted_clear);
        info!(
                    "`replacen` FHE: {decrypted_replacen_encrypted_clear} (took {elapsed:?}) (encrypted pattern, clear number)"
                );
        let now = Instant::now();
        let replacen_encrypted_encrypted = server_key.replacen(
            &encrypted_str,
            &encrypted_pattern,
            &encrypted_str2,
            encrypted_n.clone(),
        );
        let elapsed = now.elapsed();
        let decrypted_replacen_encrypted_encrypted =
            client_key.decrypt_str(&replacen_encrypted_encrypted);
        info!(
                    "`replacen` FHE: {decrypted_replacen_encrypted_encrypted} (took {elapsed:?}) (encrypted pattern, encrypted number)"
                );
        info!(
            "`replacen` std: {}",
            input_string.replacen(pattern, input_string2.as_str(), n)
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
        let le = server_key.le(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_le = client_key.decrypt_bool(&le);
        info!("`le` FHE: {decrypted_le} (took {elapsed:?})");
        info!("`le` std: {}", input_string <= &input_string2);

        let now = Instant::now();
        let ge = server_key.ge(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_ge = client_key.decrypt_bool(&ge);
        info!("`ge` FHE: {decrypted_ge} (took {elapsed:?})");
        info!("`ge` std: {}", input_string >= &input_string2);

        let now = Instant::now();
        let eq = server_key.eq(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_eq = client_key.decrypt_bool(&eq);
        info!("`eq` FHE: {decrypted_eq} (took {elapsed:?})");
        info!("`eq` std: {}", input_string == &input_string2);

        let now = Instant::now();
        let ne = server_key.ne(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_ne = client_key.decrypt_bool(&ne);
        info!("`ne` FHE: {decrypted_ne} (took {elapsed:?})");
        info!("`ne` std: {}", input_string != &input_string2);

        let now = Instant::now();
        let concatted = server_key.concat(&encrypted_str, &encrypted_str2);
        let elapsed = now.elapsed();
        let decrypted_concatted = client_key.decrypt_str(&concatted);
        info!("`concat` FHE: {decrypted_concatted} (took {elapsed:?})");
        info!("`concat` std: {}", input_string.to_owned() + &input_string2);

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
        let rsplit = server_key.rsplit(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rsplit_clear = client_key.decrypt_split(rsplit);
        info!("`rsplit` FHE: {decrypted_rsplit_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let rsplit = server_key.rsplit(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rsplit_encrypted = client_key.decrypt_split(rsplit);
        info!(
            "`rsplit` FHE: {decrypted_rsplit_encrypted:?} (took {elapsed:?}) (encrypted pattern)"
        );
        info!(
            "`rsplit` std: {:?}",
            input_string.rsplit(pattern).collect::<Vec<_>>()
        );

        let now = Instant::now();
        let rsplit_once = server_key.rsplit_once(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rsplit_once_clear = client_key.decrypt_split(rsplit_once);
        info!(
            "`rsplit_once` FHE: {decrypted_rsplit_once_clear:?} (took {elapsed:?}) (clear pattern)"
        );
        let now = Instant::now();
        let rsplit_once = server_key.rsplit_once(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rsplit_once_encrypted = client_key.decrypt_split(rsplit_once);
        info!(
            "`rsplit_once` FHE: {decrypted_rsplit_once_encrypted:?} (took {elapsed:?}) (encrypted pattern)"
        );
        let original_rsplit_once = input_string.rsplit_once(pattern);
        let transformed_rsplit_once = if let Some((x, y)) = original_rsplit_once {
            vec![x, y]
        } else {
            vec![input_string.as_str()]
        };
        info!(
            "`rsplit_once` std: {:?} (original: {:?})",
            transformed_rsplit_once, original_rsplit_once
        );

        let now = Instant::now();
        let rsplitn = server_key.rsplitn(&encrypted_str, n, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rsplit_clear_clear = client_key.decrypt_split(rsplitn);
        info!("`rsplitn` FHE: {decrypted_rsplit_clear_clear:?} (took {elapsed:?}) (clear pattern, clear count)");
        let now = Instant::now();
        let rsplitn = server_key.rsplitn(&encrypted_str, encrypted_n.clone(), pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rsplit_clear_encrypted = client_key.decrypt_split(rsplitn);
        info!("`rsplitn` FHE: {decrypted_rsplit_clear_encrypted:?} (took {elapsed:?}) (clear pattern, encrypted count)");
        let now = Instant::now();
        let rsplitn = server_key.rsplitn(&encrypted_str, n, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rsplit_encrypted_clear = client_key.decrypt_split(rsplitn);
        info!("`rsplitn` FHE: {decrypted_rsplit_encrypted_clear:?} (took {elapsed:?}) (encrypted pattern, clear count)");
        let now = Instant::now();
        let rsplitn = server_key.rsplitn(&encrypted_str, encrypted_n.clone(), &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rsplit_encrypted_encrypted = client_key.decrypt_split(rsplitn);
        info!("`rsplitn` FHE: {decrypted_rsplit_encrypted_encrypted:?} (took {elapsed:?}) (encrypted pattern, encrypted count)");
        info!(
            "`rsplitn` std: {:?}",
            input_string.rsplitn(n, pattern).collect::<Vec<_>>()
        );

        let now = Instant::now();
        let rsplit_terminator = server_key.rsplit_terminator(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_rsplit_terminator_clear = client_key.decrypt_split(rsplit_terminator);
        info!("`rsplit_terminator` FHE: {decrypted_rsplit_terminator_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let rsplit_terminator = server_key.rsplit_terminator(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_rsplit_terminator_encrypted = client_key.decrypt_split(rsplit_terminator);
        info!(
            "`rsplit_terminator` FHE: {decrypted_rsplit_terminator_encrypted:?} (took {elapsed:?}) (encrypted pattern)"
        );
        info!(
            "`rsplit_terminator` std: {:?}",
            input_string.rsplit_terminator(pattern).collect::<Vec<_>>()
        );

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

        let now = Instant::now();
        let split_ascii_whitespace = server_key.split_ascii_whitespace(&encrypted_str);
        let elapsed = now.elapsed();
        let decrypted_split_ascii_whitespace_clear =
            client_key.decrypt_split(split_ascii_whitespace);
        info!("`split_ascii_whitespace` FHE: {decrypted_split_ascii_whitespace_clear:?} (took {elapsed:?})");
        info!(
            "`split_ascii_whitespace` std: {:?}",
            input_string.split_ascii_whitespace().collect::<Vec<_>>()
        );

        let now = Instant::now();
        let split_inclusive = server_key.split_inclusive(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_split_inclusive_clear = client_key.decrypt_split(split_inclusive);
        info!("`split_inclusive` FHE: {decrypted_split_inclusive_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let split_inclusive = server_key.split_inclusive(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_split_inclusive_encrypted = client_key.decrypt_split(split_inclusive);
        info!("`split_inclusive` FHE: {decrypted_split_inclusive_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!(
            "`split_inclusive` std: {:?}",
            input_string.split_inclusive(pattern).collect::<Vec<_>>()
        );

        let now = Instant::now();
        let split_terminator = server_key.split_terminator(&encrypted_str, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_split_terminator_clear = client_key.decrypt_split(split_terminator);
        info!("`split_terminator` FHE: {decrypted_split_terminator_clear:?} (took {elapsed:?}) (clear pattern)");
        let now = Instant::now();
        let split_terminator = server_key.split_terminator(&encrypted_str, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_split_terminator_encrypted = client_key.decrypt_split(split_terminator);
        info!("`split_terminator` FHE: {decrypted_split_terminator_encrypted:?} (took {elapsed:?}) (encrypted pattern)");
        info!(
            "`split_terminator` std: {:?}",
            input_string.split_terminator(pattern).collect::<Vec<_>>()
        );

        let now = Instant::now();
        let splitn = server_key.splitn(&encrypted_str, n, pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_splitn_clear_clear = client_key.decrypt_split(splitn);
        info!("`splitn` FHE: {decrypted_splitn_clear_clear:?} (took {elapsed:?}) (clear pattern, clear count)");
        let now = Instant::now();
        let splitn = server_key.splitn(&encrypted_str, encrypted_n.clone(), pattern.as_str());
        let elapsed = now.elapsed();
        let decrypted_splitn_clear_encrypted = client_key.decrypt_split(splitn);
        info!("`splitn` FHE: {decrypted_splitn_clear_encrypted:?} (took {elapsed:?}) (clear pattern, encrypted count)");
        let now = Instant::now();
        let splitn = server_key.splitn(&encrypted_str, n, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_splitn_encrypted_clear = client_key.decrypt_split(splitn);
        info!("`splitn` FHE: {decrypted_splitn_encrypted_clear:?} (took {elapsed:?}) (encrypted pattern, clear count)");
        let now = Instant::now();
        let splitn = server_key.splitn(&encrypted_str, encrypted_n, &encrypted_pattern);
        let elapsed = now.elapsed();
        let decrypted_splitn_encrypted_encrypted = client_key.decrypt_split(splitn);
        info!("`splitn` FHE: {decrypted_splitn_encrypted_encrypted:?} (took {elapsed:?}) (encrypted pattern, encrypted count)");
        info!(
            "`splitn` std: {:?}",
            input_string.splitn(n, pattern).collect::<Vec<_>>()
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

#[cfg(test)]
mod test {
    use tfhe::{integer::gen_keys, shortint::prelude::PARAM_MESSAGE_2_CARRY_2_KS_PBS};

    use crate::{client_key, server_key};

    #[test]
    fn test_contains() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "bananas";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            for pattern in ["nana", "apples"] {
                let encrypted_pattern = client_key
                    .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.contains(pattern),
                    client_key.decrypt_bool(&server_key.contains(&encrypted_str, pattern))
                );
                assert_eq!(
                    input.contains(pattern),
                    client_key
                        .decrypt_bool(&server_key.contains(&encrypted_str, &encrypted_pattern))
                );
            }
        }
    }

    #[test]
    fn test_ends_with() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "bananas";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            for pattern in ["anas", "nana", "ana"] {
                let encrypted_pattern = client_key
                    .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.ends_with(pattern),
                    client_key.decrypt_bool(&server_key.ends_with(&encrypted_str, pattern))
                );
                assert_eq!(
                    input.ends_with(pattern),
                    client_key
                        .decrypt_bool(&server_key.ends_with(&encrypted_str, &encrypted_pattern))
                );
            }
        }
    }

    #[test]
    fn test_eq_ignore_case() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "ferris";
        let input2 = "FERRIS";
        let encrypted_str2 = client_key.encrypt_str(input2).unwrap();
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            assert_eq!(
                input.eq_ignore_ascii_case(input2),
                client_key
                    .decrypt_bool(&server_key.eq_ignore_case(&encrypted_str, &encrypted_str2))
            );
        }
    }

    #[test]
    fn test_find() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "bananas";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            for pattern in ["a", "z"] {
                let encrypted_pattern = client_key
                    .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.find(pattern),
                    client_key.decrypt_option_usize(&server_key.find(&encrypted_str, pattern))
                );
                assert_eq!(
                    input.find(pattern),
                    client_key
                        .decrypt_option_usize(&server_key.find(&encrypted_str, &encrypted_pattern))
                );
            }
        }
    }

    #[test]
    fn test_is_empty() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "";
        let input2 = "not_empty";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            let encrypted_str2 = client_key
                .encrypt_str_padded(input2, padding_len.try_into().unwrap())
                .unwrap();

            assert_eq!(
                input.is_empty(),
                client_key.decrypt_bool(&server_key.is_empty(&encrypted_str))
            );
            assert_eq!(
                input2.is_empty(),
                client_key.decrypt_bool(&server_key.is_empty(&encrypted_str2))
            );
        }
    }

    #[test]
    fn test_len() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "foo";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();

            assert_eq!(
                input.len(),
                client_key.decrypt_usize(&server_key.len(&encrypted_str))
            );
        }
    }

    #[test]
    fn test_repeat() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "abc";
        for n in 0..=4 {
            // let encrypted_n = client_key.encrypt_usize(n);

            for padding_len in 1..=3 {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();

                assert_eq!(
                    input.repeat(n),
                    client_key.decrypt_str(&server_key.repeat(&encrypted_str, n))
                );
                // assert_eq!(
                //     input.repeat(n),
                //     client_key.decrypt_str(&server_key.repeat(&encrypted_str, encrypted_n.clone()))
                // );
            }
        }
    }

    #[test]
    fn test_replace() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            (
                "this is old",
                vec![("old", "new"), ("is", "an"), ("x", "y")],
            ),
            (
                "aaabaaab",
                vec![("a", "c"), ("aa", "c"), ("aa", "cc"), ("aaa", "c")],
            ),
            ("cabcab", vec![("c", "aa"), ("cab", "")]),
            ("banana", vec![("ana", "anas")]),
        ];
        for padding_len in 1..=3 {
            for (input, replacements) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                for (pattern, replacement) in replacements {
                    println!("clear: {input} {pattern} {replacement} {padding_len}");
                    assert_eq!(
                        input.replace(pattern, replacement),
                        client_key.decrypt_str(&server_key.replace(
                            &encrypted_str,
                            *pattern,
                            *replacement
                        ))
                    );
                    let encrypted_pattern = client_key
                        .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                        .unwrap();
                    let encrypted_replacement = client_key
                        .encrypt_str_padded(replacement, padding_len.try_into().unwrap())
                        .unwrap();
                    println!("encrypted: {input} {pattern} {replacement} {padding_len}");
                    assert_eq!(
                        input.replace(pattern, replacement),
                        client_key.decrypt_str(&server_key.replace(
                            &encrypted_str,
                            &encrypted_pattern,
                            &encrypted_replacement
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn test_replacen() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("foo foo 123 foo", vec![("foo", "new", 2), ("o", "a", 3)]),
            ("this is old", vec![("cookie monster", "little lamb", 10)]),
        ];
        for padding_len in 1..=3 {
            for (input, replacements) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                for (pattern, replacement, n) in replacements {
                    let encrypted_n = client_key.encrypt_usize(*n);
                    println!("clear clear: {input} {pattern} {replacement} {padding_len} {n}");
                    assert_eq!(
                        input.replacen(pattern, replacement, *n),
                        client_key.decrypt_str(&server_key.replacen(
                            &encrypted_str,
                            *pattern,
                            *replacement,
                            *n
                        ))
                    );
                    println!("clear encrypted: {input} {pattern} {replacement} {padding_len} {n}");
                    assert_eq!(
                        input.replacen(pattern, replacement, *n),
                        client_key.decrypt_str(&server_key.replacen(
                            &encrypted_str,
                            *pattern,
                            *replacement,
                            encrypted_n.clone()
                        ))
                    );
                    let encrypted_pattern = client_key
                        .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                        .unwrap();
                    let encrypted_replacement = client_key
                        .encrypt_str_padded(replacement, padding_len.try_into().unwrap())
                        .unwrap();
                    println!("encrypted clear: {input} {pattern} {replacement} {padding_len} {n}");
                    assert_eq!(
                        input.replacen(pattern, replacement, *n),
                        client_key.decrypt_str(&server_key.replacen(
                            &encrypted_str,
                            &encrypted_pattern,
                            &encrypted_replacement,
                            *n,
                        ))
                    );
                    println!(
                        "encrypted encrypted: {input} {pattern} {replacement} {padding_len} {n}"
                    );
                    assert_eq!(
                        input.replacen(pattern, replacement, *n),
                        client_key.decrypt_str(&server_key.replacen(
                            &encrypted_str,
                            *pattern,
                            *replacement,
                            encrypted_n
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn test_rfind() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "bananas";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            for pattern in ["a", "z"] {
                let encrypted_pattern = client_key
                    .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.rfind(pattern),
                    client_key.decrypt_option_usize(&server_key.rfind(&encrypted_str, pattern))
                );
                assert_eq!(
                    input.rfind(pattern),
                    client_key.decrypt_option_usize(
                        &server_key.rfind(&encrypted_str, &encrypted_pattern)
                    )
                );
            }
        }
    }

    #[test]
    fn test_rsplit() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", " "),
            ("", "X"),
            ("lionXXtigerXleo", "X"),
            ("lion::tiger::leo", "::"),
            ("||||a||b|c", "|"),
            ("(///)", "/"),
            ("010", "0"),
            ("rust", ""),
            ("    a  b c", " "),
            ("banana", "ana"),
            ("foo:bar", "foo:"),
            ("foo:bar", "bar"),
        ];
        for padding_len in 1..=3 {
            for (input, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                println!("clear: {input} {split_pattern} {padding_len}");
                assert_eq!(
                    input.rsplit(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.rsplit(&encrypted_str, *split_pattern))
                );
                println!("encrypted: {input} {split_pattern} {padding_len}");

                assert_eq!(
                    input.rsplit(split_pattern).collect::<Vec<_>>(),
                    client_key
                        .decrypt_split(server_key.rsplit(&encrypted_str, &encrypted_split_pattern))
                );
            }
        }
    }

    #[test]
    fn test_rsplit_once() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [(vec!["cfg", "cfg=foo", "cfg=foo=bar"], "=")];
        for padding_len in 1..=3 {
            for (input_strs, split_pattern) in &inputs {
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                for input in input_strs {
                    let encrypted_str = client_key
                        .encrypt_str_padded(input, padding_len.try_into().unwrap())
                        .unwrap();
                    let rsplit_once = input.rsplit_once(split_pattern);
                    let expected = if let Some((x, y)) = rsplit_once {
                        vec![x, y]
                    } else {
                        vec![*input]
                    };
                    println!("clear: {input} {split_pattern} {padding_len}");
                    assert_eq!(
                        expected,
                        client_key
                            .decrypt_split(server_key.rsplit_once(&encrypted_str, *split_pattern))
                    );
                    println!("encrypted: {input} {split_pattern} {padding_len}");

                    assert_eq!(
                        expected,
                        client_key.decrypt_split(
                            server_key.rsplit_once(&encrypted_str, &encrypted_split_pattern)
                        )
                    );
                }
            }
        }
    }

    #[test]
    fn test_rsplitn() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", 3, " "),
            ("", 3, "X"),
            ("lionXXtigerXleopard", 3, "X"),
            ("lion::tiger::leopard", 2, "::"),
        ];
        for padding_len in 1..=3 {
            for (input, n, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_n = client_key.encrypt_usize(*n);
                println!("clear clear: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.rsplitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.rsplitn(
                        &encrypted_str,
                        *n,
                        *split_pattern
                    ))
                );
                println!("clear encrypted: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.rsplitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.rsplitn(
                        &encrypted_str,
                        encrypted_n.clone(),
                        *split_pattern
                    ))
                );
                println!("encrypted clear: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.rsplitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.rsplitn(
                        &encrypted_str,
                        *n,
                        &encrypted_split_pattern
                    ))
                );
                println!("encrypted encrypted: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.rsplitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.rsplitn(
                        &encrypted_str,
                        encrypted_n,
                        &encrypted_split_pattern
                    ))
                );
            }
        }
    }

    #[test]
    fn test_rsplit_terminator() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", " "),
            ("", "X"),
            ("lionXXtigerXleo", "X"),
            ("lion::tiger::leo", "::"),
            ("||||a||b|c", "|"),
            ("(///)", "/"),
            ("010", "0"),
            ("rust", ""),
            ("    a  b c", " "),
            ("banana", "ana"),
            ("foo:bar", "foo:"),
            ("foo:bar", "bar"),
            ("A.B.", "."),
            ("A..B..", "."),
        ];
        for padding_len in 1..=3 {
            for (input, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                println!("clear: {input} {split_pattern} {padding_len}");
                assert_eq!(
                    input.rsplit_terminator(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(
                        server_key.rsplit_terminator(&encrypted_str, *split_pattern)
                    )
                );
                println!("encrypted: {input} {split_pattern} {padding_len}");

                assert_eq!(
                    input.rsplit_terminator(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(
                        server_key.rsplit_terminator(&encrypted_str, &encrypted_split_pattern)
                    )
                );
            }
        }
    }

    #[test]
    fn test_split() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", " "),
            ("", "X"),
            ("lionXXtigerXleo", "X"),
            ("lion::tiger::leo", "::"),
            ("||||a||b|c", "|"),
            ("(///)", "/"),
            ("010", "0"),
            ("rust", ""),
            ("    a  b c", " "),
            ("banana", "ana"),
            ("foo:bar", "foo:"),
            ("foo:bar", "bar"),
        ];
        for padding_len in 1..=3 {
            for (input, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                println!("clear: {input} {split_pattern} {padding_len}");
                assert_eq!(
                    input.split(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.split(&encrypted_str, *split_pattern))
                );
                println!("encrypted: {input} {split_pattern} {padding_len}");

                assert_eq!(
                    input.split(split_pattern).collect::<Vec<_>>(),
                    client_key
                        .decrypt_split(server_key.split(&encrypted_str, &encrypted_split_pattern))
                );
            }
        }
    }

    #[test]
    fn test_split_ascii_whitespace() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            "A few words",
            " Mary   had\ta little  \n\t lamb",
            "",
            "   ",
            "    a  b c",
        ];
        for padding_len in 1..=3 {
            for input in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                println!("clear: {input} {padding_len}");
                assert_eq!(
                    input.split_ascii_whitespace().collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.split_ascii_whitespace(&encrypted_str))
                );
            }
        }
    }

    #[test]
    fn test_split_inclusive() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb\nlittle lamb\nlittle lamb.", "\n"),
            ("Mary had a little lamb\nlittle lamb\nlittle lamb.\n", "\n"),
            ("", "X"),
            ("lionXXtigerXleo", "X"),
            ("lion::tiger::leo", "::"),
            ("||||a||b|c", "|"),
            ("(///)", "/"),
            ("010", "0"),
            ("rust", ""),
            ("    a  b c", " "),
            ("banana", "ana"),
            ("foo:bar", "foo:"),
            ("foo:bar", "bar"),
        ];
        for padding_len in 1..=3 {
            for (input, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.split_inclusive(split_pattern).collect::<Vec<_>>(),
                    client_key
                        .decrypt_split(server_key.split_inclusive(&encrypted_str, *split_pattern))
                );
                assert_eq!(
                    input.split_inclusive(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(
                        server_key.split_inclusive(&encrypted_str, &encrypted_split_pattern)
                    )
                );
            }
        }
    }

    #[test]
    fn test_split_terminator() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", " "),
            ("", "X"),
            ("lionXXtigerXleo", "X"),
            ("lion::tiger::leo", "::"),
            ("||||a||b|c", "|"),
            ("(///)", "/"),
            ("010", "0"),
            ("rust", ""),
            ("    a  b c", " "),
            ("banana", "ana"),
            ("foo:bar", "foo:"),
            ("foo:bar", "bar"),
            ("A.B.", "."),
            ("A..B..", "."),
        ];
        for padding_len in 1..=3 {
            for (input, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                println!("clear: {input} {split_pattern} {padding_len}");
                assert_eq!(
                    input.split_terminator(split_pattern).collect::<Vec<_>>(),
                    client_key
                        .decrypt_split(server_key.split_terminator(&encrypted_str, *split_pattern))
                );
                println!("encrypted: {input} {split_pattern} {padding_len}");

                assert_eq!(
                    input.split_terminator(split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(
                        server_key.split_terminator(&encrypted_str, &encrypted_split_pattern)
                    )
                );
            }
        }
    }

    #[test]
    fn test_splitn() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("Mary had a little lamb", 3, " "),
            ("", 3, "X"),
            ("lionXXtigerXleopard", 1, "X"),
            ("abcXdef", 1, "X"),
        ];
        for padding_len in 1..=3 {
            for (input, n, split_pattern) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_split_pattern = client_key
                    .encrypt_str_padded(split_pattern, padding_len.try_into().unwrap())
                    .unwrap();
                let encrypted_n = client_key.encrypt_usize(*n);
                println!("clear clear: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.splitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.splitn(&encrypted_str, *n, *split_pattern))
                );
                println!("clear encrypted: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.splitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.splitn(
                        &encrypted_str,
                        encrypted_n.clone(),
                        *split_pattern
                    ))
                );
                println!("encrypted clear: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.splitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.splitn(
                        &encrypted_str,
                        *n,
                        &encrypted_split_pattern
                    ))
                );
                println!("encrypted encrypted: {input} {split_pattern} {padding_len} {n}");
                assert_eq!(
                    input.splitn(*n, split_pattern).collect::<Vec<_>>(),
                    client_key.decrypt_split(server_key.splitn(
                        &encrypted_str,
                        encrypted_n,
                        &encrypted_split_pattern
                    ))
                );
            }
        }
    }

    #[test]
    fn test_starts_with() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input = "bananas";
        for padding_len in 1..=3 {
            let encrypted_str = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            for pattern in ["bana", "nana"] {
                let encrypted_pattern = client_key
                    .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.starts_with(pattern),
                    client_key.decrypt_bool(&server_key.starts_with(&encrypted_str, pattern))
                );
                assert_eq!(
                    input.starts_with(pattern),
                    client_key
                        .decrypt_bool(&server_key.starts_with(&encrypted_str, &encrypted_pattern))
                );
            }
        }
    }

    #[test]
    fn test_strip_prefix() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [("foo:bar", vec!["foo:", "bar"]), ("foofoo", vec!["foo"])];
        for padding_len in 1..=3 {
            for (input, patterns) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                for pattern in patterns {
                    assert_eq!(
                        input.strip_prefix(pattern),
                        client_key
                            .decrypt_option_str(&server_key.strip_prefix(&encrypted_str, *pattern))
                            .as_deref()
                    );
                    let encrypted_pattern = client_key
                        .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input.strip_prefix(pattern),
                        client_key
                            .decrypt_option_str(
                                &server_key.strip_prefix(&encrypted_str, &encrypted_pattern,)
                            )
                            .as_deref()
                    );
                }
            }
        }
    }

    #[test]
    fn test_strip_suffix() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = [
            ("foo:bar", vec!["foo:", "bar"]),
            ("foofoo", vec!["foo"]),
            ("banana", vec!["ana"]),
        ];
        for padding_len in 1..=3 {
            for (input, patterns) in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                for pattern in patterns {
                    assert_eq!(
                        input.strip_suffix(pattern),
                        client_key
                            .decrypt_option_str(&server_key.strip_suffix(&encrypted_str, *pattern))
                            .as_deref()
                    );
                    let encrypted_pattern = client_key
                        .encrypt_str_padded(pattern, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input.strip_suffix(pattern),
                        client_key
                            .decrypt_option_str(
                                &server_key.strip_suffix(&encrypted_str, &encrypted_pattern,)
                            )
                            .as_deref()
                    );
                }
            }
        }
    }

    #[test]
    fn test_to_lowercase() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = ["HELLO", "hello"];
        for padding_len in 1..=3 {
            for input in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.to_lowercase(),
                    client_key.decrypt_str(&server_key.to_lowercase(&encrypted_str))
                );
            }
        }
    }

    #[test]
    fn test_to_uppercase() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let inputs = ["HELLO", "hello"];
        for padding_len in 1..=3 {
            for input in &inputs {
                let encrypted_str = client_key
                    .encrypt_str_padded(input, padding_len.try_into().unwrap())
                    .unwrap();
                assert_eq!(
                    input.to_uppercase(),
                    client_key.decrypt_str(&server_key.to_uppercase(&encrypted_str))
                );
            }
        }
    }

    #[test]
    fn test_trim() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let input = "\n Hello\tworld\t\n";
        for padding_len in 1..=3 {
            let s = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            assert_eq!(input.trim(), client_key.decrypt_str(&server_key.trim(&s)));
        }
    }

    #[test]
    fn test_trim_end() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let input = "\n Hello\tworld\t\n";
        for padding_len in 1..=3 {
            let s = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            assert_eq!(
                input.trim_end(),
                client_key.decrypt_str(&server_key.trim_end(&s))
            );
        }
    }

    #[test]
    fn test_trim_start() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let input = "\n Hello\tworld\t\n";
        for padding_len in 1..=3 {
            let s = client_key
                .encrypt_str_padded(input, padding_len.try_into().unwrap())
                .unwrap();
            assert_eq!(
                input.trim_start(),
                client_key.decrypt_str(&server_key.trim_start(&s))
            );
        }
    }

    #[test]
    fn test_concat() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);

        let input_a = "hello";
        let input_b = "world";
        for padding_len in 1..=3 {
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

    #[test]
    fn test_ge() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let inputs = [
            ("A", vec!["B"]),
            ("bananas", vec!["ana", "apples", "ban", "bbn"]),
        ];
        for (input_a, inputs) in &inputs {
            for input_b in inputs {
                for padding_len in 1..=3 {
                    let s1 = client_key
                        .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
                        .unwrap();
                    let s2 = client_key
                        .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input_a >= input_b,
                        client_key.decrypt_bool(&server_key.ge(&s1, &s2))
                    );
                    assert_eq!(
                        input_a >= input_a,
                        client_key.decrypt_bool(&server_key.ge(&s1, &s1))
                    );
                    assert_eq!(
                        input_b >= input_a,
                        client_key.decrypt_bool(&server_key.ge(&s2, &s1))
                    );
                }
            }
        }
    }

    #[test]
    fn test_le() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let inputs = [
            ("A", vec!["B"]),
            ("bananas", vec!["ana", "apples", "ban", "bbn"]),
        ];
        for (input_a, inputs) in &inputs {
            for input_b in inputs {
                for padding_len in 1..=3 {
                    let s1 = client_key
                        .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
                        .unwrap();
                    let s2 = client_key
                        .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input_a <= input_b,
                        client_key.decrypt_bool(&server_key.le(&s1, &s2))
                    );
                    assert_eq!(
                        input_a <= input_a,
                        client_key.decrypt_bool(&server_key.le(&s1, &s1))
                    );
                    assert_eq!(
                        input_b <= input_a,
                        client_key.decrypt_bool(&server_key.le(&s2, &s1))
                    );
                }
            }
        }
    }

    #[test]
    fn test_ne() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let inputs = [
            ("A", vec!["B"]),
            ("bananas", vec!["ana", "apples", "ban", "bbn"]),
        ];
        for (input_a, inputs) in &inputs {
            for input_b in inputs {
                for padding_len in 1..=3 {
                    let s1 = client_key
                        .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
                        .unwrap();
                    let s2 = client_key
                        .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input_a != input_b,
                        client_key.decrypt_bool(&server_key.ne(&s1, &s2))
                    );
                    assert_eq!(
                        input_a != input_a,
                        client_key.decrypt_bool(&server_key.ne(&s1, &s1))
                    );
                    assert_eq!(
                        input_b != input_a,
                        client_key.decrypt_bool(&server_key.ne(&s2, &s1))
                    );
                }
            }
        }
    }

    #[test]
    fn test_eq() {
        let (ck, sk) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        let client_key = client_key::ClientKey::from(ck);
        let server_key = server_key::ServerKey::from(sk);
        let inputs = [
            ("A", vec!["B"]),
            ("bananas", vec!["ana", "apples", "ban", "bbn"]),
        ];
        for (input_a, inputs) in &inputs {
            for input_b in inputs {
                for padding_len in 1..=3 {
                    let s1 = client_key
                        .encrypt_str_padded(input_a, padding_len.try_into().unwrap())
                        .unwrap();
                    let s2 = client_key
                        .encrypt_str_padded(input_b, padding_len.try_into().unwrap())
                        .unwrap();
                    assert_eq!(
                        input_a == input_b,
                        client_key.decrypt_bool(&server_key.eq(&s1, &s2))
                    );
                    assert_eq!(
                        input_a == input_a,
                        client_key.decrypt_bool(&server_key.eq(&s1, &s1))
                    );
                    assert_eq!(
                        input_b == input_a,
                        client_key.decrypt_bool(&server_key.eq(&s2, &s1))
                    );
                }
            }
        }
    }
}
