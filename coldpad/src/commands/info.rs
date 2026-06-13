use std::path::PathBuf;

use crate::cli::Encoding;
use crate::encoding::decode_if_armored;
use crate::io::{read_file, read_hash_file};
use crate::key::{decode_key_file, key_matches_status};
use crate::output;
use crate::prompt::prompt_required_if_terminal;

pub fn run(
    file: Option<PathBuf>,
    encoding: Encoding,
    password: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = match file {
        Some(file) => file,
        None => PathBuf::from(prompt_required_if_terminal(
            "Ciphertext file: ",
            "no ciphertext file provided. Pass a .otp file as an argument",
        )?),
    };
    let raw_ciphertext = read_file(&file)?;
    let key_path = file.with_extension("otp.key");
    let raw_key = match std::fs::read(&key_path) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            output::warn(format!("{}  (missing)", key_path.display()));
            return Err(format!("missing key: expected {}", key_path.display()).into());
        }
        Err(e) => {
            return Err(format!("failed to read '{}': {e}", key_path.display()).into());
        }
    };

    let ciphertext = decode_if_armored(raw_ciphertext, encoding, "ciphertext")?;
    let key = decode_key_file(raw_key, encoding, password, password_file)?;

    let ct_size = ciphertext.len();
    let hash_path = file.with_extension("otp.sha256");
    let hash_data = read_hash_file(&hash_path)?;

    output::group_start("coldpad info");
    output::info(
        "file:          ",
        format!("{}  {} bytes", file.display(), ct_size),
    );

    if key.len() != ct_size {
        return Err("key size does not match ciphertext".into());
    }
    output::info(
        "key:           ",
        format!("{}  {} bytes  matches", key_path.display(), key.len()),
    );

    match &hash_data {
        Some(expected) => {
            let plaintext = coldpad_core::decrypt(&ciphertext, &key);
            if coldpad_core::hash::verify(&plaintext, expected) {
                output::info(
                    "hash:          ",
                    format!("{}  verified", hash_path.display()),
                );
            } else {
                return Err("ciphertext has been tampered with or wrong key".into());
            }
        }
        None => {
            output::warn(key_matches_status(&hash_path));
        }
    }

    if hash_data.is_some() {
        output::success("Integrity check passed");
    }
    output::group_end();
    Ok(())
}
