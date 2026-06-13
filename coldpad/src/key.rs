use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::Encoding;
use crate::encoding::decode_if_armored;
use crate::io::read_hash_file;
use crate::output;
use crate::terminal::{ansi, color};

pub fn resolve_password(
    password: Option<String>,
    password_file: Option<PathBuf>,
    prompt: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(pw) = password {
        return Ok(pw);
    }
    if let Ok(pw) = std::env::var("COLDPAD_PASSWORD") {
        return Ok(pw);
    }
    if let Some(path) = password_file {
        let contents = std::fs::read_to_string(path)?;
        return Ok(contents.lines().next().unwrap_or("").to_string());
    }
    if io::stderr().is_terminal() {
        Ok(rpassword::prompt_password(prompt)?)
    } else {
        Err("password required for wrapped key".into())
    }
}

pub fn decode_key_file(
    raw_key: Vec<u8>,
    encoding: Encoding,
    password: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if coldpad_core::wrap::is_wrapped_key(&raw_key) {
        let password = resolve_password(password, password_file, "Key password: ")?;
        coldpad_core::wrap::unwrap_key(&raw_key, &password)
            .map_err(|e| format!("failed to unwrap key: {e}").into())
    } else {
        decode_if_armored(raw_key, encoding, "key")
    }
}

pub fn default_keygen_name() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    PathBuf::from(format!("key_{nanos}.key"))
}

pub fn encrypt_stem(file: Option<&Path>, output: Option<&str>) -> String {
    output.map(str::to_string).unwrap_or_else(|| {
        file.and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| crate::io::DEFAULT_STEM.to_string())
    })
}

pub fn planned_encrypt_paths(stem: &str, hash: bool) -> Vec<PathBuf> {
    let cipher_path = PathBuf::from(format!("{stem}.otp"));
    let key_path = PathBuf::from(format!("{stem}.otp.key"));
    let mut paths = vec![cipher_path.clone(), key_path];
    if hash {
        paths.push(cipher_path.with_extension("otp.sha256"));
    }
    paths
}

pub fn verify_decryption(
    ciphertext: &[u8],
    key: &[u8],
    plaintext: &[u8],
    file: &Path,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_path = file.with_extension("otp.sha256");

    match read_hash_file(&hash_path)? {
        Some(expected) => {
            if coldpad_core::hash::verify(plaintext, &expected) {
                if verbose {
                    output::info("integrity:     ", "hash verified");
                }
                Ok(())
            } else {
                Err("ciphertext has been tampered with or wrong key".into())
            }
        }
        None => {
            if key.len() != ciphertext.len() {
                return Err(format!(
                    "key size mismatch: {} bytes for {} bytes of ciphertext",
                    key.len(),
                    ciphertext.len()
                )
                .into());
            }
            if verbose {
                output::info("integrity:     ", "key length matches");
            }
            Ok(())
        }
    }
}

pub fn key_matches_status(hash_path: &Path) -> String {
    let status = color(ansi::GREEN, "key matches");
    format!("{}  (missing)  {}", hash_path.display(), status)
}
