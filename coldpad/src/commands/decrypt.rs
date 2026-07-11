use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use crate::cli::Encoding;
use crate::encoding::decode_if_armored;
use crate::io::{preflight_output_paths, read_file};
use crate::key::{decode_key_file, verify_decryption};
use crate::output;

pub fn run(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
    encoding: Encoding,
    password: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_policy(file, output, encoding, force, password, password_file)
}

pub fn run_with_policy(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    encoding: Encoding,
    allow_output_overwrite: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let file = match file {
        Some(file) => file,
        None => return Err("ciphertext file required: pass a .otp file".into()),
    };
    if let Some(out_path) = &output {
        preflight_output_paths(std::slice::from_ref(out_path), allow_output_overwrite)?;
    }
    let raw_ciphertext = read_file(&file).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") {
            format!("ciphertext file '{}' not found", file.display())
        } else {
            msg
        }
    })?;
    let key_path = file.with_extension("otp.key");
    let raw_key = match std::fs::read(&key_path) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(format!("missing key: expected {}", key_path.display()).into());
        }
        Err(e) => {
            return Err(format!("failed to read '{}': {e}", key_path.display()).into());
        }
    };

    let ciphertext = decode_if_armored(raw_ciphertext, encoding, "ciphertext")?;
    let key = decode_key_file(raw_key, encoding, password, password_file)?;

    if key.len() != ciphertext.len() {
        return Err(format!(
            "key size mismatch: {} bytes for {} bytes of ciphertext",
            key.len(),
            ciphertext.len()
        )
        .into());
    }

    let plaintext = coldpad_core::decrypt(&ciphertext, &key);

    let integrity = verify_decryption(&ciphertext, &key, &plaintext, &file)?;

    if let Some(out_path) = &output {
        crate::io::write_output_file(out_path, &plaintext, allow_output_overwrite)?;
    } else if io::stdout().is_terminal() && plaintext.contains(&0) {
        output::warn("output looks like binary data \u{2014} use -o to write to a file");
    }

    output::group_start("coldpad decrypt");
    output::info("decrypted:     ", format!("{} bytes", plaintext.len()));
    match integrity {
        crate::key::IntegrityStatus::SidecarMatched => {
            output::info(
                "integrity:     ",
                "SHA-256 sidecar matches (not authenticated)",
            );
        }
        crate::key::IntegrityStatus::NotVerified => {
            output::warn("integrity not verified (no hash file; key length only)");
        }
    }
    output::blank();
    output::success("Decryption complete");
    output::group_end();

    if output.is_none() {
        io::stdout().write_all(&plaintext)?;
        if io::stdout().is_terminal() && !plaintext.ends_with(b"\n") {
            io::stdout().write_all(b"\n")?;
        }
    }

    Ok(())
}
