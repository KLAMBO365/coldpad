use std::path::PathBuf;

use crate::cli::{Encoding, KeyCommand};
use crate::encoding::{decode_if_armored, encode_armored};
use crate::io::{read_file, write_secret_file};
use crate::key::{default_keygen_name, resolve_password};
use crate::output;

pub fn run(command: KeyCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        KeyCommand::Generate {
            length,
            output,
            force,
            encoding,
        } => run_generate(length, output, force, encoding),
        KeyCommand::Wrap {
            key_file,
            output,
            force,
            password,
            password_file,
            encoding,
        } => run_wrap(key_file, output, force, password, password_file, encoding),
        KeyCommand::Unwrap {
            key_file,
            output,
            force,
            password,
            password_file,
            encoding,
        } => run_unwrap(key_file, output, force, password, password_file, encoding),
    }
}

pub fn run_generate(
    length: Option<usize>,
    output: Option<PathBuf>,
    force: bool,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let length = match length {
        Some(length) => length,
        None => return Err("key length required: use --length <bytes>".into()),
    };
    let out_path = output.unwrap_or_else(default_keygen_name);

    let key = coldpad_core::generate_key(length);
    let out_key = encode_armored(&key, encoding);

    write_secret_file(&out_path, &out_key, force)?;

    output::group_start("coldpad key generate");
    output::info("key size:      ", format!("{} bytes", key.len()));
    output::success(format!("Wrote {}", out_path.display()));
    output::group_end();
    Ok(())
}

pub fn run_wrap(
    key_file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_file = match key_file {
        Some(path) => path,
        None => return Err("key file required: pass a key file to wrap".into()),
    };
    let output = match output {
        Some(path) => path,
        None => return Err("output path required: use --output <file>".into()),
    };
    let password = resolve_password(password, password_file, "Password for wrapped key: ")?;

    let raw_key = read_file(&key_file)?;
    let key = decode_if_armored(raw_key, encoding, "key")?;

    let wrapped = coldpad_core::wrap::wrap_key(&key, &password);
    write_secret_file(&output, &wrapped, force)?;

    output::group_start("coldpad key wrap");
    output::info("key size:      ", format!("{} bytes", key.len()));
    output::success(format!("Wrote {}", output.display()));
    output::group_end();
    Ok(())
}

pub fn run_unwrap(
    key_file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_file = match key_file {
        Some(path) => path,
        None => return Err("wrapped key file required: pass a key file to unwrap".into()),
    };
    let output = match output {
        Some(path) => path,
        None => return Err("output path required: use --output <file>".into()),
    };
    let password = resolve_password(password, password_file, "Password for wrapped key: ")?;

    let raw_key = read_file(&key_file)?;
    if !coldpad_core::wrap::is_wrapped_key(&raw_key) {
        return Err("key file is not password-protected".into());
    }
    let key = coldpad_core::wrap::unwrap_key(&raw_key, &password)
        .map_err(|e| format!("failed to unwrap key: {e}"))?;

    let out_key = encode_armored(&key, encoding);
    write_secret_file(&output, &out_key, force)?;

    output::group_start("coldpad key unwrap");
    output::info("key size:      ", format!("{} bytes", key.len()));
    output::success(format!("Wrote {}", output.display()));
    output::group_end();
    Ok(())
}
