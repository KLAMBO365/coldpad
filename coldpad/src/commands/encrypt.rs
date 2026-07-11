use crate::cli::EncryptOptions;
use crate::encoding::encode_armored;
use crate::io::{PlannedWrite, preflight_output_paths, read_file, write_files_atomically};
use crate::key::planned_encrypt_paths;
use crate::key::resolve_password;
use crate::output;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

pub struct EncryptResult {
    pub key_bytes: usize,
    pub ciphertext_bytes: usize,
    pub cipher_path: PathBuf,
    pub key_path: PathBuf,
    pub hash_path: Option<PathBuf>,
    pub key_wrapped: bool,
}

pub fn run(options: EncryptOptions) -> Result<(), Box<dyn std::error::Error>> {
    let result = execute(options)?;

    output::group_start("coldpad encrypt");
    output::info("key size:      ", format!("{} bytes", result.key_bytes));
    if result.key_wrapped {
        output::info("key format:    ", "password-protected");
    }
    output::info(
        "ciphertext:    ",
        format!("{} bytes", result.ciphertext_bytes),
    );
    output::blank();
    output::success(format!("Wrote {}", result.cipher_path.display()));
    output::info("  ", format!("Wrote {}", result.key_path.display()));
    if let Some(h) = &result.hash_path {
        output::info("  ", format!("Wrote {}", h.display()));
    }
    output::group_end();
    Ok(())
}

pub fn execute(options: EncryptOptions) -> Result<EncryptResult, Box<dyn std::error::Error>> {
    let EncryptOptions {
        text,
        output,
        force,
        hash,
        file,
        encoding,
        wrap_key,
        password,
        password_file,
    } = options;

    let plaintext = if let Some(path) = &file {
        read_file(path)?
    } else {
        read_input(text)?
    };

    let stem = crate::key::encrypt_stem(file.as_deref(), output.as_deref());
    if plaintext.is_empty() && file.is_none() {
        output::warn("empty input \u{2014} writing 0-byte ciphertext and key");
    }

    let paths = planned_encrypt_paths(&stem, hash);
    preflight_output_paths(&paths, force)?;
    let cipher_path = paths[0].clone();
    let key_path = paths[1].clone();
    let hash_path = hash.then(|| paths[2].clone());

    let password = if wrap_key {
        Some(resolve_password(
            password,
            password_file,
            "Password for wrapped key: ",
        )?)
    } else {
        None
    };

    let key = coldpad_core::generate_key(plaintext.len());
    let ciphertext = coldpad_core::encrypt(&plaintext, &key);

    let out_cipher = encode_armored(&ciphertext, encoding);
    let out_key = if wrap_key {
        coldpad_core::wrap::wrap_key(&key, password.as_deref().expect("password resolved"))
    } else {
        encode_armored(&key, encoding)
    };

    let hash_contents = hash_path
        .as_ref()
        .map(|_| coldpad_core::hash::compute(&plaintext).into_bytes());
    let mut writes = vec![
        PlannedWrite::new(&cipher_path, &out_cipher, false),
        PlannedWrite::new(&key_path, &out_key, true),
    ];
    if let (Some(path), Some(contents)) = (&hash_path, &hash_contents) {
        writes.push(PlannedWrite::new(path, contents, false));
    }
    write_files_atomically(&writes, force)?;

    Ok(EncryptResult {
        key_bytes: key.len(),
        ciphertext_bytes: ciphertext.len(),
        cipher_path,
        key_path,
        hash_path,
        key_wrapped: wrap_key,
    })
}

fn read_input(text: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match text {
        Some(t) => Ok(t.into_bytes()),
        None => {
            if io::stdin().is_terminal() {
                Err("input required: pass TEXT, use --file, or pipe stdin".into())
            } else {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }
}
