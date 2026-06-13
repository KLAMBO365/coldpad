use std::io::{self, IsTerminal, Read};
use crate::cli::EncryptOptions;
use crate::encoding::encode_armored;
use crate::io::{
    prepare_output_paths, write_hash_file, write_output_file, write_secret_file,
};
use crate::key::resolve_password;
use crate::output;
use crate::prompt::prompt_line;

pub fn run(options: EncryptOptions) -> Result<(), Box<dyn std::error::Error>> {
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
        std::fs::read(path)?
    } else {
        read_input(text)?
    };

    let stem = crate::key::encrypt_stem(file.as_deref(), output.as_deref());
    if plaintext.is_empty() && file.is_none() {
        output::warn("empty input \u{2014} writing 0-byte ciphertext and key");
    }

    let (cipher_path, key_path) = prepare_output_paths(&stem, force)?;
    let key = coldpad_core::generate_key(plaintext.len());
    let ciphertext = coldpad_core::encrypt(&plaintext, &key);

    let out_cipher = encode_armored(&ciphertext, encoding);
    let out_key = if wrap_key {
        let password = resolve_password(password, password_file, "Password for wrapped key: ")?;
        coldpad_core::wrap::wrap_key(&key, &password)
    } else {
        encode_armored(&key, encoding)
    };

    let hash_path = if hash {
        let path = cipher_path.with_extension("otp.sha256");
        if !force && path.exists() {
            return Err(format!(
                "'{}' already exists (use --force to overwrite)",
                path.display()
            )
            .into());
        }
        write_hash_file(&path, &plaintext, force)?;
        Some(path)
    } else {
        None
    };

    write_output_file(&cipher_path, &out_cipher, force)?;
    write_secret_file(&key_path, &out_key, force)?;

    output::group_start("coldpad encrypt");
    output::info("key size:      ", format!("{} bytes", key.len()));
    if wrap_key {
        output::info("key format:    ", "password-protected");
    }
    output::info("ciphertext:    ", format!("{} bytes", ciphertext.len()));
    output::blank();
    output::success(format!("Wrote {}", cipher_path.display()));
    output::info("  ", format!("Wrote {}", key_path.display()));
    if let Some(h) = &hash_path {
        output::info("  ", format!("Wrote {}", h.display()));
    }
    output::group_end();
    Ok(())
}

fn read_input(text: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match text {
        Some(t) => Ok(t.into_bytes()),
        None => {
            if io::stdin().is_terminal() {
                Ok(prompt_line("Text to encrypt: ")?.into_bytes())
            } else {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }
}
