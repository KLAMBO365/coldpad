use std::path::PathBuf;

use crate::cli::EncryptOptions;
use crate::key::{default_keygen_name, encrypt_stem, planned_encrypt_paths};
use crate::output;
use crate::prompt::{
    confirm_writes, prompt_confirmed_password, prompt_encoding, prompt_line, prompt_optional,
    prompt_required, prompt_usize, prompt_yes_no,
};

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    output::group_start("coldpad secure");
    output::info("guided mode:   ", "answer a few prompts for one workflow");
    output::group_end();

    loop {
        eprintln!("What do you want to do?");
        eprintln!("  1) Encrypt text or a file");
        eprintln!("  2) Decrypt a .otp file");
        eprintln!("  3) Generate a key file");
        eprintln!("  4) Show information about a .otp file");
        eprintln!("  5) Wrap a key file with a password");
        eprintln!("  6) Unwrap a password-protected key file");
        eprintln!("  7) Quit");
        let workflow = prompt_required("Selection: ")?;
        match workflow.to_ascii_lowercase().as_str() {
            "1" | "encrypt" | "e" => return secure_encrypt(),
            "2" | "decrypt" | "d" => return secure_decrypt(),
            "3" | "keygen" | "key" | "k" => return secure_keygen(),
            "4" | "info" | "i" => return secure_info(),
            "5" | "wrap" | "wrap-key" | "w" => return secure_wrap_key(),
            "6" | "unwrap" | "unwrap-key" | "u" => return secure_unwrap_key(),
            "7" | "quit" | "q" | "exit" => return Ok(()),
            _ => output::warn("enter one of the listed numbers"),
        }
    }
}

fn secure_encrypt() -> Result<(), Box<dyn std::error::Error>> {
    let (text, file) = loop {
        eprintln!("What do you want to encrypt?");
        eprintln!("  1) Type text now");
        eprintln!("  2) Encrypt a file");
        let source = prompt_required("Selection: ")?;
        match source.to_ascii_lowercase().as_str() {
            "1" | "text" | "t" => {
                let text = prompt_line("Text to encrypt: ")?;
                break (Some(text), None);
            }
            "2" | "file" | "f" => {
                let path = prompt_required("File to encrypt: ")?;
                break (None, Some(PathBuf::from(path)));
            }
            _ => output::warn("enter one of the listed numbers"),
        }
    };

    let output_prompt = if file.is_some() {
        "Output name without extension (leave blank to use the input file name): "
    } else {
        "Output name without extension (leave blank for output): "
    };
    let output = prompt_optional(output_prompt)?;
    let hash = prompt_yes_no("Write SHA-256 hash file?", true)?;
    let wrap_key = prompt_yes_no("Password-protect the key file?", true)?;
    let encoding = if wrap_key {
        prompt_encoding("How should coldpad store the ciphertext file?")?
    } else {
        prompt_encoding("How should coldpad store the ciphertext and key files?")?
    };
    let stem = encrypt_stem(file.as_deref(), output.as_deref());
    let paths = planned_encrypt_paths(&stem, hash);
    let force = paths.iter().any(|path| path.exists());

    if !confirm_writes(&paths)? {
        return Ok(());
    }

    let password = if wrap_key {
        Some(prompt_confirmed_password()?)
    } else {
        None
    };

    super::encrypt::run(EncryptOptions {
        text,
        output,
        force,
        hash,
        file,
        encoding,
        wrap_key,
        password,
        password_file: None,
    })
}

fn secure_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let file = PathBuf::from(prompt_required("Ciphertext file: ")?);
    let key_path = file.with_extension("otp.key");
    let (password, password_file) = if key_path.exists()
        && std::fs::read(&key_path).is_ok_and(|k| coldpad_core::wrap::is_wrapped_key(&k))
    {
        let pw = rpassword::prompt_password("Key password: ")?;
        (Some(pw), None)
    } else {
        (None, None)
    };
    let output = if prompt_yes_no("Write plaintext to a file?", false)? {
        Some(PathBuf::from(prompt_required("Output file: ")?))
    } else {
        None
    };
    let encoding = prompt_encoding("How are the ciphertext and key files currently stored?")?;

    let allow_output_overwrite = if let Some(path) = &output {
        let paths = vec![path.clone()];
        let force = path.exists();
        if !confirm_writes(&paths)? {
            return Ok(());
        }
        force
    } else {
        true
    };

    super::decrypt::run_with_policy(
        Some(file),
        output,
        encoding,
        allow_output_overwrite,
        password,
        password_file,
    )
}

fn secure_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let length = prompt_usize("Key length in bytes: ")?;
    let out_path = prompt_optional("Output key file (leave blank to generate a file name): ")?
        .map(PathBuf::from)
        .unwrap_or_else(default_keygen_name);
    let encoding = prompt_encoding("How should coldpad store the key file?")?;
    let paths = vec![out_path.clone()];
    let force = out_path.exists();

    if !confirm_writes(&paths)? {
        return Ok(());
    }

    super::key::run_generate(Some(length), Some(out_path), force, encoding)
}

fn secure_info() -> Result<(), Box<dyn std::error::Error>> {
    let file = PathBuf::from(prompt_required("Ciphertext file: ")?);
    let key_path = file.with_extension("otp.key");
    let (password, password_file) = if key_path.exists()
        && std::fs::read(&key_path).is_ok_and(|k| coldpad_core::wrap::is_wrapped_key(&k))
    {
        let pw = rpassword::prompt_password("Key password: ")?;
        (Some(pw), None)
    } else {
        (None, None)
    };
    let encoding = prompt_encoding("How are the ciphertext and key files currently stored?")?;
    super::info::run(Some(file), encoding, password, password_file)
}

fn secure_wrap_key() -> Result<(), Box<dyn std::error::Error>> {
    let key_file = PathBuf::from(prompt_required("Key file to wrap: ")?);
    let output = PathBuf::from(prompt_required("Output wrapped key file: ")?);
    let encoding = prompt_encoding("How is the input key file currently stored?")?;
    let password = prompt_confirmed_password()?;
    let paths = vec![output.clone()];
    let force = output.exists();
    if !confirm_writes(&paths)? {
        return Ok(());
    }
    super::key::run_wrap(
        Some(key_file),
        Some(output),
        force,
        Some(password),
        None,
        encoding,
    )
}

fn secure_unwrap_key() -> Result<(), Box<dyn std::error::Error>> {
    let key_file = PathBuf::from(prompt_required("Wrapped key file: ")?);
    let output = PathBuf::from(prompt_required("Output unwrapped key file: ")?);
    let encoding = prompt_encoding("How should the unwrapped key file be stored?")?;
    let password = rpassword::prompt_password("Password for wrapped key: ")?;
    let paths = vec![output.clone()];
    let force = output.exists();
    if !confirm_writes(&paths)? {
        return Ok(());
    }
    super::key::run_unwrap(
        Some(key_file),
        Some(output),
        force,
        Some(password),
        None,
        encoding,
    )
}
