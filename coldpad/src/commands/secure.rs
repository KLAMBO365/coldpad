use crate::cli::EncryptOptions;
use crate::key::{
    default_keygen_name, encrypt_stem, planned_encrypt_paths, prompt_password_for_wrapped_key,
};
use crate::output;
use crate::prompt::{
    confirm_single_write, confirm_writes, prompt_confirmed_password, prompt_encoding, prompt_line,
    prompt_optional, prompt_optional_path, prompt_path, prompt_required, prompt_usize,
    prompt_yes_no,
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
                break (None, Some(prompt_path("File to encrypt: ")?));
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
    let file = prompt_path("Ciphertext file: ")?;
    let password = prompt_password_for_wrapped_key(&file)?;
    let output = if prompt_yes_no("Write plaintext to a file?", false)? {
        Some(prompt_path("Output file: ")?)
    } else {
        None
    };
    let encoding = prompt_encoding("How are the ciphertext and key files currently stored?")?;

    let allow_output_overwrite = if let Some(path) = &output {
        let force = path.exists();
        if !confirm_single_write(path)? {
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
        None,
    )
}

fn secure_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let length = prompt_usize("Key length in bytes: ")?;
    let out_path = prompt_optional_path("Output key file (leave blank to generate a file name): ")?
        .unwrap_or_else(default_keygen_name);
    let encoding = prompt_encoding("How should coldpad store the key file?")?;
    let force = out_path.exists();

    if !confirm_single_write(&out_path)? {
        return Ok(());
    }

    super::key::run_generate(Some(length), Some(out_path), force, encoding)
}

fn secure_info() -> Result<(), Box<dyn std::error::Error>> {
    let file = prompt_path("Ciphertext file: ")?;
    let password = prompt_password_for_wrapped_key(&file)?;
    let encoding = prompt_encoding("How are the ciphertext and key files currently stored?")?;
    super::info::run(Some(file), encoding, password, None)
}

fn secure_wrap_key() -> Result<(), Box<dyn std::error::Error>> {
    let key_file = prompt_path("Key file to wrap: ")?;
    let output = prompt_path("Output wrapped key file: ")?;
    let encoding = prompt_encoding("How is the input key file currently stored?")?;
    let password = prompt_confirmed_password()?;
    let force = output.exists();
    if !confirm_single_write(&output)? {
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
    let key_file = prompt_path("Wrapped key file: ")?;
    let output = prompt_path("Output unwrapped key file: ")?;
    let encoding = prompt_encoding("How should the unwrapped key file be stored?")?;
    let password = rpassword::prompt_password("Password for wrapped key: ")?;
    let force = output.exists();
    if !confirm_single_write(&output)? {
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
