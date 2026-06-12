use base64::Engine;
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

mod output;

const DEFAULT_STEM: &str = "output";

pub mod ansi {
    pub const BOLD: &str = "1";
    pub const CYAN: &str = "36";
    pub const BOLD_CYAN: &str = "1;36";
    pub const RED: &str = "31";
    pub const GREEN: &str = "32";
    pub const YELLOW: &str = "33";
}

fn no_color() -> bool {
    !io::stderr().is_terminal() || std::env::var("NO_COLOR").is_ok()
}

fn color(code: &str, text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

fn read_input(text: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match text {
        Some(t) => Ok(t.into_bytes()),
        None => {
            if io::stdin().is_terminal() {
                Err("no input provided. Pass text as an argument or pipe it in".into())
            } else {
                let mut buf = Vec::new();
                io::stdin().read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }
}

fn prepare_output_paths(
    stem: &str,
    force: bool,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let cipher_path = PathBuf::from(format!("{stem}.otp"));
    let key_path = PathBuf::from(format!("{stem}.otp.key"));

    if !force {
        for path in [&cipher_path, &key_path] {
            if path.exists() {
                return Err(format!(
                    "'{}' already exists (use --force to overwrite)",
                    path.display()
                )
                .into());
            }
        }
    }

    Ok((cipher_path, key_path))
}

fn read_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!("'{}' not found", path.display()).into()
        } else {
            format!("failed to read '{}': {e}", path.display()).into()
        }
    })
}

fn write_hash_file(
    hash_path: &Path,
    plaintext: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_hex = coldpad_core::hash::compute(plaintext);
    write_output_file(hash_path, hash_hex.as_bytes(), force)
}

fn write_output_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "'{}' already exists (use --force to overwrite)",
                path.display()
            )
        } else {
            format!("failed to write '{}': {e}", path.display())
        }
    })?;
    file.write_all(contents)?;
    file.flush()?;
    Ok(())
}

fn write_secret_file(
    path: &Path,
    contents: &[u8],
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            format!(
                "'{}' already exists (use --force to overwrite)",
                path.display()
            )
        } else {
            format!("failed to write '{}': {e}", path.display())
        }
    })?;

    file.write_all(contents)?;
    file.flush()?;

    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

fn read_hash_file(hash_path: &Path) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::fs::read_to_string(hash_path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("failed to read '{}': {e}", hash_path.display()).into()),
    }
}

fn verify_decryption(
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

fn encode_armored(data: &[u8], base64: bool, hex: bool) -> Vec<u8> {
    if base64 {
        base64::engine::general_purpose::STANDARD
            .encode(data)
            .into_bytes()
    } else if hex {
        hex::encode(data).into_bytes()
    } else {
        data.to_vec()
    }
}

fn decode_if_armored(
    data: Vec<u8>,
    base64: bool,
    hex: bool,
    context: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if base64 {
        let s = std::str::from_utf8(&data)
            .map_err(|_| format!("{context} is not valid UTF-8 (required for base64)"))?;
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|e| format!("{context} is not valid base64: {e}").into())
    } else if hex {
        let s = std::str::from_utf8(&data)
            .map_err(|_| format!("{context} is not valid UTF-8 (required for hex)"))?;
        hex::decode(s.trim()).map_err(|e| format!("{context} is not valid hex: {e}").into())
    } else {
        Ok(data)
    }
}

fn default_keygen_name() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos();
    PathBuf::from(format!("key_{nanos}.key"))
}

fn encrypt_stem(file: Option<&Path>, output: Option<&str>) -> String {
    output.map(str::to_string).unwrap_or_else(|| {
        file.and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_STEM.to_string())
    })
}

fn planned_encrypt_paths(stem: &str, hash: bool) -> Vec<PathBuf> {
    let cipher_path = PathBuf::from(format!("{stem}.otp"));
    let key_path = PathBuf::from(format!("{stem}.otp.key"));
    let mut paths = vec![cipher_path.clone(), key_path];
    if hash {
        paths.push(cipher_path.with_extension("otp.sha256"));
    }
    paths
}

fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stderr = io::stderr();
    write!(stderr, "{prompt}")?;
    stderr.flush()?;

    let mut input = String::new();
    let bytes = io::stdin().read_line(&mut input)?;
    if bytes == 0 {
        return Err("input ended before the prompt was answered".into());
    }
    Ok(input.trim().to_string())
}

fn prompt_required(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let value = prompt_line(prompt)?;
        if !value.is_empty() {
            return Ok(value);
        }
        output::warn("value required");
    }
}

fn prompt_optional(prompt: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let value = prompt_line(prompt)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let default_text = if default { "yes" } else { "no" };
    loop {
        let answer = prompt_line(&format!("{prompt} Type yes or no [{default_text}]: "))?;
        if answer.is_empty() {
            return Ok(default);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => output::warn("answer yes or no"),
        }
    }
}

fn prompt_encoding(question: &str) -> Result<(bool, bool), Box<dyn std::error::Error>> {
    loop {
        eprintln!("{question}");
        eprintln!("  1) Raw bytes");
        eprintln!("  2) Base64 text");
        eprintln!("  3) Hex text");
        let answer = prompt_line("Selection: ")?;
        match answer.to_ascii_lowercase().as_str() {
            "1" | "raw" => return Ok((false, false)),
            "2" | "base64" | "b64" => return Ok((true, false)),
            "3" | "hex" => return Ok((false, true)),
            _ => output::warn("enter one of the listed numbers"),
        }
    }
}

fn prompt_usize(prompt: &str) -> Result<usize, Box<dyn std::error::Error>> {
    loop {
        let answer = prompt_required(prompt)?;
        match answer.parse::<usize>() {
            Ok(value) => return Ok(value),
            Err(_) => output::warn("enter a whole number"),
        }
    }
}

fn confirm_writes(paths: &[PathBuf]) -> Result<bool, Box<dyn std::error::Error>> {
    output::group_start("files coldpad will write");
    for path in paths {
        let status = if path.exists() { "exists" } else { "new" };
        output::info("  ", format!("{}  ({status})", path.display()));
    }
    output::group_end();

    let existing = paths.iter().filter(|path| path.exists()).count();
    if existing > 0 {
        output::warn(format!("{existing} planned output file(s) already exist"));
        if !prompt_yes_no("Overwrite existing files?", false)? {
            output::warn("aborted");
            return Ok(false);
        }
    }

    if !prompt_yes_no("Create these files now?", false)? {
        output::warn("aborted");
        return Ok(false);
    }

    Ok(true)
}

#[derive(Parser)]
#[command(
    name = "coldpad",
    version,
    about = "ColdPad — one-time pad encryption tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        alias = "e",
        about = "Encrypt text, piped input, or a file using a one-time pad"
    )]
    Encrypt {
        #[arg(
            help = "Text to encrypt (omit to pipe input or use --file)",
            conflicts_with = "file"
        )]
        text: Option<String>,
        #[arg(short = 'o', long, help = "Output filename stem (default: output)")]
        output: Option<String>,
        #[arg(short = 'f', long, help = "Overwrite existing output files")]
        force: bool,
        #[arg(
            short = 's',
            long,
            help = "Write a SHA-256 hash file for integrity verification"
        )]
        hash: bool,
        #[arg(long, help = "Encrypt a file instead of text", conflicts_with = "text")]
        file: Option<PathBuf>,
        #[arg(
            long,
            help = "Write ciphertext and key as base64",
            conflicts_with = "hex"
        )]
        base64: bool,
        #[arg(
            long,
            help = "Write ciphertext and key as hex",
            conflicts_with = "base64"
        )]
        hex: bool,
    },
    #[command(alias = "d", about = "Decrypt a coldpad file")]
    Decrypt {
        #[arg(
            help = "Path to the .otp ciphertext file (or use --file)",
            conflicts_with = "file_flag"
        )]
        file: Option<PathBuf>,
        #[arg(
            short = 'o',
            long,
            help = "Write decrypted output to a file instead of stdout"
        )]
        output: Option<PathBuf>,
        #[arg(
            long = "file",
            help = "Decrypt a .otp ciphertext file",
            conflicts_with = "file"
        )]
        file_flag: Option<PathBuf>,
        #[arg(
            long,
            help = "Read ciphertext and key as base64",
            conflicts_with = "hex"
        )]
        base64: bool,
        #[arg(
            long,
            help = "Read ciphertext and key as hex",
            conflicts_with = "base64"
        )]
        hex: bool,
    },
    #[command(alias = "k", about = "Generate a random key")]
    Keygen {
        #[arg(short = 'l', long, help = "Key length in bytes")]
        length: usize,
        #[arg(short = 'o', long, help = "Output file (default: key_<timestamp>.key)")]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, help = "Overwrite existing files")]
        force: bool,
        #[arg(long, help = "Write key as base64", conflicts_with = "hex")]
        base64: bool,
        #[arg(long, help = "Write key as hex", conflicts_with = "base64")]
        hex: bool,
    },
    #[command(
        alias = "i",
        about = "Show information about an encrypted coldpad file"
    )]
    Info {
        #[arg(
            help = "Path to the .otp file (or use --file)",
            conflicts_with = "file_flag"
        )]
        file: Option<PathBuf>,
        #[arg(
            long = "file",
            help = "Show info about a .otp ciphertext file",
            conflicts_with = "file"
        )]
        file_flag: Option<PathBuf>,
        #[arg(
            long,
            help = "Read ciphertext and key as base64",
            conflicts_with = "hex"
        )]
        base64: bool,
        #[arg(
            long,
            help = "Read ciphertext and key as hex",
            conflicts_with = "base64"
        )]
        hex: bool,
    },
    #[command(about = "Start a guided secure workflow")]
    Secure,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Encrypt {
            text,
            output,
            force,
            hash,
            file,
            base64,
            hex,
        }) => cmd_encrypt(text, output, force, hash, file, base64, hex),
        Some(Command::Decrypt {
            file,
            output,
            file_flag,
            base64,
            hex,
        }) => cmd_decrypt(file.or(file_flag), output, base64, hex),
        Some(Command::Keygen {
            length,
            output,
            force,
            base64,
            hex,
        }) => cmd_keygen(length, output, force, base64, hex),
        Some(Command::Info {
            file,
            file_flag,
            base64,
            hex,
        }) => cmd_info(file.or(file_flag), base64, hex),
        Some(Command::Secure) => cmd_secure(),
        None => cmd_root(),
    };
    if let Err(e) = result {
        eprintln!("{}", color(ansi::RED, &format!("error: {e}")));
        process::exit(1);
    }
}

fn cmd_root() -> Result<(), Box<dyn std::error::Error>> {
    if io::stderr().is_terminal() {
        eprint!("\x1b[2J\x1b[H");
    }
    let title = color(ansi::BOLD_CYAN, "coldpad \u{2014} one-time pad encryption");
    eprintln!();
    eprintln!("{title}");
    output::underline("coldpad \u{2014} one-time pad encryption");
    output::blank();
    output::info("version ", env!("CARGO_PKG_VERSION"));
    output::blank();
    eprintln!("  Encrypt and decrypt data using");
    eprintln!("  information-theoretic security.");
    output::blank();
    output::info("usage:     ", "coldpad <COMMAND> [OPTIONS]");
    output::blank();
    output::info("commands:  ", "");
    output::info("  encrypt, e   ", "Encrypt text, pipe, or a file");
    output::info("  decrypt, d   ", "Decrypt a .otp ciphertext file");
    output::info("  keygen,  k   ", "Generate a random key of N bytes");
    output::info("  info,    i   ", "Show info about a .otp file");
    output::info("  secure       ", "Start a guided secure workflow");
    output::blank();
    output::info("options:   ", "");
    output::info("  --help        ", "Show help for any command");
    output::info("  --version     ", "Show version information");
    output::group_end();
    Ok(())
}

fn cmd_secure() -> Result<(), Box<dyn std::error::Error>> {
    output::group_start("coldpad secure");
    output::info("guided mode:   ", "answer a few prompts for one workflow");
    output::group_end();

    loop {
        eprintln!("What do you want to do?");
        eprintln!("  1) Encrypt text or a file");
        eprintln!("  2) Decrypt a .otp file");
        eprintln!("  3) Generate a key file");
        eprintln!("  4) Show information about a .otp file");
        eprintln!("  5) Quit");
        let workflow = prompt_required("Selection: ")?;
        match workflow.to_ascii_lowercase().as_str() {
            "1" | "encrypt" | "e" => return secure_encrypt(),
            "2" | "decrypt" | "d" => return secure_decrypt(),
            "3" | "keygen" | "key" | "k" => return secure_keygen(),
            "4" | "info" | "i" => return secure_info(),
            "5" | "quit" | "q" | "exit" => return Ok(()),
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
    let (base64, hex) = prompt_encoding("How should coldpad store the ciphertext and key files?")?;
    let stem = encrypt_stem(file.as_deref(), output.as_deref());
    let paths = planned_encrypt_paths(&stem, hash);
    let force = paths.iter().any(|path| path.exists());

    if !confirm_writes(&paths)? {
        return Ok(());
    }

    cmd_encrypt(text, output, force, hash, file, base64, hex)
}

fn secure_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let file = PathBuf::from(prompt_required("Ciphertext file: ")?);
    let output = if prompt_yes_no("Write plaintext to a file?", false)? {
        Some(PathBuf::from(prompt_required("Output file: ")?))
    } else {
        None
    };
    let (base64, hex) = prompt_encoding("How are the ciphertext and key files currently stored?")?;

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

    cmd_decrypt_with_output_policy(Some(file), output, base64, hex, allow_output_overwrite)
}

fn secure_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let length = prompt_usize("Key length in bytes: ")?;
    let out_path = prompt_optional("Output key file (leave blank to generate a file name): ")?
        .map(PathBuf::from)
        .unwrap_or_else(default_keygen_name);
    let (base64, hex) = prompt_encoding("How should coldpad store the key file?")?;
    let paths = vec![out_path.clone()];
    let force = out_path.exists();

    if !confirm_writes(&paths)? {
        return Ok(());
    }

    cmd_keygen(length, Some(out_path), force, base64, hex)
}

fn secure_info() -> Result<(), Box<dyn std::error::Error>> {
    let file = PathBuf::from(prompt_required("Ciphertext file: ")?);
    let (base64, hex) = prompt_encoding("How are the ciphertext and key files currently stored?")?;
    cmd_info(Some(file), base64, hex)
}

fn cmd_encrypt(
    text: Option<String>,
    output: Option<String>,
    force: bool,
    hash: bool,
    file: Option<PathBuf>,
    base64: bool,
    hex: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = if let Some(path) = &file {
        std::fs::read(path)?
    } else {
        read_input(text)?
    };

    let stem = encrypt_stem(file.as_deref(), output.as_deref());
    if plaintext.is_empty() && file.is_none() {
        output::warn("empty input \u{2014} writing 0-byte ciphertext and key");
    }

    let (cipher_path, key_path) = prepare_output_paths(&stem, force)?;
    let key = coldpad_core::generate_key(plaintext.len());
    let ciphertext = coldpad_core::encrypt(&plaintext, &key);

    let out_cipher = encode_armored(&ciphertext, base64, hex);
    let out_key = encode_armored(&key, base64, hex);

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

fn cmd_decrypt(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    base64: bool,
    hex: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    cmd_decrypt_with_output_policy(file, output, base64, hex, true)
}

fn cmd_decrypt_with_output_policy(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    base64: bool,
    hex: bool,
    allow_output_overwrite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let file =
        file.ok_or("no ciphertext file provided. Pass a .otp file as an argument or use --file")?;
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

    let ciphertext = decode_if_armored(raw_ciphertext, base64, hex, "ciphertext")?;
    let key = decode_if_armored(raw_key, base64, hex, "key")?;

    if key.len() != ciphertext.len() {
        return Err(format!(
            "key size mismatch: {} bytes for {} bytes of ciphertext",
            key.len(),
            ciphertext.len()
        )
        .into());
    }

    let plaintext = coldpad_core::decrypt(&ciphertext, &key);

    if let Some(out_path) = &output {
        output::group_start("coldpad decrypt");
        output::info("decrypted:     ", format!("{} bytes", plaintext.len()));

        verify_decryption(&ciphertext, &key, &plaintext, &file, true)?;

        write_output_file(out_path, &plaintext, allow_output_overwrite)?;

        output::blank();
        output::success("Decryption complete");
        output::group_end();
    } else {
        output::group_start("coldpad decrypt");
        output::info("decrypted:     ", format!("{} bytes", plaintext.len()));

        verify_decryption(&ciphertext, &key, &plaintext, &file, true)?;

        if io::stdout().is_terminal() && plaintext.contains(&0) {
            output::warn("output looks like binary data \u{2014} use -o to write to a file");
        }

        output::blank();
        output::success("Decryption complete");
        output::group_end();

        io::stdout().write_all(&plaintext)?;
        if io::stdout().is_terminal() && !plaintext.ends_with(b"\n") {
            io::stdout().write_all(b"\n")?;
        }
    }

    Ok(())
}

fn cmd_keygen(
    length: usize,
    output: Option<PathBuf>,
    force: bool,
    base64: bool,
    hex: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let out_path = output.unwrap_or_else(default_keygen_name);

    if !force && out_path.exists() {
        return Err(format!(
            "'{}' already exists (use --force to overwrite)",
            out_path.display()
        )
        .into());
    }

    let key = coldpad_core::generate_key(length);
    let out_key = encode_armored(&key, base64, hex);

    write_secret_file(&out_path, &out_key, force)?;

    output::group_start("coldpad keygen");
    output::info("key size:      ", format!("{} bytes", key.len()));
    output::success(format!("Wrote {}", out_path.display()));
    output::group_end();
    Ok(())
}

fn cmd_info(
    file: Option<PathBuf>,
    base64: bool,
    hex: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let file =
        file.ok_or("no ciphertext file provided. Pass a .otp file as an argument or use --file")?;
    let raw_ciphertext = read_file(&file)?;
    let key_path = file.with_extension("otp.key");
    let raw_key = match std::fs::read(&key_path) {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            output::warn(format!("{}  (missing)", key_path.display()));
            return Err(format!("missing key: expected {}", key_path.display()).into());
        }
        Err(e) => {
            return Err(format!("failed to read '{}': {e}", key_path.display()).into());
        }
    };

    let ciphertext = decode_if_armored(raw_ciphertext, base64, hex, "ciphertext")?;
    let key = decode_if_armored(raw_key, base64, hex, "key")?;

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
            let status = color(ansi::GREEN, "key matches");
            output::warn(format!("{}  (missing)  {}", hash_path.display(), status));
        }
    }

    if hash_data.is_some() {
        output::success("Integrity check passed");
    }
    output::group_end();
    Ok(())
}
