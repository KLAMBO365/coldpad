use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

mod output;

const DEFAULT_STEM: &str = "output";

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
enum Encoding {
    #[default]
    Raw,
    Base64,
    Hex,
}

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

fn reject_removed_cli_forms() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        return;
    }

    if args.iter().any(|arg| arg == "--base64" || arg == "--hex") {
        eprintln!(
            "{}",
            color(
                ansi::RED,
                "error: --base64 and --hex were removed; use --encoding base64 or --encoding hex"
            )
        );
        process::exit(1);
    }

    match args[0].as_str() {
        "keygen" | "k" => {
            eprintln!(
                "{}",
                color(
                    ansi::RED,
                    "error: coldpad keygen was removed; use coldpad key generate"
                )
            );
            process::exit(1);
        }
        "wrap-key" => {
            eprintln!(
                "{}",
                color(
                    ansi::RED,
                    "error: coldpad wrap-key was removed; use coldpad key wrap"
                )
            );
            process::exit(1);
        }
        "unwrap-key" => {
            eprintln!(
                "{}",
                color(
                    ansi::RED,
                    "error: coldpad unwrap-key was removed; use coldpad key unwrap"
                )
            );
            process::exit(1);
        }
        "decrypt" | "d" | "info" | "i" if args.iter().any(|arg| arg == "--file") => {
            eprintln!(
                "{}",
                color(
                    ansi::RED,
                    "error: --file was removed here; pass the .otp path as an argument"
                )
            );
            process::exit(1);
        }
        _ => {}
    }
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

fn encode_armored(data: &[u8], encoding: Encoding) -> Vec<u8> {
    match encoding {
        Encoding::Raw => data.to_vec(),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD
            .encode(data)
            .into_bytes(),
        Encoding::Hex => hex::encode(data).into_bytes(),
    }
}

fn decode_if_armored(
    data: Vec<u8>,
    encoding: Encoding,
    context: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match encoding {
        Encoding::Raw => Ok(data),
        Encoding::Base64 => {
            let s = std::str::from_utf8(&data)
                .map_err(|_| format!("{context} is not valid UTF-8 (required for base64)"))?;
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|e| format!("{context} is not valid base64: {e}").into())
        }
        Encoding::Hex => {
            let s = std::str::from_utf8(&data)
                .map_err(|_| format!("{context} is not valid UTF-8 (required for hex)"))?;
            hex::decode(s.trim()).map_err(|e| format!("{context} is not valid hex: {e}").into())
        }
    }
}

fn resolve_password(
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

fn decode_key_file(
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

fn prompt_required_if_terminal(
    prompt: &str,
    error: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        prompt_required(prompt)
    } else {
        Err(error.to_string().into())
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

fn prompt_encoding(question: &str) -> Result<Encoding, Box<dyn std::error::Error>> {
    loop {
        eprintln!("{question}");
        eprintln!("  1) Raw bytes");
        eprintln!("  2) Base64 text");
        eprintln!("  3) Hex text");
        let answer = prompt_line("Selection: ")?;
        match answer.to_ascii_lowercase().as_str() {
            "1" | "raw" => return Ok(Encoding::Raw),
            "2" | "base64" | "b64" => return Ok(Encoding::Base64),
            "3" | "hex" => return Ok(Encoding::Hex),
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

fn prompt_confirmed_password() -> Result<String, Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("Password for wrapped key: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
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
    #[command(about = "Start a guided secure workflow")]
    Secure,
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
            value_enum,
            default_value_t,
            help = "Encoding for ciphertext and raw key files"
        )]
        encoding: Encoding,
        #[arg(long, help = "Password-protect the generated key file")]
        wrap_key: bool,
        #[arg(
            long,
            help = "Password for the generated wrapped key",
            requires = "wrap_key"
        )]
        password: Option<String>,
        #[arg(
            long,
            help = "Read generated key password from a file",
            conflicts_with = "password",
            requires = "wrap_key"
        )]
        password_file: Option<PathBuf>,
    },
    #[command(alias = "d", about = "Decrypt a coldpad file")]
    Decrypt {
        #[arg(help = "Path to the .otp ciphertext file")]
        file: Option<PathBuf>,
        #[arg(
            short = 'o',
            long,
            help = "Write decrypted output to a file instead of stdout"
        )]
        output: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Encoding used by the ciphertext and raw key files"
        )]
        encoding: Encoding,
        #[arg(long, help = "Password for a wrapped key file")]
        password: Option<String>,
        #[arg(
            long,
            help = "Read key password from a file",
            conflicts_with = "password"
        )]
        password_file: Option<PathBuf>,
    },
    #[command(
        alias = "i",
        about = "Show information about an encrypted coldpad file"
    )]
    Info {
        #[arg(help = "Path to the .otp file")]
        file: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Encoding used by the ciphertext and raw key files"
        )]
        encoding: Encoding,
        #[arg(long, help = "Password for a wrapped key file")]
        password: Option<String>,
        #[arg(
            long,
            help = "Read key password from a file",
            conflicts_with = "password"
        )]
        password_file: Option<PathBuf>,
    },
    #[command(about = "Generate, wrap, or unwrap key files")]
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    #[command(about = "Generate a random key")]
    Generate {
        #[arg(short = 'l', long, help = "Key length in bytes")]
        length: Option<usize>,
        #[arg(short = 'o', long, help = "Output file (default: key_<timestamp>.key)")]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, help = "Overwrite existing files")]
        force: bool,
        #[arg(long, value_enum, default_value_t, help = "Encoding for the key file")]
        encoding: Encoding,
    },
    #[command(about = "Wrap an existing key with a password")]
    Wrap {
        #[arg(help = "Path to the key file to wrap")]
        key_file: Option<PathBuf>,
        #[arg(short = 'o', long, help = "Output file")]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, help = "Overwrite existing output file")]
        force: bool,
        #[arg(long, help = "Password for the wrapped key")]
        password: Option<String>,
        #[arg(long, help = "Read password from a file", conflicts_with = "password")]
        password_file: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Encoding used by the input key file"
        )]
        encoding: Encoding,
    },
    #[command(about = "Unwrap a password-protected key")]
    Unwrap {
        #[arg(help = "Path to the wrapped key file")]
        key_file: Option<PathBuf>,
        #[arg(short = 'o', long, help = "Output file")]
        output: Option<PathBuf>,
        #[arg(short = 'f', long, help = "Overwrite existing output file")]
        force: bool,
        #[arg(long, help = "Password for the wrapped key")]
        password: Option<String>,
        #[arg(long, help = "Read password from a file", conflicts_with = "password")]
        password_file: Option<PathBuf>,
        #[arg(
            long,
            value_enum,
            default_value_t,
            help = "Encoding for the unwrapped key file"
        )]
        encoding: Encoding,
    },
}

fn main() {
    reject_removed_cli_forms();
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Secure) => cmd_secure(),
        Some(Command::Encrypt {
            text,
            output,
            force,
            hash,
            file,
            encoding,
            wrap_key,
            password,
            password_file,
        }) => cmd_encrypt(EncryptOptions {
            text,
            output,
            force,
            hash,
            file,
            encoding,
            wrap_key,
            password,
            password_file,
        }),
        Some(Command::Decrypt {
            file,
            output,
            encoding,
            password,
            password_file,
        }) => cmd_decrypt(file, output, encoding, password, password_file),
        Some(Command::Info {
            file,
            encoding,
            password,
            password_file,
        }) => cmd_info(file, encoding, password, password_file),
        Some(Command::Key { command }) => match command {
            KeyCommand::Generate {
                length,
                output,
                force,
                encoding,
            } => cmd_keygen(length, output, force, encoding),
            KeyCommand::Wrap {
                key_file,
                output,
                force,
                password,
                password_file,
                encoding,
            } => cmd_wrap_key(key_file, output, force, password, password_file, encoding),
            KeyCommand::Unwrap {
                key_file,
                output,
                force,
                password,
                password_file,
                encoding,
            } => cmd_unwrap_key(key_file, output, force, password, password_file, encoding),
        },
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
    output::info("  secure       ", "Start a guided secure workflow");
    output::info("  encrypt, e   ", "Encrypt text, pipe, or a file");
    output::info("  decrypt, d   ", "Decrypt a .otp ciphertext file");
    output::info("  info,    i   ", "Show info about a .otp file");
    output::info("  key          ", "Generate, wrap, or unwrap key files");
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

    cmd_encrypt(EncryptOptions {
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

    cmd_decrypt_with_output_policy(
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

    cmd_keygen(Some(length), Some(out_path), force, encoding)
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
    cmd_info(Some(file), encoding, password, password_file)
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
    cmd_wrap_key(
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
    cmd_unwrap_key(
        Some(key_file),
        Some(output),
        force,
        Some(password),
        None,
        encoding,
    )
}

struct EncryptOptions {
    text: Option<String>,
    output: Option<String>,
    force: bool,
    hash: bool,
    file: Option<PathBuf>,
    encoding: Encoding,
    wrap_key: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
}

fn cmd_encrypt(options: EncryptOptions) -> Result<(), Box<dyn std::error::Error>> {
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

    let stem = encrypt_stem(file.as_deref(), output.as_deref());
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

fn cmd_decrypt(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    encoding: Encoding,
    password: Option<String>,
    password_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    cmd_decrypt_with_output_policy(file, output, encoding, true, password, password_file)
}

fn cmd_decrypt_with_output_policy(
    file: Option<PathBuf>,
    output: Option<PathBuf>,
    encoding: Encoding,
    allow_output_overwrite: bool,
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
    length: Option<usize>,
    output: Option<PathBuf>,
    force: bool,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let length = match length {
        Some(length) => length,
        None => prompt_required_if_terminal(
            "Key length in bytes: ",
            "key length required (use --length <bytes>)",
        )?
        .parse::<usize>()
        .map_err(|_| "key length must be a whole number")?,
    };
    let out_path = output.unwrap_or_else(default_keygen_name);

    if !force && out_path.exists() {
        return Err(format!(
            "'{}' already exists (use --force to overwrite)",
            out_path.display()
        )
        .into());
    }

    let key = coldpad_core::generate_key(length);
    let out_key = encode_armored(&key, encoding);

    write_secret_file(&out_path, &out_key, force)?;

    output::group_start("coldpad key generate");
    output::info("key size:      ", format!("{} bytes", key.len()));
    output::success(format!("Wrote {}", out_path.display()));
    output::group_end();
    Ok(())
}

fn cmd_wrap_key(
    key_file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_file = match key_file {
        Some(path) => path,
        None => PathBuf::from(prompt_required_if_terminal(
            "Key file to wrap: ",
            "no key file provided",
        )?),
    };
    let output = match output {
        Some(path) => path,
        None => PathBuf::from(prompt_required_if_terminal(
            "Output wrapped key file: ",
            "output path is required (use -o)",
        )?),
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

fn cmd_unwrap_key(
    key_file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
    password: Option<String>,
    password_file: Option<PathBuf>,
    encoding: Encoding,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_file = match key_file {
        Some(path) => path,
        None => PathBuf::from(prompt_required_if_terminal(
            "Wrapped key file: ",
            "no key file provided",
        )?),
    };
    let output = match output {
        Some(path) => path,
        None => PathBuf::from(prompt_required_if_terminal(
            "Output unwrapped key file: ",
            "output path is required (use -o)",
        )?),
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

fn cmd_info(
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
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
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
