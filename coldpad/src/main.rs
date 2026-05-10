use base64::Engine;
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn write_hash_file(hash_path: &Path, plaintext: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let hash_hex = coldpad_core::hash::compute(plaintext);
    std::fs::write(hash_path, hash_hex.as_bytes())?;
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
        base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
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
        hex::decode(s.trim())
            .map_err(|e| format!("{context} is not valid hex: {e}").into())
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

#[derive(Parser)]
#[command(name = "coldpad", version, about = "ColdPad — one-time pad encryption tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    #[command(alias = "e", about = "Encrypt text, piped input, or a file using a one-time pad")]
    Encrypt {
        #[arg(help = "Text to encrypt (omit to pipe input or use --file)")]
        text: Option<String>,
        #[arg(short = 'o', long, help = "Output filename stem (default: output)")]
        output: Option<String>,
        #[arg(short = 'f', long, help = "Overwrite existing output files")]
        force: bool,
        #[arg(short = 's', long, help = "Write a SHA-256 hash file for integrity verification")]
        hash: bool,
        #[arg(long, help = "Encrypt a file instead of text")]
        file: Option<PathBuf>,
        #[arg(long, help = "Write ciphertext and key as base64", conflicts_with = "hex")]
        base64: bool,
        #[arg(long, help = "Write ciphertext and key as hex", conflicts_with = "base64")]
        hex: bool,
    },
    #[command(alias = "d", about = "Decrypt a coldpad file")]
    Decrypt {
        #[arg(help = "Path to the .otp ciphertext file (or use --file)")]
        file: Option<PathBuf>,
        #[arg(short = 'o', long, help = "Write decrypted output to a file instead of stdout")]
        output: Option<PathBuf>,
        #[arg(long = "file", help = "Decrypt a .otp ciphertext file")]
        file_flag: Option<PathBuf>,
        #[arg(long, help = "Read ciphertext and key as base64", conflicts_with = "hex")]
        base64: bool,
        #[arg(long, help = "Read ciphertext and key as hex", conflicts_with = "base64")]
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
    #[command(alias = "i", about = "Show information about an encrypted coldpad file")]
    Info {
        #[arg(help = "Path to the .otp file (or use --file)")]
        file: Option<PathBuf>,
        #[arg(long = "file", help = "Show info about a .otp ciphertext file")]
        file_flag: Option<PathBuf>,
        #[arg(long, help = "Read ciphertext and key as base64", conflicts_with = "hex")]
        base64: bool,
        #[arg(long, help = "Read ciphertext and key as hex", conflicts_with = "base64")]
        hex: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::Encrypt { text, output, force, hash, file, base64, hex }) => {
            cmd_encrypt(text, output, force, hash, file, base64, hex)
        }
        Some(Command::Decrypt { file, output, file_flag, base64, hex }) => {
            cmd_decrypt(file.or(file_flag), output, base64, hex)
        }
        Some(Command::Keygen { length, output, force, base64, hex }) => {
            cmd_keygen(length, output, force, base64, hex)
        }
        Some(Command::Info { file, file_flag, base64, hex }) => cmd_info(file.or(file_flag), base64, hex),
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
    output::blank();
    output::info("options:   ", "");
    output::info("  --help        ", "Show help for any command");
    output::info("  --version     ", "Show version information");
    output::group_end();
    Ok(())
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

    let stem = output.unwrap_or_else(|| {
        file.as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| DEFAULT_STEM.to_string())
    });
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
            return Err(format!("'{}' already exists (use --force to overwrite)", path.display()).into());
        }
        write_hash_file(&path, &plaintext)?;
        Some(path)
    } else {
        None
    };

    std::fs::write(&cipher_path, &out_cipher)?;
    std::fs::write(&key_path, &out_key)?;

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
    let file = file.ok_or("no ciphertext file provided. Pass a .otp file as an argument or use --file")?;
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
        std::fs::write(out_path, &plaintext)?;

        output::group_start("coldpad decrypt");
        output::info("decrypted:     ", format!("{} bytes", plaintext.len()));

        verify_decryption(&ciphertext, &key, &plaintext, &file, true)?;

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
        return Err(format!("'{}' already exists (use --force to overwrite)", out_path.display()).into());
    }

    let key = coldpad_core::generate_key(length);
    let out_key = encode_armored(&key, base64, hex);

    std::fs::write(&out_path, &out_key)?;

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
    let file = file.ok_or("no ciphertext file provided. Pass a .otp file as an argument or use --file")?;
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
    output::info("file:          ", format!("{}  {} bytes", file.display(), ct_size));

    if key.len() != ct_size {
        return Err("key size does not match ciphertext".into());
    }
    output::info("key:           ", format!("{}  {} bytes  matches", key_path.display(), key.len()));

    match &hash_data {
        Some(expected) => {
            let plaintext = coldpad_core::decrypt(&ciphertext, &key);
            if coldpad_core::hash::verify(&plaintext, &expected) {
                output::info("hash:          ", format!("{}  verified", hash_path.display()));
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
