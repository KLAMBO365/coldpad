use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand, ValueEnum};

use crate::terminal::{ansi, color};

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum Encoding {
    #[default]
    Raw,
    Base64,
    Hex,
}

#[derive(Parser)]
#[command(
    name = "coldpad",
    version,
    about = "ColdPad — one-time pad encryption tool"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
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
pub enum KeyCommand {
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

pub struct EncryptOptions {
    pub text: Option<String>,
    pub output: Option<String>,
    pub force: bool,
    pub hash: bool,
    pub file: Option<PathBuf>,
    pub encoding: Encoding,
    pub wrap_key: bool,
    pub password: Option<String>,
    pub password_file: Option<PathBuf>,
}

pub fn reject_removed_cli_forms() {
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
