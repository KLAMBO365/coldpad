use crate::cli::{Cli, Command, EncryptOptions};
use crate::output;
use crate::prompt;
use crate::terminal::{ansi, color};

mod decrypt;
mod encrypt;
mod info;
mod key;
mod secure;

pub fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Command::Secure) => secure::run(),
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
        }) => encrypt::run(EncryptOptions {
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
        }) => decrypt::run(file, output, encoding, password, password_file),
        Some(Command::Info {
            file,
            encoding,
            password,
            password_file,
        }) => info::run(file, encoding, password, password_file),
        Some(Command::Key { command }) => key::run(command),
        None => root(),
    }
}

fn root() -> Result<(), Box<dyn std::error::Error>> {
    if prompt::is_interactive_terminal() {
        return secure::run();
    }

    print_concise_help();
    Ok(())
}

fn print_concise_help() {
    if crate::terminal::no_color() {
        output::blank();
    } else {
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
}
