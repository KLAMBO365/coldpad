use clap::Parser;

mod cli;
mod commands;
mod encoding;
mod io;
mod key;
mod output;
mod prompt;
mod terminal;

fn main() {
    cli::reject_removed_cli_forms();
    let cli = cli::Cli::parse();
    if let Err(e) = commands::run(cli) {
        eprintln!(
            "{}",
            terminal::color(terminal::ansi::RED, &format!("error: {e}"))
        );
        std::process::exit(1);
    }
}
