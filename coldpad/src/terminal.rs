use std::io::{self, IsTerminal};

pub use console::Key;
use console::Term;

pub mod ansi {
    pub const BOLD: &str = "1";
    pub const CYAN: &str = "36";
    pub const BOLD_CYAN: &str = "1;36";
    pub const BOLD_GREEN: &str = "1;32";
    pub const BOLD_YELLOW: &str = "1;33";
    pub const DIM_WHITE: &str = "2;37";
    pub const RED: &str = "31";
    pub const GREEN: &str = "32";
    pub const YELLOW: &str = "33";
}

pub fn no_color() -> bool {
    !io::stderr().is_terminal() || std::env::var("NO_COLOR").is_ok()
}

pub fn color(code: &str, text: &str) -> String {
    if no_color() {
        text.to_string()
    } else {
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}

pub fn clear_screen() -> io::Result<()> {
    if io::stderr().is_terminal() {
        Term::stderr().clear_screen()?;
    }
    Ok(())
}

pub fn show_cursor() -> io::Result<()> {
    if io::stderr().is_terminal() {
        let term = Term::stderr();
        term.show_cursor()?;
        term.flush()?;
    }
    Ok(())
}

pub fn render_frame(lines: &[String], prompt: &str) -> io::Result<()> {
    let term = Term::stderr();
    term.clear_screen()?;
    for line in lines {
        term.write_line(line)?;
    }
    term.write_str(prompt)?;
    term.flush()
}

pub fn read_key() -> io::Result<Key> {
    Term::stderr().read_key()
}
