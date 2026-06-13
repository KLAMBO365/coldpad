use std::io::{self, IsTerminal};

pub mod ansi {
    pub const CYAN: &str = "36";
    pub const BOLD_CYAN: &str = "1;36";
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
