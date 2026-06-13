use std::fmt::Display;

use crate::terminal::{ansi, color};

pub fn group_start(title: &str) {
    eprintln!();
    eprintln!("{}", color(ansi::BOLD_CYAN, title));
}

pub fn underline(title: &str) {
    let line = "\u{2550}".repeat(title.len());
    eprintln!("{}", color(ansi::CYAN, &line));
}

pub fn group_end() {
    eprintln!();
}

pub fn info(label: &str, value: impl Display) {
    let label_colored = color(ansi::CYAN, label);
    eprintln!("  {label_colored}{value}");
}

pub fn success(msg: impl Display) {
    let check = color(ansi::GREEN, "\u{2714}");
    eprintln!("  {check} {msg}");
}

pub fn warn(msg: impl Display) {
    let warn = color(ansi::YELLOW, "\u{26A0}");
    eprintln!("  {warn} {msg}");
}

pub fn blank() {
    eprintln!();
}
