use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use crate::cli::Encoding;
use crate::output;

pub fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
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

pub fn prompt_required(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let value = prompt_line(prompt)?;
        if !value.is_empty() {
            return Ok(value);
        }
        output::warn("value required");
    }
}

pub fn prompt_optional(prompt: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let value = prompt_line(prompt)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

pub fn prompt_required_if_terminal(
    prompt: &str,
    error: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        prompt_required(prompt)
    } else {
        Err(error.to_string().into())
    }
}

pub fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, Box<dyn std::error::Error>> {
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

pub fn prompt_encoding(question: &str) -> Result<Encoding, Box<dyn std::error::Error>> {
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

pub fn prompt_usize(prompt: &str) -> Result<usize, Box<dyn std::error::Error>> {
    loop {
        let answer = prompt_required(prompt)?;
        match answer.parse::<usize>() {
            Ok(value) => return Ok(value),
            Err(_) => output::warn("enter a whole number"),
        }
    }
}

pub fn prompt_confirmed_password() -> Result<String, Box<dyn std::error::Error>> {
    let password = rpassword::prompt_password("Password for wrapped key: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

pub fn confirm_writes(paths: &[PathBuf]) -> Result<bool, Box<dyn std::error::Error>> {
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
