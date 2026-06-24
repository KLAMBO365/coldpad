use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::cli::Encoding;
use crate::output;
use crate::terminal;

pub(crate) fn is_interactive_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn prompt_label(prompt: &str) -> String {
    prompt.trim().trim_end_matches(':').trim().to_string()
}

pub fn prompt_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if is_interactive_terminal() {
        let value = dialoguer::Input::<String>::new()
            .with_prompt(prompt_label(prompt))
            .allow_empty(true)
            .interact_text()?;
        return Ok(value.trim().to_string());
    }

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

pub fn prompt_raw_line(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    terminal::show_cursor()?;

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
    if is_interactive_terminal() {
        let value = dialoguer::Input::<String>::new()
            .with_prompt(prompt_label(prompt))
            .interact_text()?;
        return Ok(value.trim().to_string());
    }

    loop {
        let value = prompt_line(prompt)?;
        if !value.is_empty() {
            return Ok(value);
        }
        output::warn("value required");
    }
}

pub fn prompt_path(prompt: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(prompt_required(prompt)?))
}

pub fn prompt_optional_path(prompt: &str) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    Ok(prompt_optional(prompt)?.map(PathBuf::from))
}

pub fn prompt_optional(prompt: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if is_interactive_terminal() {
        let value = dialoguer::Input::<String>::new()
            .with_prompt(prompt_label(prompt))
            .allow_empty(true)
            .interact_text()?;
        let value = value.trim().to_string();
        return Ok((!value.is_empty()).then_some(value));
    }

    let value = prompt_line(prompt)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

pub fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, Box<dyn std::error::Error>> {
    if is_interactive_terminal() {
        return Ok(dialoguer::Confirm::new()
            .with_prompt(prompt_label(prompt))
            .default(default)
            .interact()?);
    }

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

pub fn prompt_select(
    question: &str,
    items: &[&str],
    aliases: &[&[&str]],
) -> Result<usize, Box<dyn std::error::Error>> {
    if items.is_empty() || items.len() != aliases.len() {
        return Err("invalid prompt options".into());
    }

    if is_interactive_terminal() {
        return Ok(dialoguer::Select::new()
            .with_prompt(question)
            .items(items)
            .default(0)
            .interact()?);
    }

    loop {
        eprintln!("{question}");
        for (index, item) in items.iter().enumerate() {
            eprintln!("  {}) {item}", index + 1);
        }

        let answer = prompt_required("Selection: ")?;
        let answer = answer.to_ascii_lowercase();
        if let Ok(number) = answer.parse::<usize>()
            && (1..=items.len()).contains(&number)
        {
            return Ok(number - 1);
        }

        for (index, item_aliases) in aliases.iter().enumerate() {
            if item_aliases.iter().any(|alias| *alias == answer) {
                return Ok(index);
            }
        }

        output::warn("enter one of the listed numbers");
    }
}

pub fn prompt_encoding(question: &str) -> Result<Encoding, Box<dyn std::error::Error>> {
    let selected = prompt_select(
        question,
        &["Raw bytes", "Base64 text", "Hex text"],
        &[&["raw"], &["base64", "b64"], &["hex"]],
    )?;
    Ok(match selected {
        0 => Encoding::Raw,
        1 => Encoding::Base64,
        _ => Encoding::Hex,
    })
}

pub fn prompt_usize(prompt: &str) -> Result<usize, Box<dyn std::error::Error>> {
    if is_interactive_terminal() {
        return Ok(dialoguer::Input::<usize>::new()
            .with_prompt(prompt_label(prompt))
            .interact_text()?);
    }

    loop {
        let answer = prompt_required(prompt)?;
        match answer.parse::<usize>() {
            Ok(value) => return Ok(value),
            Err(_) => output::warn("enter a whole number"),
        }
    }
}

pub fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if is_interactive_terminal() {
        return Ok(dialoguer::Password::new()
            .with_prompt(prompt_label(prompt))
            .interact()?);
    }

    prompt_line(prompt)
}

pub fn prompt_confirmed_password() -> Result<String, Box<dyn std::error::Error>> {
    let password = prompt_password("Password for wrapped key: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    if password != confirm {
        return Err("passwords do not match".into());
    }
    Ok(password)
}

pub fn prompt_wrapped_key_password(
    ciphertext_file: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let key_path = ciphertext_file.with_extension("otp.key");
    if key_path.exists()
        && std::fs::read(&key_path).is_ok_and(|key| coldpad_core::wrap::is_wrapped_key(&key))
    {
        Ok(Some(prompt_password("Key password: ")?))
    } else {
        Ok(None)
    }
}

pub fn confirm_writes(paths: &[PathBuf]) -> Result<bool, Box<dyn std::error::Error>> {
    output::group_start("files coldpad will write");
    for path in paths {
        let status = if path.exists() { "exists" } else { "new" };
        output::info("  ", format!("{}  ({status})", path.display()));
    }
    output::group_end();

    let existing = paths.iter().filter(|path| path.exists()).count();
    let proceed = if existing > 0 {
        output::warn(format!("{existing} planned output file(s) already exist"));
        prompt_yes_no("Proceed and overwrite existing files?", false)?
    } else {
        prompt_yes_no("Create these files now?", false)?
    };
    if !proceed {
        output::warn("aborted");
        return Ok(false);
    }

    Ok(true)
}
