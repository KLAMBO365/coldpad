use crate::cli::{Encoding, EncryptOptions};
use crate::key::{default_keygen_name, encrypt_stem, planned_encrypt_paths};
use crate::output;
use crate::prompt::{
    confirm_writes, prompt_confirmed_password, prompt_encoding, prompt_line, prompt_optional,
    prompt_optional_path, prompt_password, prompt_path, prompt_raw_line, prompt_select,
    prompt_usize, prompt_wrapped_key_password, prompt_yes_no,
};
use crate::terminal::{self, Key, ansi, color};

use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

struct WorkflowItem {
    key: &'static str,
    title: &'static str,
    middle: &'static str,
    right: &'static str,
}

const WORKFLOW_ITEMS: &[WorkflowItem] = &[
    WorkflowItem {
        key: "1",
        title: "Encrypt",
        middle: "Text, stdin, or file",
        right: ".otp + key",
    },
    WorkflowItem {
        key: "2",
        title: "Decrypt",
        middle: ".otp + key",
        right: "plaintext",
    },
    WorkflowItem {
        key: "3",
        title: "Keygen",
        middle: "Generate standalone key file",
        right: "",
    },
    WorkflowItem {
        key: "4",
        title: "Info",
        middle: "Inspect .otp, key, hash",
        right: "",
    },
    WorkflowItem {
        key: "5",
        title: "Wrap key",
        middle: "Password-protect a key file",
        right: "",
    },
    WorkflowItem {
        key: "6",
        title: "Unwrap key",
        middle: "Restore raw key file",
        right: "",
    },
    WorkflowItem {
        key: "q",
        title: "Quit",
        middle: "Exit without changes",
        right: "",
    },
];

struct StepMenuItem {
    key: &'static str,
    title: &'static str,
    description: &'static str,
    aliases: &'static [&'static str],
}

struct StepMenuView<'a> {
    workflow: &'a str,
    step: usize,
    total: usize,
    heading: &'a str,
    items: &'a [StepMenuItem],
    back: bool,
}

enum StepAction {
    Select(usize),
    Back,
    Cancel,
}

enum StepValue<T> {
    Value(T),
    Back,
    Cancel,
}

enum FlowExit {
    Done,
    BackToMenu,
    Cancel,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let workflow = choose_workflow()?;
        let result = match workflow {
            0 => secure_encrypt(),
            1 => secure_decrypt(),
            2 => secure_keygen(),
            3 => secure_info(),
            4 => secure_wrap_key(),
            5 => secure_unwrap_key(),
            _ => Ok(FlowExit::Cancel),
        }?;

        match result {
            FlowExit::Done | FlowExit::Cancel => return Ok(()),
            FlowExit::BackToMenu => {}
        }
    }
}

fn choose_workflow() -> Result<usize, Box<dyn std::error::Error>> {
    if crate::prompt::is_interactive_terminal() {
        prompt_workflow_menu()
    } else {
        output::group_start("coldpad secure");
        output::info("guided mode:   ", "answer a few prompts for one workflow");
        output::group_end();

        prompt_select(
            "What do you want to do?",
            &[
                "Encrypt text or a file",
                "Decrypt a .otp file",
                "Generate a key file",
                "Show information about a .otp file",
                "Wrap a key file with a password",
                "Unwrap a password-protected key file",
                "Quit",
            ],
            &[
                &["encrypt", "e"],
                &["decrypt", "d"],
                &["keygen", "key", "k"],
                &["info", "i"],
                &["wrap", "wrap-key", "w"],
                &["unwrap", "unwrap-key", "u"],
                &["quit", "q", "exit"],
            ],
        )
    }
}

fn prompt_workflow_menu() -> Result<usize, Box<dyn std::error::Error>> {
    interactive_select(
        0,
        WORKFLOW_ITEMS.len(),
        |selected| {
            workflow_menu_lines(
                selected,
                output::WORKFLOW_WIDTH,
                &output::divider(output::WORKFLOW_WIDTH),
            )
        },
        workflow_action_for_key,
    )
}

fn workflow_action_for_key(key: Key, selected: usize) -> Option<usize> {
    match key {
        Key::Enter => Some(selected),
        Key::Escape | Key::CtrlC => Some(WORKFLOW_ITEMS.len() - 1),
        Key::Char(value) => workflow_action_for_answer(&value.to_string()),
        _ => None,
    }
}

fn workflow_action_for_answer(answer: &str) -> Option<usize> {
    let answer = answer.trim().to_ascii_lowercase();
    if answer.is_empty() {
        return Some(0);
    }
    if answer == "q" || answer == "quit" || answer == "exit" {
        return Some(WORKFLOW_ITEMS.len() - 1);
    }
    if let Ok(number) = answer.parse::<usize>()
        && (1..WORKFLOW_ITEMS.len()).contains(&number)
    {
        return Some(number - 1);
    }
    WORKFLOW_ITEMS.iter().enumerate().find_map(|(index, item)| {
        let title = item.title.to_ascii_lowercase();
        let matches_title_prefix = title
            .chars()
            .next()
            .is_some_and(|prefix| answer == prefix.to_string());
        (answer == title
            || matches_title_prefix
            || item.key == answer
            || (item.title == "Keygen" && (answer == "key" || answer == "k"))
            || (item.title == "Wrap key"
                && (answer == "wrap" || answer == "wrap-key" || answer == "w"))
            || (item.title == "Unwrap key"
                && (answer == "unwrap" || answer == "unwrap-key" || answer == "u")))
            .then_some(index)
    })
}

fn interactive_select<T>(
    initial_selected: usize,
    choice_count: usize,
    mut render_lines: impl FnMut(usize) -> Vec<String>,
    mut key_action: impl FnMut(Key, usize) -> Option<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    if choice_count == 0 {
        return Err("invalid prompt options".into());
    }

    let mut selected = initial_selected.min(choice_count - 1);
    loop {
        let lines = render_lines(selected);
        terminal::render_frame(&lines, &output::prompt_choice("Choice"))?;

        match terminal::read_key()? {
            Key::ArrowDown | Key::Tab => {
                selected = (selected + 1) % choice_count;
            }
            Key::ArrowUp | Key::BackTab => {
                selected = (selected + choice_count - 1) % choice_count;
            }
            key => {
                if let Some(action) = key_action(key, selected) {
                    return Ok(action);
                }
            }
        }
    }
}

fn clear_wizard_screen() {
    let _ = terminal::clear_screen();
}

fn workflow_menu_lines(selected: usize, width: usize, _divider: &str) -> Vec<String> {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut lines = output::workflow_header_lines(
        "coldpad secure",
        output::WorkflowStatus::Label(&version),
        width,
    );

    for (index, item) in WORKFLOW_ITEMS.iter().enumerate() {
        if index == 3 || index == 6 {
            lines.push(String::new());
        }
        lines.push(workflow_menu_row(index == selected, item));
    }

    lines
}

fn workflow_menu_row(selected: bool, item: &WorkflowItem) -> String {
    let marker = if selected {
        color(ansi::BOLD_GREEN, ">")
    } else {
        " ".to_string()
    };
    let key = color(ansi::BOLD_YELLOW, &format!("{:>2}", item.key));
    let title = color(ansi::BOLD, &format!("{:<18}", item.title));
    let middle = color(ansi::DIM_WHITE, &format!("{:<28}", item.middle));

    if item.right.is_empty() {
        format!("  {marker}  {key}   {title} {middle}")
    } else {
        let arrow = color(ansi::DIM_WHITE, "→");
        let right = color(ansi::DIM_WHITE, item.right);
        format!("  {marker}  {key}   {title} {middle} {arrow}   {right}")
    }
}

fn prompt_step_menu(
    workflow: &str,
    step: usize,
    total: usize,
    heading: &str,
    items: &[StepMenuItem],
    back: bool,
) -> Result<StepAction, Box<dyn std::error::Error>> {
    if crate::prompt::is_interactive_terminal() {
        prompt_step_menu_interactive(workflow, step, total, heading, items, back)
    } else {
        prompt_step_menu_fallback(heading, items, back)
    }
}

fn prompt_step_menu_interactive(
    workflow: &str,
    step: usize,
    total: usize,
    heading: &str,
    items: &[StepMenuItem],
    back: bool,
) -> Result<StepAction, Box<dyn std::error::Error>> {
    let view = StepMenuView {
        workflow,
        step,
        total,
        heading,
        items,
        back,
    };

    prompt_interactive_step_menu(0, items, back, |selected| {
        step_menu_lines(
            &view,
            selected,
            output::WORKFLOW_WIDTH,
            &output::divider(output::WORKFLOW_WIDTH),
        )
    })
}

fn prompt_interactive_step_menu(
    initial_selected: usize,
    items: &[StepMenuItem],
    back: bool,
    render_lines: impl FnMut(usize) -> Vec<String>,
) -> Result<StepAction, Box<dyn std::error::Error>> {
    interactive_select(
        initial_selected,
        step_choice_count(items, back),
        render_lines,
        |key, selected| step_action_for_key(key, selected, items, back),
    )
}

fn step_choice_count(items: &[StepMenuItem], back: bool) -> usize {
    items.len() + usize::from(back) + 1
}

fn step_action_for_key(
    key: Key,
    selected: usize,
    items: &[StepMenuItem],
    back: bool,
) -> Option<StepAction> {
    match key {
        Key::Enter => Some(step_action_for_selected(selected, items, back)),
        Key::Escape | Key::CtrlC => Some(StepAction::Cancel),
        Key::Char(value) => step_action_for_key_text(&value.to_string(), items, back),
        _ => None,
    }
}

fn step_action_for_selected(selected: usize, items: &[StepMenuItem], back: bool) -> StepAction {
    if selected < items.len() {
        return StepAction::Select(selected);
    }
    if back && selected == items.len() {
        return StepAction::Back;
    }
    StepAction::Cancel
}

fn prompt_step_menu_fallback(
    heading: &str,
    items: &[StepMenuItem],
    back: bool,
) -> Result<StepAction, Box<dyn std::error::Error>> {
    loop {
        eprintln!("{heading}");
        for item in items {
            eprintln!("  {}) {}  {}", item.key, item.title, item.description);
        }
        if back {
            eprintln!("  b) Back  Return to main menu");
        }
        eprintln!("  q) Cancel  Exit without changes");

        let answer = prompt_line("Selection: ")?;
        let answer = answer.to_ascii_lowercase();
        if back && (answer == "b" || answer == "back") {
            return Ok(StepAction::Back);
        }
        if answer == "q" || answer == "quit" || answer == "cancel" {
            return Ok(StepAction::Cancel);
        }
        for (index, item) in items.iter().enumerate() {
            if answer == item.key || item.aliases.iter().any(|alias| *alias == answer) {
                return Ok(StepAction::Select(index));
            }
        }
        output::warn("enter one of the listed choices");
    }
}

fn step_menu_lines(
    view: &StepMenuView<'_>,
    selected: usize,
    width: usize,
    divider: &str,
) -> Vec<String> {
    let mut lines = step_header_lines(view.workflow, view.step, view.total, width, divider);
    lines.push(color(ansi::BOLD, view.heading));
    lines.push(String::new());

    for (index, item) in view.items.iter().enumerate() {
        lines.push(step_menu_row(
            index == selected,
            item.key,
            item.title,
            item.description,
        ));
    }

    lines.push(String::new());
    let mut control_index = view.items.len();
    if view.back {
        lines.push(step_menu_row(
            selected == control_index,
            "b",
            "Back",
            "Return to main menu",
        ));
        control_index += 1;
    }
    lines.push(step_menu_row(
        selected == control_index,
        "q",
        "Cancel",
        "Exit without changes",
    ));

    lines
}

fn step_header_lines(
    workflow: &str,
    step: usize,
    total: usize,
    width: usize,
    _divider: &str,
) -> Vec<String> {
    output::workflow_header_lines(
        &format!("coldpad secure / {workflow}"),
        output::WorkflowStatus::Step(step, total),
        width,
    )
}

fn step_menu_row(selected: bool, key: &str, title: &str, description: &str) -> String {
    let marker = if selected {
        color(ansi::BOLD_GREEN, ">")
    } else {
        " ".to_string()
    };
    let key = color(ansi::BOLD_YELLOW, &format!("{key:>2}"));
    let title = color(ansi::BOLD, &format!("{title:<18}"));
    let description = color(ansi::DIM_WHITE, description);
    format!("  {marker}  {key}   {title} {description}")
}

fn step_choice_lines(
    items: &[StepMenuItem],
    selected: usize,
    back: bool,
    back_description: &'static str,
) -> Vec<String> {
    let mut rows = items
        .iter()
        .enumerate()
        .map(|(index, item)| output::ChoiceRow {
            selected: index == selected,
            key: item.key,
            label: item.title,
            description: item.description,
        })
        .collect::<Vec<_>>();

    let mut lines = output::choice_row_lines(&rows);
    rows.clear();
    lines.push(String::new());

    let mut control_index = items.len();
    if back {
        rows.push(output::ChoiceRow {
            selected: selected == control_index,
            key: "b",
            label: "Back",
            description: back_description,
        });
        control_index += 1;
    }
    rows.push(output::ChoiceRow {
        selected: selected == control_index,
        key: "q",
        label: "Cancel",
        description: "Exit without changes",
    });
    lines.extend(output::choice_row_lines(&rows));
    lines.push(String::new());
    lines
}

fn step_action_for_answer(answer: &str, items: &[StepMenuItem], back: bool) -> Option<StepAction> {
    let answer = answer.trim().to_ascii_lowercase();
    if back && (answer == "b" || answer == "back") {
        return Some(StepAction::Back);
    }
    if answer == "q" || answer == "quit" || answer == "cancel" {
        return Some(StepAction::Cancel);
    }
    if let Ok(number) = answer.parse::<usize>()
        && (1..=items.len()).contains(&number)
    {
        return Some(StepAction::Select(number - 1));
    }

    items
        .iter()
        .position(|item| answer == item.key || item.aliases.iter().any(|alias| *alias == answer))
        .map(StepAction::Select)
}

fn step_action_for_key_text(
    answer: &str,
    items: &[StepMenuItem],
    back: bool,
) -> Option<StepAction> {
    step_action_for_answer(answer, items, back).or_else(|| {
        let answer = answer.trim().to_ascii_lowercase();
        if answer.chars().count() != 1 {
            return None;
        }

        let mut matches = items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.aliases.iter().any(|alias| alias.starts_with(&answer)));
        let (index, _) = matches.next()?;
        matches
            .next()
            .is_none()
            .then_some(StepAction::Select(index))
    })
}

fn render_step_input(
    workflow: &str,
    step: usize,
    total: usize,
    heading: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !crate::prompt::is_interactive_terminal() {
        return Ok(());
    }

    clear_wizard_screen();
    output::workflow_header(
        &format!("coldpad secure / {workflow}"),
        output::WorkflowStatus::Step(step, total),
    );
    eprintln!("{}", color(ansi::BOLD, heading));
    eprintln!();
    Ok(())
}

fn prompt_step_yes_no(
    workflow: &str,
    step: usize,
    total: usize,
    heading: &str,
    yes_description: &'static str,
    no_description: &'static str,
    default: bool,
) -> Result<StepValue<bool>, Box<dyn std::error::Error>> {
    if !crate::prompt::is_interactive_terminal() {
        return Ok(StepValue::Value(prompt_yes_no(heading, default)?));
    }

    let action = prompt_step_menu(
        workflow,
        step,
        total,
        heading,
        &[
            StepMenuItem {
                key: "y",
                title: "Yes",
                description: yes_description,
                aliases: &["yes"],
            },
            StepMenuItem {
                key: "n",
                title: "No",
                description: no_description,
                aliases: &["no"],
            },
        ],
        true,
    )?;
    Ok(match action {
        StepAction::Select(0) => StepValue::Value(true),
        StepAction::Select(_) => StepValue::Value(false),
        StepAction::Back => StepValue::Back,
        StepAction::Cancel => StepValue::Cancel,
    })
}

fn prompt_step_encoding(
    workflow: &str,
    step: usize,
    total: usize,
    heading: &str,
) -> Result<StepValue<crate::cli::Encoding>, Box<dyn std::error::Error>> {
    if !crate::prompt::is_interactive_terminal() {
        return Ok(StepValue::Value(prompt_encoding(heading)?));
    }

    let action = prompt_step_menu(
        workflow,
        step,
        total,
        heading,
        &[
            StepMenuItem {
                key: "1",
                title: "Raw",
                description: "Store raw bytes",
                aliases: &["raw"],
            },
            StepMenuItem {
                key: "2",
                title: "Base64",
                description: "Store printable Base64 text",
                aliases: &["base64", "b64"],
            },
            StepMenuItem {
                key: "3",
                title: "Hex",
                description: "Store printable hexadecimal text",
                aliases: &["hex"],
            },
        ],
        true,
    )?;

    Ok(match action {
        StepAction::Select(0) => StepValue::Value(crate::cli::Encoding::Raw),
        StepAction::Select(1) => StepValue::Value(crate::cli::Encoding::Base64),
        StepAction::Select(_) => StepValue::Value(crate::cli::Encoding::Hex),
        StepAction::Back => StepValue::Back,
        StepAction::Cancel => StepValue::Cancel,
    })
}

fn prompt_step_confirm_writes(
    workflow: &str,
    step: usize,
    total: usize,
    paths: &[std::path::PathBuf],
) -> Result<StepValue<bool>, Box<dyn std::error::Error>> {
    if !crate::prompt::is_interactive_terminal() {
        return Ok(StepValue::Value(confirm_writes(paths)?));
    }

    let existing = paths.iter().filter(|path| path.exists()).count();
    let description = if existing > 0 {
        "Proceed and overwrite existing files"
    } else {
        "Create these files now"
    };
    let items = [
        StepMenuItem {
            key: "y",
            title: "Proceed",
            description,
            aliases: &["yes", "proceed"],
        },
        StepMenuItem {
            key: "n",
            title: "Abort",
            description: "Return without writing files",
            aliases: &["no", "abort"],
        },
    ];

    let action = prompt_interactive_step_menu(0, &items, true, |selected| {
        let mut lines = step_header_lines(
            workflow,
            step,
            total,
            output::WORKFLOW_WIDTH,
            &output::divider(output::WORKFLOW_WIDTH),
        );
        lines.push(color(ansi::BOLD, "Review files"));
        lines.push(String::new());
        for path in paths {
            let status = output::status_new_or_exists(path);
            lines.push(format!(
                "  {:<12} {:<24} {}",
                "file",
                path.display(),
                status
            ));
        }
        lines.push(String::new());
        lines.push(color(ansi::BOLD, "Confirm write"));
        lines.push(String::new());
        lines.extend(step_choice_lines(
            &items,
            selected,
            true,
            "Return to previous step",
        ));
        lines
    })?;

    Ok(match action {
        StepAction::Select(0) => StepValue::Value(true),
        StepAction::Select(_) => StepValue::Value(false),
        StepAction::Back => StepValue::Back,
        StepAction::Cancel => StepValue::Cancel,
    })
}

fn step_value_or_flow<T>(value: StepValue<T>) -> Result<T, FlowExit> {
    match value {
        StepValue::Value(value) => Ok(value),
        StepValue::Back => Err(FlowExit::BackToMenu),
        StepValue::Cancel => Err(FlowExit::Cancel),
    }
}

#[derive(Clone, Copy)]
enum EncryptSource {
    Text,
    File,
    Stdin,
}

#[derive(Clone)]
struct EncryptWizardInput {
    source: EncryptSource,
    text: Option<String>,
    file: Option<PathBuf>,
    size: usize,
}

#[derive(Clone)]
struct EncryptWizardOutput {
    output: Option<String>,
    encoding: Encoding,
    hash: bool,
    wrap_key: bool,
    password: Option<String>,
}

const ENCRYPT_CIPHERTEXT_PROMPT: &str = "Ciphertext file";

fn secure_encrypt_wizard() -> Result<FlowExit, Box<dyn std::error::Error>> {
    let mut step = 1;
    let mut source = None;
    let mut input = None;
    let mut output_settings = None;

    loop {
        match step {
            1 => match prompt_encrypt_source()? {
                StepValue::Value(value) => {
                    source = Some(value);
                    input = None;
                    output_settings = None;
                    step = 2;
                }
                StepValue::Back => return Ok(FlowExit::BackToMenu),
                StepValue::Cancel => return Ok(FlowExit::Cancel),
            },
            2 => {
                let selected_source = source.expect("source step completed");
                match prompt_encrypt_input(selected_source)? {
                    StepValue::Value(value) => {
                        input = Some(value);
                        output_settings = None;
                        step = 3;
                    }
                    StepValue::Back => step = 1,
                    StepValue::Cancel => return Ok(FlowExit::Cancel),
                }
            }
            3 => {
                let selected_input = input.as_ref().expect("input step completed");
                match prompt_encrypt_output(selected_input)? {
                    StepValue::Value(value) => {
                        output_settings = Some(value);
                        step = 4;
                    }
                    StepValue::Back => step = 2,
                    StepValue::Cancel => return Ok(FlowExit::Cancel),
                }
            }
            _ => {
                let selected_input = input.as_ref().expect("input step completed");
                let selected_output = output_settings.as_ref().expect("output step completed");
                let stem = encrypt_stem(
                    selected_input.file.as_deref(),
                    selected_output.output.as_deref(),
                );
                let paths = planned_encrypt_paths(&stem, selected_output.hash);

                match prompt_encrypt_confirm(selected_input, selected_output, &paths)? {
                    StepValue::Value(true) => {
                        let force = paths.iter().any(|path| path.exists());
                        let result = super::encrypt::execute(EncryptOptions {
                            text: selected_input.text.clone(),
                            output: selected_output.output.clone(),
                            force,
                            hash: selected_output.hash,
                            file: selected_input.file.clone(),
                            encoding: selected_output.encoding,
                            wrap_key: selected_output.wrap_key,
                            password: selected_output.password.clone(),
                            password_file: None,
                        })?;
                        render_encrypt_success(&result);
                        return Ok(FlowExit::Done);
                    }
                    StepValue::Value(false) => return Ok(FlowExit::Cancel),
                    StepValue::Back => step = 3,
                    StepValue::Cancel => return Ok(FlowExit::Cancel),
                }
            }
        }
    }
}

fn prompt_encrypt_source() -> Result<StepValue<EncryptSource>, Box<dyn std::error::Error>> {
    let items = [
        StepMenuItem {
            key: "1",
            title: "Text",
            description: "Type plaintext now",
            aliases: &["text", "t"],
        },
        StepMenuItem {
            key: "2",
            title: "File",
            description: "Encrypt a file from disk",
            aliases: &["file", "f"],
        },
        StepMenuItem {
            key: "3",
            title: "Stdin",
            description: "Read plaintext from pipe",
            aliases: &["stdin", "pipe", "s"],
        },
    ];

    let mut message: Option<&str> = None;
    loop {
        let action = prompt_interactive_step_menu(0, &items, true, |selected| {
            let mut lines = encrypt_header_lines(1);
            lines.push(color(ansi::BOLD, "Choose input source"));
            lines.push(String::new());
            lines.extend(step_choice_lines(
                &items,
                selected,
                true,
                "Return to main menu",
            ));
            if let Some(message) = &message {
                lines.push(color(ansi::RED, message));
                lines.push(String::new());
            }
            lines
        })?;

        match action {
            StepAction::Select(0) => return Ok(StepValue::Value(EncryptSource::Text)),
            StepAction::Select(1) => return Ok(StepValue::Value(EncryptSource::File)),
            StepAction::Select(_) => {
                if io::stdin().is_terminal() {
                    message = Some("  stdin source requires piped input");
                } else {
                    return Ok(StepValue::Value(EncryptSource::Stdin));
                }
            }
            StepAction::Back => return Ok(StepValue::Back),
            StepAction::Cancel => return Ok(StepValue::Cancel),
        }
    }
}

fn prompt_encrypt_input(
    source: EncryptSource,
) -> Result<StepValue<EncryptWizardInput>, Box<dyn std::error::Error>> {
    loop {
        render_encrypt_header(2);
        render_encrypt_progress(2, Some(source));

        match source {
            EncryptSource::Text => {
                eprintln!("{}", color(ansi::BOLD, "Enter plaintext"));
                eprintln!();
                eprintln!(
                    "{}",
                    color(
                        ansi::DIM_WHITE,
                        "Press Enter to finish. Type :back to go back, or :cancel to cancel."
                    )
                );
                eprintln!();
                let answer = prompt_raw_line(&output::prompt_text("Text"))?;
                if let Some(control) = wizard_text_control(&answer) {
                    return Ok(control);
                }
                let size = answer.len();
                return Ok(StepValue::Value(EncryptWizardInput {
                    source,
                    text: Some(answer),
                    file: None,
                    size,
                }));
            }
            EncryptSource::File => {
                eprintln!("{}", color(ansi::BOLD, "Choose file"));
                eprintln!();
                eprintln!(
                    "{}",
                    color(
                        ansi::DIM_WHITE,
                        "Type :back to go back, or :cancel to cancel."
                    )
                );
                eprintln!();
                let answer = prompt_raw_line(&output::prompt_text("File path"))?;
                if let Some(control) = wizard_text_control(&answer) {
                    return Ok(control);
                }
                if answer.is_empty() {
                    output::warn("file path required");
                    continue;
                }
                let file = PathBuf::from(answer);
                let metadata = match std::fs::metadata(&file) {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        output::error(format!("failed to read '{}': {e}", file.display()));
                        continue;
                    }
                };
                if !metadata.is_file() {
                    output::error(format!("'{}' is not a file", file.display()));
                    continue;
                }
                return Ok(StepValue::Value(EncryptWizardInput {
                    source,
                    text: None,
                    file: Some(file),
                    size: metadata.len() as usize,
                }));
            }
            EncryptSource::Stdin => {
                let mut plaintext = Vec::new();
                io::stdin().read_to_end(&mut plaintext)?;
                let text = String::from_utf8(plaintext)?;
                let size = text.len();
                return Ok(StepValue::Value(EncryptWizardInput {
                    source,
                    text: Some(text),
                    file: None,
                    size,
                }));
            }
        }
    }
}

fn encrypt_output_prompt_lines(input: &EncryptWizardInput) -> Vec<String> {
    let default_paths = planned_encrypt_paths(&encrypt_stem(input.file.as_deref(), None), false);
    let default_ciphertext = default_paths[0].display().to_string();

    let mut lines = vec![color(ansi::BOLD, "Choose output"), String::new()];
    lines.extend(output::field_lines(&[
        output::Field {
            label: "Input",
            value: source_description(input.source).to_string(),
        },
        output::Field {
            label: "Size",
            value: format_bytes(input.size),
        },
        output::Field {
            label: "Ciphertext",
            value: default_ciphertext.clone(),
        },
        output::Field {
            label: "Key file",
            value: default_paths[1].display().to_string(),
        },
    ]));
    lines.push(String::new());
    lines.push(color(
        ansi::DIM_WHITE,
        &format!(
            "Leave blank for {default_ciphertext}. Type :back to go back, or :cancel to cancel."
        ),
    ));
    lines.push(String::new());
    lines
}

fn encrypt_output_stem_from_ciphertext_answer(answer: &str) -> Option<String> {
    let answer = answer.trim();
    if answer.is_empty() {
        return None;
    }

    let path = Path::new(answer);
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("otp"))
    {
        return Some(path.with_extension("").display().to_string());
    }

    Some(answer.to_string())
}

fn encrypt_ciphertext_path(file: Option<&Path>, output_stem: Option<&str>) -> PathBuf {
    let stem = encrypt_stem(file, output_stem);
    planned_encrypt_paths(&stem, false)[0].clone()
}

fn prompt_encrypt_output(
    input: &EncryptWizardInput,
) -> Result<StepValue<EncryptWizardOutput>, Box<dyn std::error::Error>> {
    let output_stem = {
        render_encrypt_header(3);
        render_encrypt_progress(3, Some(input.source));
        for line in encrypt_output_prompt_lines(input) {
            eprintln!("{line}");
        }
        let answer = prompt_raw_line(&output::prompt_text(ENCRYPT_CIPHERTEXT_PROMPT))?;
        if let Some(control) = wizard_text_control::<String>(&answer) {
            match control {
                StepValue::Back => return Ok(StepValue::Back),
                StepValue::Cancel => return Ok(StepValue::Cancel),
                StepValue::Value(_) => {}
            }
        }
        encrypt_output_stem_from_ciphertext_answer(&answer)
    };

    let encoding = match prompt_encrypt_encoding(input, output_stem.as_deref())? {
        StepValue::Value(value) => value,
        StepValue::Back => return Ok(StepValue::Back),
        StepValue::Cancel => return Ok(StepValue::Cancel),
    };
    let hash = match prompt_encrypt_bool(
        input,
        output_stem.as_deref(),
        "Write SHA-256 hash file?",
        "Yes",
        "Create integrity file",
        "No",
        "Skip integrity file",
        true,
    )? {
        StepValue::Value(value) => value,
        StepValue::Back => return Ok(StepValue::Back),
        StepValue::Cancel => return Ok(StepValue::Cancel),
    };
    let wrap_key = match prompt_encrypt_bool(
        input,
        output_stem.as_deref(),
        "Password-protect the key file?",
        "Yes",
        "Wrap generated key with a password",
        "No",
        "Write raw key file with mode 0600",
        true,
    )? {
        StepValue::Value(value) => value,
        StepValue::Back => return Ok(StepValue::Back),
        StepValue::Cancel => return Ok(StepValue::Cancel),
    };
    let password = if wrap_key {
        render_encrypt_header(3);
        render_encrypt_progress(3, Some(input.source));
        eprintln!("{}", color(ansi::BOLD, "Set wrapped-key password"));
        eprintln!();
        eprintln!("{}", color(ansi::DIM_WHITE, "Press Ctrl-C to cancel."));
        eprintln!();
        Some(prompt_confirmed_password()?)
    } else {
        None
    };

    Ok(StepValue::Value(EncryptWizardOutput {
        output: output_stem,
        encoding,
        hash,
        wrap_key,
        password,
    }))
}

fn prompt_encrypt_encoding(
    input: &EncryptWizardInput,
    output_stem: Option<&str>,
) -> Result<StepValue<Encoding>, Box<dyn std::error::Error>> {
    let items = [
        StepMenuItem {
            key: "1",
            title: "Raw",
            description: "Binary files, smallest size",
            aliases: &["raw"],
        },
        StepMenuItem {
            key: "2",
            title: "Base64",
            description: "Text-safe output",
            aliases: &["base64", "b64"],
        },
        StepMenuItem {
            key: "3",
            title: "Hex",
            description: "Debug-friendly, larger files",
            aliases: &["hex"],
        },
    ];

    let action = prompt_interactive_step_menu(0, &items, true, |selected| {
        let mut lines = encrypt_header_lines(3);
        lines.extend(encrypt_progress_lines(3, Some(input.source)));
        lines.push(color(ansi::BOLD, "How should files be stored?"));
        lines.push(String::new());
        lines.extend(output::field_lines(&[
            output::Field {
                label: "Input",
                value: source_description(input.source).to_string(),
            },
            output::Field {
                label: "Size",
                value: format_bytes(input.size),
            },
            output::Field {
                label: "Ciphertext",
                value: encrypt_ciphertext_path(input.file.as_deref(), output_stem)
                    .display()
                    .to_string(),
            },
        ]));
        lines.push(String::new());
        lines.extend(step_choice_lines(
            &items,
            selected,
            true,
            "Return to output",
        ));
        lines
    })?;

    Ok(match action {
        StepAction::Select(0) => StepValue::Value(Encoding::Raw),
        StepAction::Select(1) => StepValue::Value(Encoding::Base64),
        StepAction::Select(_) => StepValue::Value(Encoding::Hex),
        StepAction::Back => StepValue::Back,
        StepAction::Cancel => StepValue::Cancel,
    })
}

#[allow(clippy::too_many_arguments)]
fn prompt_encrypt_bool(
    input: &EncryptWizardInput,
    output_stem: Option<&str>,
    heading: &'static str,
    yes_title: &'static str,
    yes_description: &'static str,
    no_title: &'static str,
    no_description: &'static str,
    default: bool,
) -> Result<StepValue<bool>, Box<dyn std::error::Error>> {
    let items = [
        StepMenuItem {
            key: "y",
            title: yes_title,
            description: yes_description,
            aliases: &["yes"],
        },
        StepMenuItem {
            key: "n",
            title: no_title,
            description: no_description,
            aliases: &["no"],
        },
    ];
    let selected = usize::from(!default);

    let action = prompt_interactive_step_menu(selected, &items, true, |selected| {
        let mut lines = encrypt_header_lines(3);
        lines.extend(encrypt_progress_lines(3, Some(input.source)));
        lines.push(color(ansi::BOLD, heading));
        lines.push(String::new());
        lines.extend(output::field_lines(&[
            output::Field {
                label: "Ciphertext",
                value: encrypt_ciphertext_path(input.file.as_deref(), output_stem)
                    .display()
                    .to_string(),
            },
            output::Field {
                label: "Default",
                value: if default { "Yes" } else { "No" }.to_string(),
            },
        ]));
        lines.push(String::new());
        lines.extend(step_choice_lines(
            &items,
            selected,
            true,
            "Return to output",
        ));
        lines
    })?;

    Ok(match action {
        StepAction::Select(0) => StepValue::Value(true),
        StepAction::Select(_) => StepValue::Value(false),
        StepAction::Back => StepValue::Back,
        StepAction::Cancel => StepValue::Cancel,
    })
}

fn prompt_encrypt_confirm(
    input: &EncryptWizardInput,
    settings: &EncryptWizardOutput,
    paths: &[PathBuf],
) -> Result<StepValue<bool>, Box<dyn std::error::Error>> {
    loop {
        render_encrypt_header(4);
        render_encrypt_progress(4, Some(input.source));
        eprintln!("{}", color(ansi::BOLD, "ColdPad will write"));
        eprintln!();
        render_encrypt_write_plan(paths, settings.hash, settings.wrap_key);
        eprintln!();
        if paths.iter().any(|path| path.exists()) {
            output::warn("existing files will be overwritten after confirmation");
            eprintln!();
        }
        eprintln!("{}", color(ansi::BOLD, "Security note"));
        eprintln!();
        eprintln!(
            "  {}",
            color(
                ansi::DIM_WHITE,
                "Keep the key separate from the ciphertext."
            )
        );
        eprintln!(
            "  {}",
            color(
                ansi::DIM_WHITE,
                "Anyone with both files can recover the plaintext."
            )
        );
        eprintln!();
        eprintln!(
            "{}",
            color(
                ansi::DIM_WHITE,
                "Type y to create files, :back to change output, or :cancel to cancel."
            )
        );
        eprintln!();

        let answer = prompt_raw_line("Create these files? [y/N] \u{203a} ")?;
        let answer = answer.trim().to_ascii_lowercase();
        match answer.as_str() {
            "" | "n" | "no" => return Ok(StepValue::Value(false)),
            "y" | "yes" => return Ok(StepValue::Value(true)),
            ":back" => return Ok(StepValue::Back),
            ":cancel" => return Ok(StepValue::Cancel),
            _ => output::warn("answer yes or no"),
        }
    }
}

fn render_encrypt_header(step: usize) {
    clear_wizard_screen();
    for line in encrypt_header_lines(step) {
        eprintln!("{line}");
    }
}

fn render_encrypt_progress(step: usize, source: Option<EncryptSource>) {
    output::progress(&encrypt_progress_items(step, source));
}

fn encrypt_header_lines(step: usize) -> Vec<String> {
    output::workflow_header_lines(
        "coldpad secure / encrypt",
        output::WorkflowStatus::Step(step, 4),
        output::WORKFLOW_WIDTH,
    )
}

fn encrypt_progress_lines(step: usize, source: Option<EncryptSource>) -> Vec<String> {
    vec![
        output::progress_line(&encrypt_progress_items(step, source)),
        String::new(),
    ]
}

fn encrypt_progress_items(
    step: usize,
    source: Option<EncryptSource>,
) -> [output::ProgressItem<'static>; 4] {
    let input_label = match (step, source) {
        (2, Some(EncryptSource::Text)) => "Plaintext",
        (2, Some(EncryptSource::File)) => "File",
        (2, Some(EncryptSource::Stdin)) => "Stdin",
        _ => "Input",
    };
    [
        output::ProgressItem {
            label: "Source",
            state: if step == 1 {
                output::ProgressState::Active
            } else {
                output::ProgressState::Done
            },
        },
        output::ProgressItem {
            label: input_label,
            state: match step {
                1 => output::ProgressState::Pending,
                2 => output::ProgressState::Active,
                _ => output::ProgressState::Done,
            },
        },
        output::ProgressItem {
            label: "Output",
            state: match step {
                1 | 2 => output::ProgressState::Pending,
                3 => output::ProgressState::Active,
                _ => output::ProgressState::Done,
            },
        },
        output::ProgressItem {
            label: "Confirm",
            state: if step == 4 {
                output::ProgressState::Active
            } else {
                output::ProgressState::Pending
            },
        },
    ]
}

fn render_encrypt_write_plan(paths: &[PathBuf], hash: bool, wrap_key: bool) {
    let cipher_path = &paths[0];
    let key_path = &paths[1];
    eprintln!(
        "  {:<12} {:<24} {}",
        "ciphertext",
        cipher_path.display(),
        output::status_new_or_exists(cipher_path)
    );
    let key_note = if wrap_key {
        "mode 0600 wrapped"
    } else {
        "mode 0600"
    };
    eprintln!(
        "  {:<12} {:<24} {:<8} {}",
        "key",
        key_path.display(),
        output::status_new_or_exists(key_path),
        key_note
    );
    if hash {
        let hash_path = &paths[2];
        eprintln!(
            "  {:<12} {:<24} {}",
            "hash",
            hash_path.display(),
            output::status_new_or_exists(hash_path)
        );
    }
}

fn render_encrypt_success(result: &super::encrypt::EncryptResult) {
    output::workflow_header("coldpad secure / encrypt", output::WorkflowStatus::Complete);
    output::success(format!("Encrypted {} bytes", result.ciphertext_bytes));
    eprintln!();
    eprintln!("  {:<12} {}", "ciphertext", result.cipher_path.display());
    let key_note = if result.key_wrapped {
        "mode 0600 wrapped"
    } else {
        "mode 0600"
    };
    eprintln!(
        "  {:<12} {:<24} {}",
        "key",
        result.key_path.display(),
        key_note
    );
    if let Some(hash_path) = &result.hash_path {
        eprintln!("  {:<12} {}", "hash", hash_path.display());
    }
    eprintln!();
    eprintln!("{}", color(ansi::BOLD, "Next command"));
    eprintln!();
    if result.key_wrapped {
        eprintln!(
            "  coldpad decrypt {} --password <password>",
            result.cipher_path.display()
        );
    } else {
        eprintln!("  coldpad decrypt {}", result.cipher_path.display());
    }
    eprintln!();
    eprintln!("Done.");
}

fn source_description(source: EncryptSource) -> &'static str {
    match source {
        EncryptSource::Text => "Text input",
        EncryptSource::File => "File input",
        EncryptSource::Stdin => "Stdin input",
    }
}

fn format_bytes(bytes: usize) -> String {
    format!("{bytes} bytes")
}

fn wizard_text_control<T>(answer: &str) -> Option<StepValue<T>> {
    match answer.trim().to_ascii_lowercase().as_str() {
        ":back" => Some(StepValue::Back),
        ":cancel" => Some(StepValue::Cancel),
        _ => None,
    }
}

fn secure_encrypt() -> Result<FlowExit, Box<dyn std::error::Error>> {
    if crate::prompt::is_interactive_terminal() {
        return secure_encrypt_wizard();
    }

    secure_encrypt_scripted()
}

fn secure_encrypt_scripted() -> Result<FlowExit, Box<dyn std::error::Error>> {
    let source = match prompt_step_menu(
        "encrypt",
        1,
        4,
        "Choose input source",
        &[
            StepMenuItem {
                key: "1",
                title: "Text",
                description: "Type plaintext now",
                aliases: &["text", "t"],
            },
            StepMenuItem {
                key: "2",
                title: "File",
                description: "Encrypt a file from disk",
                aliases: &["file", "f"],
            },
            StepMenuItem {
                key: "3",
                title: "Stdin",
                description: "Read plaintext from pipe",
                aliases: &["stdin", "pipe", "s"],
            },
        ],
        true,
    )? {
        StepAction::Select(source) => source,
        StepAction::Back => return Ok(FlowExit::BackToMenu),
        StepAction::Cancel => return Ok(FlowExit::Cancel),
    };

    let (text, file) = match source {
        0 => {
            render_step_input("encrypt", 1, 4, "Enter plaintext")?;
            let text = prompt_line("Text to encrypt: ")?;
            (Some(text), None)
        }
        1 => {
            render_step_input("encrypt", 1, 4, "Choose file")?;
            (None, Some(prompt_path("File to encrypt: ")?))
        }
        _ => {
            if io::stdin().is_terminal() {
                return Err("stdin source requires piped input".into());
            }
            let mut plaintext = Vec::new();
            io::stdin().read_to_end(&mut plaintext)?;
            (Some(String::from_utf8(plaintext)?), None)
        }
    };

    render_step_input("encrypt", 2, 4, "Choose output")?;
    let output_prompt = if file.is_some() {
        "Output name without extension (leave blank to use the input file name): "
    } else {
        "Output name without extension (leave blank for output): "
    };
    let output = prompt_optional(output_prompt)?;
    let hash = match step_value_or_flow(prompt_step_yes_no(
        "encrypt",
        2,
        4,
        "Write SHA-256 hash file?",
        "Create integrity file",
        "Skip integrity file",
        true,
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    let wrap_key = match step_value_or_flow(prompt_step_yes_no(
        "encrypt",
        2,
        4,
        "Password-protect the key file?",
        "Wrap generated key with a password",
        "Write raw key file",
        true,
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    let encoding = if wrap_key {
        match step_value_or_flow(prompt_step_encoding(
            "encrypt",
            3,
            4,
            "Choose ciphertext encoding",
        )?) {
            Ok(value) => value,
            Err(flow) => return Ok(flow),
        }
    } else {
        match step_value_or_flow(prompt_step_encoding(
            "encrypt",
            3,
            4,
            "Choose ciphertext and key encoding",
        )?) {
            Ok(value) => value,
            Err(flow) => return Ok(flow),
        }
    };
    let stem = encrypt_stem(file.as_deref(), output.as_deref());
    let paths = planned_encrypt_paths(&stem, hash);
    let force = paths.iter().any(|path| path.exists());

    let confirmed = match step_value_or_flow(prompt_step_confirm_writes("encrypt", 4, 4, &paths)?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    if !confirmed {
        return Ok(FlowExit::Cancel);
    }

    let password = if wrap_key {
        render_step_input("encrypt", 4, 4, "Set wrapped-key password")?;
        Some(prompt_confirmed_password()?)
    } else {
        None
    };

    super::encrypt::run(EncryptOptions {
        text,
        output,
        force,
        hash,
        file,
        encoding,
        wrap_key,
        password,
        password_file: None,
    })?;
    Ok(FlowExit::Done)
}

fn secure_decrypt() -> Result<FlowExit, Box<dyn std::error::Error>> {
    render_step_input("decrypt", 1, 4, "Choose ciphertext")?;
    let file = prompt_path("Ciphertext file: ")?;
    let password = prompt_wrapped_key_password(&file)?;
    let write_output = match step_value_or_flow(prompt_step_yes_no(
        "decrypt",
        2,
        4,
        "Write plaintext to a file?",
        "Save plaintext on disk",
        "Print plaintext to stdout",
        false,
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    let output = if write_output {
        render_step_input("decrypt", 2, 4, "Choose output file")?;
        Some(prompt_path("Output file: ")?)
    } else {
        None
    };
    let encoding = match step_value_or_flow(prompt_step_encoding(
        "decrypt",
        3,
        4,
        "Choose ciphertext and key encoding",
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };

    let allow_output_overwrite = if let Some(path) = &output {
        let force = path.exists();
        let confirmed = match step_value_or_flow(prompt_step_confirm_writes(
            "decrypt",
            4,
            4,
            &[path.to_path_buf()],
        )?) {
            Ok(value) => value,
            Err(flow) => return Ok(flow),
        };
        if !confirmed {
            return Ok(FlowExit::Cancel);
        }
        force
    } else {
        true
    };

    super::decrypt::run_with_policy(
        Some(file),
        output,
        encoding,
        allow_output_overwrite,
        password,
        None,
    )?;
    Ok(FlowExit::Done)
}

fn secure_keygen() -> Result<FlowExit, Box<dyn std::error::Error>> {
    render_step_input("keygen", 1, 4, "Choose key length")?;
    let length = prompt_usize("Key length in bytes: ")?;
    render_step_input("keygen", 2, 4, "Choose output file")?;
    let out_path = prompt_optional_path("Output key file (leave blank to generate a file name): ")?
        .unwrap_or_else(default_keygen_name);
    let encoding =
        match step_value_or_flow(prompt_step_encoding("keygen", 3, 4, "Choose key encoding")?) {
            Ok(value) => value,
            Err(flow) => return Ok(flow),
        };
    let force = out_path.exists();

    let confirmed = match step_value_or_flow(prompt_step_confirm_writes(
        "keygen",
        4,
        4,
        std::slice::from_ref(&out_path),
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    if !confirmed {
        return Ok(FlowExit::Cancel);
    }

    super::key::run_generate(Some(length), Some(out_path), force, encoding)?;
    Ok(FlowExit::Done)
}

fn secure_info() -> Result<FlowExit, Box<dyn std::error::Error>> {
    render_step_input("info", 1, 2, "Choose ciphertext")?;
    let file = prompt_path("Ciphertext file: ")?;
    let password = prompt_wrapped_key_password(&file)?;
    let encoding = match step_value_or_flow(prompt_step_encoding(
        "info",
        2,
        2,
        "Choose ciphertext and key encoding",
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    super::info::run(Some(file), encoding, password, None)?;
    Ok(FlowExit::Done)
}

fn secure_wrap_key() -> Result<FlowExit, Box<dyn std::error::Error>> {
    render_step_input("wrap key", 1, 4, "Choose key file")?;
    let key_file = prompt_path("Key file to wrap: ")?;
    render_step_input("wrap key", 2, 4, "Choose output file")?;
    let output = prompt_path("Output wrapped key file: ")?;
    let encoding = match step_value_or_flow(prompt_step_encoding(
        "wrap key",
        3,
        4,
        "Choose input key encoding",
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    let force = output.exists();
    let confirmed = match step_value_or_flow(prompt_step_confirm_writes(
        "wrap key",
        4,
        4,
        std::slice::from_ref(&output),
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    if !confirmed {
        return Ok(FlowExit::Cancel);
    }
    render_step_input("wrap key", 4, 4, "Set wrapped-key password")?;
    let password = prompt_confirmed_password()?;

    super::key::run_wrap(
        Some(key_file),
        Some(output),
        force,
        Some(password),
        None,
        encoding,
    )?;
    Ok(FlowExit::Done)
}

fn secure_unwrap_key() -> Result<FlowExit, Box<dyn std::error::Error>> {
    render_step_input("unwrap key", 1, 4, "Choose wrapped key file")?;
    let key_file = prompt_path("Wrapped key file: ")?;
    render_step_input("unwrap key", 2, 4, "Choose output file")?;
    let output = prompt_path("Output unwrapped key file: ")?;
    let encoding = match step_value_or_flow(prompt_step_encoding(
        "unwrap key",
        3,
        4,
        "Choose output key encoding",
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    let force = output.exists();
    let confirmed = match step_value_or_flow(prompt_step_confirm_writes(
        "unwrap key",
        4,
        4,
        std::slice::from_ref(&output),
    )?) {
        Ok(value) => value,
        Err(flow) => return Ok(flow),
    };
    if !confirmed {
        return Ok(FlowExit::Cancel);
    }
    render_step_input("unwrap key", 4, 4, "Enter wrapped-key password")?;
    let password = prompt_password("Password for wrapped key: ")?;

    super::key::run_unwrap(
        Some(key_file),
        Some(output),
        force,
        Some(password),
        None,
        encoding,
    )?;
    Ok(FlowExit::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_key_actions_support_numbers_letters_and_enter() {
        assert_eq!(workflow_action_for_key(Key::Char('1'), 4), Some(0));
        assert_eq!(workflow_action_for_key(Key::Char('k'), 0), Some(2));
        assert_eq!(workflow_action_for_key(Key::Enter, 5), Some(5));
        assert_eq!(
            workflow_action_for_key(Key::Escape, 0),
            Some(WORKFLOW_ITEMS.len() - 1)
        );
    }

    #[test]
    fn step_key_actions_support_selected_rows_controls_and_aliases() {
        let items = [
            StepMenuItem {
                key: "1",
                title: "Raw",
                description: "Store raw bytes",
                aliases: &["raw"],
            },
            StepMenuItem {
                key: "2",
                title: "Base64",
                description: "Store printable Base64 text",
                aliases: &["base64", "b64"],
            },
            StepMenuItem {
                key: "3",
                title: "Hex",
                description: "Store printable hexadecimal text",
                aliases: &["hex"],
            },
        ];

        assert!(matches!(
            step_action_for_key(Key::Enter, 1, &items, true),
            Some(StepAction::Select(1))
        ));
        assert!(matches!(
            step_action_for_key(Key::Enter, 3, &items, true),
            Some(StepAction::Back)
        ));
        assert!(matches!(
            step_action_for_key(Key::Enter, 4, &items, true),
            Some(StepAction::Cancel)
        ));
        assert!(matches!(
            step_action_for_key(Key::Char('h'), 0, &items, true),
            Some(StepAction::Select(2))
        ));
    }

    #[test]
    fn encrypt_output_prompt_uses_ciphertext_file_copy() {
        let input = EncryptWizardInput {
            source: EncryptSource::Text,
            text: Some("secret".to_string()),
            file: None,
            size: 6,
        };

        let lines = encrypt_output_prompt_lines(&input).join("\n");

        assert!(lines.contains("Choose output"));
        assert!(lines.contains("Ciphertext"));
        assert!(lines.contains("output.otp"));
        assert!(lines.contains("output.otp.key"));
        assert!(lines.contains("Type :back"));
        assert!(lines.contains(":cancel"));
        assert!(!lines.contains("Output stem"));
        assert!(!lines.contains("Back"));
        assert!(!lines.contains("Cancel"));
        assert_eq!(
            output::prompt_text(ENCRYPT_CIPHERTEXT_PROMPT),
            "Ciphertext file \u{203a} "
        );
    }

    #[test]
    fn encrypt_output_stem_accepts_ciphertext_paths() {
        assert_eq!(
            encrypt_ciphertext_path(
                None,
                encrypt_output_stem_from_ciphertext_answer("").as_deref()
            ),
            std::path::PathBuf::from("output.otp")
        );
        assert_eq!(
            encrypt_ciphertext_path(
                Some(std::path::Path::new("plain.txt")),
                encrypt_output_stem_from_ciphertext_answer("").as_deref()
            ),
            std::path::PathBuf::from("plain.txt.otp")
        );
        assert_eq!(
            encrypt_ciphertext_path(
                None,
                encrypt_output_stem_from_ciphertext_answer("secure-out").as_deref()
            ),
            std::path::PathBuf::from("secure-out.otp")
        );
        assert_eq!(
            encrypt_ciphertext_path(
                None,
                encrypt_output_stem_from_ciphertext_answer("secure-out.otp").as_deref()
            ),
            std::path::PathBuf::from("secure-out.otp")
        );
        assert_eq!(
            encrypt_ciphertext_path(
                None,
                encrypt_output_stem_from_ciphertext_answer("dir/secure-out.otp").as_deref()
            ),
            std::path::PathBuf::from("dir/secure-out.otp")
        );
    }
}
