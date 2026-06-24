use std::fmt::Display;
use std::path::Path;

use crate::terminal::{ansi, color};

pub const WORKFLOW_WIDTH: usize = 72;

pub enum WorkflowStatus<'a> {
    Step(usize, usize),
    Complete,
    Label(&'a str),
}

pub enum ProgressState {
    Done,
    Active,
    Pending,
}

pub struct ProgressItem<'a> {
    pub label: &'a str,
    pub state: ProgressState,
}

pub struct ChoiceRow<'a> {
    pub selected: bool,
    pub key: &'a str,
    pub label: &'a str,
    pub description: &'a str,
}

pub struct Field<'a> {
    pub label: &'a str,
    pub value: String,
}

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

pub fn workflow_header(path: &str, status: WorkflowStatus<'_>) {
    for line in workflow_header_lines(path, status, WORKFLOW_WIDTH) {
        eprintln!("{line}");
    }
}

pub fn workflow_header_lines(path: &str, status: WorkflowStatus<'_>, width: usize) -> Vec<String> {
    let status_text = match status {
        WorkflowStatus::Step(step, total) => format!("step {step} of {total}"),
        WorkflowStatus::Complete => "complete".to_string(),
        WorkflowStatus::Label(label) => label.to_string(),
    };
    let gap = width.saturating_sub(path.len() + status_text.len()).max(1);
    let path = color(ansi::BOLD_GREEN, path);
    let status = color(ansi::DIM_WHITE, &status_text);

    vec![
        format!("{path}{}{status}", " ".repeat(gap)),
        color(ansi::DIM_WHITE, "guided one-time-pad workflow"),
        color(ansi::DIM_WHITE, &divider(width)),
        String::new(),
    ]
}

pub fn divider(width: usize) -> String {
    "\u{2500}".repeat(width)
}

pub fn progress(items: &[ProgressItem<'_>]) {
    eprintln!("{}", progress_line(items));
    eprintln!();
}

pub fn progress_line(items: &[ProgressItem<'_>]) -> String {
    items
        .iter()
        .map(|item| {
            let marker = match item.state {
                ProgressState::Done => color(ansi::GREEN, "\u{2713}"),
                ProgressState::Active => color(ansi::BOLD_GREEN, ">"),
                ProgressState::Pending => " ".to_string(),
            };
            let label = match item.state {
                ProgressState::Active => color(ansi::BOLD, item.label),
                ProgressState::Done | ProgressState::Pending => item.label.to_string(),
            };
            format!("[{marker}] {label}")
        })
        .collect::<Vec<_>>()
        .join("   ")
}

pub fn choice_row_lines(rows: &[ChoiceRow<'_>]) -> Vec<String> {
    let key_width = rows
        .iter()
        .map(|row| row.key.len())
        .max()
        .unwrap_or(1)
        .max(2);
    let label_width = rows
        .iter()
        .map(|row| row.label.len())
        .max()
        .unwrap_or(1)
        .max(8);

    rows.iter()
        .map(|row| {
            let marker = if row.selected {
                color(ansi::BOLD_GREEN, ">")
            } else {
                " ".to_string()
            };
            let key = color(ansi::BOLD_YELLOW, &format!("{:>key_width$}", row.key));
            let label_text = format!("{:<label_width$}", row.label);
            let label = color(ansi::BOLD, &label_text);
            let description = color(ansi::DIM_WHITE, row.description);
            format!("  {marker}  {key}   {label} {description}")
        })
        .collect()
}

pub fn field_lines(fields: &[Field<'_>]) -> Vec<String> {
    let label_width = fields
        .iter()
        .map(|field| field.label.len())
        .max()
        .unwrap_or(1)
        .max(8);

    fields
        .iter()
        .map(|field| field_line(field.label, &field.value, label_width))
        .collect()
}

fn field_line(label: &str, value: &str, label_width: usize) -> String {
    let label = color(ansi::DIM_WHITE, &format!("{label:<label_width$}"));
    format!("  {label}  {value}")
}

pub fn prompt_choice(label: &str) -> String {
    format!("{label} \u{203a} ")
}

pub fn prompt_text(label: &str) -> String {
    prompt_choice(label)
}

pub fn status_new_or_exists(path: &Path) -> &'static str {
    if path.exists() { "exists" } else { "new" }
}

pub fn error(msg: impl Display) {
    eprintln!("{}", color(ansi::RED, &format!("  {msg}")));
}
