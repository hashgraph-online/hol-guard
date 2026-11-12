//! Editor and dev container settings that run a command without being asked.
//!
//! A VS Code task whose `runOptions.runOn` is `folderOpen` runs as soon as
//! the folder is opened, and editors that skip the workspace trust prompt run
//! it without any other step. A dev container's `initializeCommand` runs on
//! the host, outside the container, whenever the container is built or
//! started. Cloned repositories use both to run code the moment someone opens
//! them.
//!
//! These rules read the configuration's text only. Both files are JSON with
//! comments and trailing commas, so the rules strip those and parse the
//! result; a file that still does not parse is matched by its text and
//! reported as unparsed, so the scan does not claim it saw the file whole.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

#[cfg(test)]
#[path = "editor_task_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditorTaskRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const FOLDER_OPEN_TASK: EditorTaskRule = EditorTaskRule {
    id: "editor.task.folder-open",
    category: "execution",
    severity: "high",
    confidence: "likely",
    title: "Editor task runs when the folder is opened",
    reason: "A VS Code task in this project is set to run when the folder is opened, so opening the repository in an editor that runs automatic tasks executes its command with no other step.",
    false_positive_hint: Some(
        "Expected when the maintainers start a watcher or dev server this way; read the task's command before opening the folder in an editor that runs automatic tasks.",
    ),
};

pub const DEVCONTAINER_INITIALIZE: EditorTaskRule = EditorTaskRule {
    id: "devcontainer.initialize-command",
    category: "execution",
    severity: "medium",
    confidence: "likely",
    title: "Dev container runs a command on the host",
    reason: "The dev container configuration sets initializeCommand, which runs on the host machine, outside the container, whenever the container is built or started from this project.",
    false_positive_hint: Some(
        "Often used to create a folder or file the container mounts; read the command before building the container.",
    ),
};

/// Which kind of configuration a file is, which decides the rule it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorConfig {
    /// `.vscode/tasks.json` or a `.code-workspace` file, which can hold tasks.
    Tasks,
    /// A `devcontainer.json`.
    DevContainer,
}

/// The rules one configuration matched, and whether it parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorTaskCheck {
    pub rules: Vec<EditorTaskRule>,
    pub parsed: bool,
}

static RUN_ON_FOLDER_OPEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""runOn"\s*:\s*"(?i:folderopen)""#).expect("valid runOn pattern")
});
/// A key with a value that is not `null`, a blank string or an empty list or
/// object.
static INITIALIZE_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""initializeCommand"\s*:\s*(?:"\s*[^"\s]|\[\s*[^\s\]]|\{\s*[^\s}])"#)
        .expect("valid initializeCommand pattern")
});

/// The rules the configuration `text` of kind `config` matches.
pub fn detect_editor_task_risk(config: EditorConfig, text: &str) -> EditorTaskCheck {
    // Editors accept a file saved with a byte order mark; JSON parsers do not.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let stripped = strip_trailing_commas(&strip_comments(text));
    let parsed: Option<Value> = serde_json::from_str(&stripped).ok();
    let found = match (config, parsed.as_ref()) {
        (EditorConfig::Tasks, Some(value)) => runs_on_folder_open(value),
        (EditorConfig::Tasks, None) => RUN_ON_FOLDER_OPEN.is_match(&stripped),
        (EditorConfig::DevContainer, Some(value)) => {
            value.get("initializeCommand").is_some_and(is_command)
        }
        (EditorConfig::DevContainer, None) => INITIALIZE_COMMAND.is_match(&stripped),
    };
    let rule = match config {
        EditorConfig::Tasks => FOLDER_OPEN_TASK,
        EditorConfig::DevContainer => DEVCONTAINER_INITIALIZE,
    };
    EditorTaskCheck {
        rules: if found { vec![rule] } else { Vec::new() },
        parsed: parsed.is_some(),
    }
}

/// Whether any `runOptions` object in `value` runs on folder open. Tasks sit
/// in a `tasks` list, a workspace file's `tasks` object or a platform
/// override, so every level is searched. VS Code reads the value without
/// regard to case.
fn runs_on_folder_open(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, field)| {
            (key == "runOptions"
                && field
                    .get("runOn")
                    .and_then(Value::as_str)
                    .is_some_and(|run_on| run_on.eq_ignore_ascii_case("folderOpen")))
                || runs_on_folder_open(field)
        }),
        Value::Array(items) => items.iter().any(runs_on_folder_open),
        _ => false,
    }
}

/// A command in any of the forms dev containers accept: a string, a list of
/// arguments or an object of named commands. An empty one runs nothing.
fn is_command(value: &Value) -> bool {
    match value {
        Value::String(command) => !command.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(commands) => !commands.is_empty(),
        _ => false,
    }
}

/// `text` with `//` and `/* */` comments outside strings replaced by spaces,
/// keeping line breaks.
fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut previous = '\0';
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        out.push('\n');
                    }
                    if previous == '*' && skipped == '/' {
                        break;
                    }
                    previous = skipped;
                }
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

/// `text` without a comma that is followed only by whitespace before a
/// closing bracket or brace, outside strings.
fn strip_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut index = 0;
    while index < chars.len() {
        let c = chars[index];
        index += 1;
        if in_string {
            out.push(c);
            if c == '\\' && index < chars.len() {
                out.push(chars[index]);
                index += 1;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        }
        if c == ',' {
            let next = chars[index..].iter().find(|next| !next.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}
