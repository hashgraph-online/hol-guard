//! What a program launch read from configuration would do, without running it.
//!
//! An MCP server names a program and its arguments; a hook names a shell
//! command. Both reach a POSIX shell script the same way: directly, through
//! `env` (including a `-S` split string), through privilege wrappers in any
//! order, or through a shell's `-c` inside another script. The script then
//! runs the pipeline screen the pre-tool hook applies to an agent's shell
//! commands, so downloaded code and environment exfiltration are named the
//! same way everywhere. Windows `cmd /c` and PowerShell scripts are not read.

use crate::parser_segments::{shell_tokens, split_pipelines_including_background};
use crate::pretool::pipe_attacks::{pipe_attacks, ENVIRONMENT_EXFILTRATION, REMOTE_CODE};
use crate::{parse_command, CommandModelRequestV1};

#[cfg(test)]
#[path = "launch_screen_tests.rs"]
mod tests;

/// What one launch would do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchRisk {
    pub remote_code: bool,
    pub environment_exfiltration: bool,
    pub privileged: bool,
}

const SHELLS: &[&str] = &["ash", "bash", "dash", "fish", "ksh", "mksh", "sh", "zsh"];
const PRIVILEGE_WRAPPERS: &[&str] = &["doas", "gsudo", "pkexec", "run0", "sudo"];
const PRIVILEGE_VALUE_OPTIONS: &[&str] = &[
    "-C", "-D", "-U", "-g", "-h", "-p", "-r", "-t", "-u", "--chdir", "--group", "--user",
];
const ENV_VALUE_OPTIONS: &[&str] = &["-C", "-u", "--chdir", "--unset"];
const SHELL_VALUE_OPTIONS: &[&str] = &["+O", "+o", "-O", "-o", "--init-file", "--rcfile"];
/// Scripts parsed for one launch, nested or side by side. A launch that
/// nests deeper than this keeps what was found so far.
const MAX_SCRIPTS: usize = 16;
/// Wrappers unwrapped before one program, so a crafted chain stays bounded.
const MAX_WRAPPERS: usize = 32;

/// The risk of launching `argv[0]` with the rest as its arguments.
pub fn screen_argv(argv: &[String]) -> LaunchRisk {
    let mut screen = Screen::default();
    screen.argv(argv);
    screen.risk
}

/// The risk of running `script` with `sh -c`.
pub fn screen_script(script: &str) -> LaunchRisk {
    let mut screen = Screen::default();
    screen.script(script);
    screen.risk
}

#[derive(Default)]
struct Screen {
    risk: LaunchRisk,
    scripts: usize,
}

impl Screen {
    fn argv(&mut self, argv: &[String]) {
        let mut argv = after_assignments(argv).to_vec();
        for _ in 0..MAX_WRAPPERS {
            if let Some(next) = after_env(&argv) {
                argv = next;
            } else if let Some(next) = after_privilege(&argv) {
                self.risk.privileged = true;
                // `sudo` runs `VAR=value` words before the program as assignments.
                argv = after_assignments(&next).to_vec();
            } else {
                break;
            }
        }
        if let Some(script) = shell_script(&argv) {
            self.script(script);
        }
    }

    fn script(&mut self, script: &str) {
        if self.scripts >= MAX_SCRIPTS {
            return;
        }
        self.scripts += 1;
        let Ok(model) = parse_command(&shell_request(script)) else {
            return;
        };
        for attack in pipe_attacks(&model) {
            self.risk.remote_code |= attack == REMOTE_CODE;
            self.risk.environment_exfiltration |= attack == ENVIRONMENT_EXFILTRATION;
        }
        self.risk.privileged |= model.segments.iter().any(|segment| {
            segment
                .executable
                .as_deref()
                .is_some_and(is_privilege_wrapper)
                || segment
                    .wrapper_chain
                    .iter()
                    .any(|wrapper| is_privilege_wrapper(wrapper))
        });
        // A nested shell launch leaves the model uncertain and without
        // segments, so each command is split from the raw script, as the
        // pipeline screen does.
        let preserve_backslash = cfg!(windows);
        let Ok(commands) = split_pipelines_including_background(script, preserve_backslash) else {
            return;
        };
        let chars: Vec<char> = script.chars().collect();
        for command in commands {
            let text: String = chars[command.start..command.end].iter().collect();
            if let Ok(words) = shell_tokens(&text, preserve_backslash) {
                self.argv(&words);
            }
        }
    }
}

fn shell_request(script: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: script.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

/// The program name without its directory or a Windows `.exe` suffix.
fn program(word: &str) -> &str {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    match name.len().checked_sub(4) {
        Some(stem) if name.is_char_boundary(stem) && name[stem..].eq_ignore_ascii_case(".exe") => {
            &name[..stem]
        }
        _ => name,
    }
}

fn is_privilege_wrapper(word: &str) -> bool {
    PRIVILEGE_WRAPPERS.contains(&program(word))
}

fn after_assignments(argv: &[String]) -> &[String] {
    let start = argv
        .iter()
        .position(|word| !is_assignment(word))
        .unwrap_or(argv.len());
    &argv[start..]
}

/// The words a leading `env` runs, after its options and assignments. A
/// `-S` split string is split into words in place, as `env` does.
fn after_env(argv: &[String]) -> Option<Vec<String>> {
    if argv.first().map(|word| program(word)) != Some("env") {
        return None;
    }
    let mut index = 1;
    while let Some(word) = argv.get(index) {
        let split = if word == "-S" || word == "--split-string" {
            Some((argv.get(index + 1).map_or("", String::as_str), index + 2))
        } else if let Some(value) = word.strip_prefix("--split-string=") {
            Some((value, index + 1))
        } else {
            word.strip_prefix("-S")
                .filter(|value| !value.is_empty())
                .map(|value| (value, index + 1))
        };
        if let Some((value, next)) = split {
            let mut words = vec!["env".to_owned()];
            words.extend(shell_tokens(value, false).unwrap_or_default());
            words.extend_from_slice(argv.get(next..).unwrap_or_default());
            return Some(words);
        }
        if word == "--" {
            index += 1;
            break;
        }
        if ENV_VALUE_OPTIONS.contains(&word.as_str()) {
            index += 2;
        } else if word.starts_with('-') || is_assignment(word) {
            index += 1;
        } else {
            break;
        }
    }
    Some(argv.get(index..).unwrap_or_default().to_vec())
}

/// The words a leading privilege wrapper runs, after its options.
fn after_privilege(argv: &[String]) -> Option<Vec<String>> {
    if !is_privilege_wrapper(argv.first()?) {
        return None;
    }
    let mut index = 1;
    while let Some(word) = argv.get(index) {
        if word == "--" {
            index += 1;
            break;
        }
        if PRIVILEGE_VALUE_OPTIONS.contains(&word.as_str()) {
            index += 2;
        } else if word.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    Some(argv.get(index..).unwrap_or_default().to_vec())
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The script a shell launch runs with `-c` (or fish's `--command`).
fn shell_script(argv: &[String]) -> Option<&str> {
    if !SHELLS.contains(&program(argv.first()?)) {
        return None;
    }
    let mut runs_script = false;
    let mut words = argv[1..].iter().map(String::as_str);
    while let Some(word) = words.next() {
        if word == "--command" {
            return words.next();
        }
        if let Some(script) = word.strip_prefix("--command=") {
            return Some(script);
        }
        if word == "--" {
            break;
        }
        if SHELL_VALUE_OPTIONS.contains(&word) {
            words.next();
        } else if word.starts_with("--") {
            continue;
        } else if let Some(cluster) = word.strip_prefix('-').filter(|cluster| !cluster.is_empty()) {
            runs_script |= cluster.contains('c');
        } else if word.starts_with('+') && word.len() > 1 {
            continue;
        } else {
            return runs_script.then_some(word);
        }
    }
    if runs_script {
        words.next()
    } else {
        None
    }
}
