//! Guard approval mutation attempts from agent-controlled shells
//! (`self_approval.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_py::{is_py_space, shlex_split, PyPath};
use crate::sfrs_shlex::{split_with, COMMAND_LEXER};

pub(crate) const SELF_APPROVAL_ACTION_CLASS: &str = "Guard approval self-authorization command";
pub(crate) const SELF_APPROVAL_REASON: &str = "Guard blocks AI agents from approving or weakening Guard approval state from inside a protected shell. Review the original request in the local approval center or native harness prompt.";

const APPROVAL_ROOTS: [&str; 2] = ["approvals", "requests"];
const APPROVAL_MUTATION_COMMANDS: [&str; 6] = [
    "approve",
    "allow",
    "deny",
    "block",
    "clear-history",
    "unlock",
];
const GUARD_BINARIES: [&str; 2] = ["hol-guard", "plugin-guard"];
const PYTHON_MODULES: [&str; 2] = ["codex_plugin_scanner", "codex_plugin_scanner.cli"];
const PYTHON_OPTIONS_WITH_VALUES: [&str; 3] = ["-W", "-X", "--check-hash-based-pycs"];
const RUN_WRAPPERS: [&str; 7] = ["hatch", "mise", "nix", "pipx", "poetry", "uv", "uvx"];
const SHELL_SEPARATORS: [&str; 6] = [";", "&&", "||", "|", "|&", "&"];
const AGENT_ENV_MARKERS: [&str; 10] = [
    "HOL_GUARD_HOOK_ARGV",
    "HOL_GUARD_MANAGED_CURSOR_HOOK",
    "HOL_GUARD_CURSOR_APPROVAL_BINDING",
    "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
    "CURSOR_SESSION_ID",
    "CURSOR_TRACE_ID",
    "CURSOR_TRANSCRIPT_PATH",
    "CLAUDECODE",
    "OPENCODE_CONFIG_CONTENT",
    "CODEX_SANDBOX",
];

/// `is_guard_approval_mutation_command`.
pub(crate) fn is_guard_approval_mutation_command(command_text: &str) -> bool {
    let parts = split_shell_parts(command_text);
    if parts.is_empty() {
        return false;
    }
    shell_segments(&parts)
        .iter()
        .any(|segment| segment_is_guard_approval_mutation(segment, 0))
}

/// `approval_resolution_invoked_from_agent`: a known harness marker is set.
pub(crate) fn approval_resolution_invoked_from_agent(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> bool {
    AGENT_ENV_MARKERS
        .iter()
        .any(|key| lookup(key).is_some_and(|value| !value.trim_matches(is_py_space).is_empty()))
}

/// `_split_shell_parts`: the punctuation lexer, whitespace splitting on error.
pub(crate) fn split_shell_parts(command_text: &str) -> Vec<String> {
    split_with(COMMAND_LEXER, &command_text.replace('\n', " ; ")).unwrap_or_else(|_| {
        command_text
            .split(is_py_space)
            .filter(|piece| !piece.is_empty())
            .map(str::to_owned)
            .collect()
    })
}

/// `_shell_segments`.
pub(crate) fn shell_segments(parts: &[String]) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for part in parts {
        if SHELL_SEPARATORS.contains(&part.as_str()) {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(part.clone());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

/// `_segment_is_guard_approval_mutation`.
pub(crate) fn segment_is_guard_approval_mutation(segment: &[String], depth: usize) -> bool {
    if depth > 3 {
        return false;
    }
    let Some(index) = first_executable_index(segment) else {
        return false;
    };
    let command_name = PyPath::new(&segment[index]).name().to_lowercase();
    if GUARD_BINARIES.contains(&command_name.as_str()) {
        return guard_args_mutate_approvals(&segment[index + 1..]);
    }
    if is_python_interpreter(&command_name) {
        return python_module_args_mutate_approvals(&segment[index + 1..]);
    }
    match runner_wrapper_tail(&command_name, &segment[index + 1..]) {
        Some(tail) => segment_is_guard_approval_mutation(&tail, depth + 1),
        None => false,
    }
}

/// `_first_executable_index`.
pub(crate) fn first_executable_index(segment: &[String]) -> Option<usize> {
    segment
        .iter()
        .position(|token| !token.is_empty() && !looks_env_assignment(token))
}

/// `_looks_env_assignment`.
pub(crate) fn looks_env_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '_') && characters.all(|c| c.is_alphanumeric() || c == '_')
}

/// `_is_python_interpreter`.
pub(crate) fn is_python_interpreter(command_name: &str) -> bool {
    command_name == "python"
        || command_name == "py"
        || command_name.starts_with("python")
        || command_name.starts_with("py3")
}

/// `_python_module_args_mutate_approvals`.
pub(crate) fn python_module_args_mutate_approvals(args: &[String]) -> bool {
    let mut index = 0usize;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "-m" && index + 1 < args.len() {
            let module_name = args[index + 1].trim_matches(is_py_space);
            if PYTHON_MODULES.contains(&module_name) {
                return guard_args_mutate_approvals(&args[index + 2..]);
            }
            return false;
        }
        if token == "-c" {
            return false;
        }
        if PYTHON_OPTIONS_WITH_VALUES.contains(&token) {
            index += 2;
            continue;
        }
        if PYTHON_OPTIONS_WITH_VALUES.iter().any(|option| {
            token
                .strip_prefix(option)
                .is_some_and(|rest| rest.starts_with('='))
        }) {
            index += 1;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        return false;
    }
    false
}

/// `_runner_wrapper_tail`.
pub(crate) fn runner_wrapper_tail(command_name: &str, args: &[String]) -> Option<Vec<String>> {
    if !RUN_WRAPPERS.contains(&command_name) {
        return None;
    }
    match command_name {
        "uv" => {
            if args.first().is_some_and(|first| first == "tool") {
                return tail_after_subcommand(&args[1..], &["run"]);
            }
            tail_after_subcommand(args, &["run"])
        }
        "uvx" => Some(args.to_vec()),
        "pipx" | "poetry" | "hatch" => tail_after_subcommand(args, &["run"]),
        "mise" => tail_after_subcommand(args, &["exec"]),
        "nix" => tail_after_flag(args, "--command"),
        _ => None,
    }
}

/// `_tail_after_subcommand`.
pub(crate) fn tail_after_subcommand(args: &[String], subcommands: &[&str]) -> Option<Vec<String>> {
    for (index, token) in args.iter().enumerate() {
        if token == "--" {
            break;
        }
        if subcommands.contains(&token.as_str()) {
            let mut tail = &args[index + 1..];
            if tail.first().is_some_and(|first| first == "--") {
                tail = &tail[1..];
            }
            return Some(tail.to_vec());
        }
    }
    None
}

/// `_tail_after_flag`.
pub(crate) fn tail_after_flag(args: &[String], flag: &str) -> Option<Vec<String>> {
    for (index, token) in args.iter().enumerate() {
        if token == flag {
            let remaining = &args[index + 1..];
            if remaining.is_empty() {
                return Some(Vec::new());
            }
            return Some(shlex_split(&remaining.join(" ")).unwrap_or_else(|| remaining.to_vec()));
        }
        if let Some(value) = token
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(shlex_split(value).unwrap_or_default());
        }
    }
    None
}

/// `_guard_args_mutate_approvals`.
pub(crate) fn guard_args_mutate_approvals(args: &[String]) -> bool {
    let args = if args.first().is_some_and(|first| first == "guard") {
        &args[1..]
    } else {
        args
    };
    for (index, token) in args.iter().enumerate() {
        if !APPROVAL_ROOTS.contains(&token.as_str()) {
            continue;
        }
        return approval_tail_has_mutation(&args[index + 1..]);
    }
    false
}

/// `_approval_tail_has_mutation`.
pub(crate) fn approval_tail_has_mutation(args: &[String]) -> bool {
    for token in args {
        if token.starts_with('-') {
            continue;
        }
        return APPROVAL_MUTATION_COMMANDS.contains(&token.as_str());
    }
    false
}
