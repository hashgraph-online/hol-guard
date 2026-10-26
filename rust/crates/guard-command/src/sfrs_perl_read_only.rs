//! Read-only Perl filter validation
//! (`secret_file_request_services/perl_read_only.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, shlex_split, PyPath};
use crate::sfrs_requests::classify_sensitive_path;
use crate::sfrs_static_safety::{shell_token_has_command_substitution, which_for_execution_cwd};

const PERL_ENVIRONMENT_KEYS: [&str; 6] = [
    "PERL5DB",
    "PERL5LIB",
    "PERL5OPT",
    "PERLIO",
    "PERLIO_DEBUG",
    "PERLLIB",
];
const PRINT_IF_PREFIX: &str = "print if /";

/// `_looks_like_read_only_perl_filter`: Perl's read loop with a literal
/// print-if-regex program over bounded workspace files.
pub(crate) fn looks_like_read_only_perl_filter(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let Some(tokens) = shlex_split(command_text) else {
        return false;
    };
    if tokens.len() < 4 || PyPath::new(&tokens[0]).name().to_lowercase() != "perl" {
        return false;
    }
    let (Some(cwd), Some(home_dir)) = (cwd, home_dir) else {
        return false;
    };
    if !perl_execution_environment_is_safe(ctx) {
        return false;
    }
    let cwd_path = absolute(&PyPath::new(&cwd.to_string_lossy()), ctx);
    if !trusted_perl_command(&tokens[0], &cwd_path, ctx) {
        return false;
    }
    let script_index = if tokens[1] == "-ne" {
        2
    } else if tokens.len() >= 5 && tokens[1] == "-n" && tokens[2] == "-e" {
        3
    } else {
        return false;
    };
    let Some(pattern) = perl_print_if_pattern(&tokens[script_index]) else {
        return false;
    };
    if pattern.chars().count() > 4096
        || ["(?{", "(??{", "${", "`"]
            .iter()
            .any(|marker| pattern.contains(marker))
        || has_unescaped_at(&pattern)
        || has_unescaped_dollar(&pattern)
    {
        return false;
    }
    let operands = &tokens[script_index + 1..];
    if operands.is_empty() {
        return false;
    }
    let Ok(canonical) = fs::canonicalize(cwd_path.to_string()) else {
        return false;
    };
    let workspace = PyPath::new(&canonical.to_string_lossy());
    operands
        .iter()
        .all(|operand| operand_is_safe(operand, &workspace, home_dir))
}

fn operand_is_safe(operand: &str, workspace: &PyPath, home_dir: &Path) -> bool {
    if operand == "-"
        || operand.starts_with(['-', '~'])
        || operand.contains('$')
        || operand.contains(['|', '<', '>', '\n', '\0'])
        || shell_token_has_command_substitution(operand)
    {
        return false;
    }
    let candidate = PyPath::new(operand);
    let target = if candidate.is_absolute() {
        candidate
    } else {
        workspace.join(operand)
    };
    let Ok(resolved) = fs::canonicalize(target.to_string()) else {
        return false;
    };
    let resolved = PyPath::new(&resolved.to_string_lossy());
    if pyfs::is_symlink(&target) != Ok(false)
        || resolved.relative_to(workspace).is_none()
        || pyfs::is_file(&resolved) != Ok(true)
    {
        return false;
    }
    classify_sensitive_path(
        &resolved.to_string(),
        Some(Path::new(&workspace.to_string())),
        Some(home_dir),
    )
    .is_none()
}

/// `(?<!\\)(?:\\\\)*@`: an `@` preceded by an even run of backslashes.
fn has_unescaped_at(pattern: &str) -> bool {
    unescaped_positions(pattern, '@').next().is_some()
}

/// `(?<!\\)(?:\\\\)*\$(?!$|[)|])`: an unescaped `$` that is neither at the end
/// (or before a final newline) nor before `)` or `|`.
fn has_unescaped_dollar(pattern: &str) -> bool {
    unescaped_positions(pattern, '$').any(|rest| {
        !(rest.is_empty() || rest == "\n" || rest.starts_with(')') || rest.starts_with('|'))
    })
}

/// The text after each `marker` preceded by an even run of backslashes.
fn unescaped_positions(pattern: &str, marker: char) -> impl Iterator<Item = &str> {
    pattern
        .char_indices()
        .filter_map(move |(index, character)| {
            if character != marker {
                return None;
            }
            let slashes = pattern[..index]
                .chars()
                .rev()
                .take_while(|c| *c == '\\')
                .count();
            (slashes % 2 == 0).then(|| &pattern[index + character.len_utf8()..])
        })
}

/// `_perl_execution_environment_is_safe`.
pub(crate) fn perl_execution_environment_is_safe(ctx: &Ctx) -> bool {
    !PERL_ENVIRONMENT_KEYS.iter().any(|key| {
        ctx.host
            .env(key)
            .is_some_and(|value| !py_strip(&value).is_empty())
    })
}

fn absolute(path: &PyPath, ctx: &Ctx) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        ctx.process_cwd.join(&path.to_string())
    }
}

/// `_trusted_perl_command`: the Perl on the search path, bound to the request.
pub(crate) fn trusted_perl_command(command: &str, cwd: &PyPath, ctx: &Ctx) -> bool {
    let Some(located) = which_for_execution_cwd("perl", Path::new(&cwd.to_string()), ctx) else {
        return false;
    };
    let Ok(resolved) = fs::canonicalize(&located) else {
        return false;
    };
    let requested = PyPath::new(command);
    if requested.name() != command {
        let requested_path = if requested.is_absolute() {
            requested
        } else {
            cwd.join(command)
        };
        match fs::canonicalize(requested_path.to_string()) {
            Ok(path) if path == resolved => {}
            _ => return false,
        }
    }
    ctx.host
        .git_binary_trusted(&resolved.to_string_lossy(), &cwd.to_string())
}

/// `_perl_print_if_pattern`: the regex of a literal `print if /.../flags`.
pub(crate) fn perl_print_if_pattern(script: &str) -> Option<String> {
    let rest = script.strip_prefix(PRINT_IF_PREFIX)?;
    let mut escaped = false;
    let mut pattern = String::new();
    for (index, character) in rest.char_indices() {
        if escaped {
            pattern.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            pattern.push(character);
            escaped = true;
            continue;
        }
        if character != '/' {
            pattern.push(character);
            continue;
        }
        let flags = &rest[index + 1..];
        return flags
            .chars()
            .all(|flag| matches!(flag, 'i' | 'm' | 's' | 'x'))
            .then_some(pattern);
    }
    None
}
