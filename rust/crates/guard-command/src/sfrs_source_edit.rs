//! Literal in-place `sed` edits inside a bounded workspace
//! (`source_edit_context.py`: the sed script and workspace checks).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{is_py_space, py_strip, PyPath};
use crate::command_option_parsing::python_is_alphanumeric;
use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;

const REGEX_METACHARACTERS: &str = ".^$*+?[]()|";
const WORKSPACE_MARKERS: [&str; 5] = [
    ".git",
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
];

fn is_delimiter_rejected(character: char) -> bool {
    python_is_alphanumeric(character) || is_py_space(character) || character == '\\'
}

/// `_split_literal_sed_commands`; empty when the script is not a bounded list.
pub(crate) fn split_literal_sed_commands(script: &str) -> Vec<String> {
    let chars: Vec<char> = script.chars().collect();
    let mut commands: Vec<String> = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        while index < chars.len() && is_py_space(chars[index]) {
            index += 1;
        }
        let start = index;
        if index + 1 >= chars.len() || chars[index] != 's' {
            return Vec::new();
        }
        let delimiter = chars[index + 1];
        if is_delimiter_rejected(delimiter) {
            return Vec::new();
        }
        index += 2;
        let mut terminated_fields = 0;
        let mut escaped = false;
        while index < chars.len() && terminated_fields < 2 {
            let character = chars[index];
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                terminated_fields += 1;
            }
            index += 1;
        }
        if escaped || terminated_fields != 2 {
            return Vec::new();
        }
        while index < chars.len() && chars[index] != ';' {
            index += 1;
        }
        let command: String = chars[start..index].iter().collect();
        let command = py_strip(&command);
        if command.is_empty() {
            return Vec::new();
        }
        commands.push(command.to_owned());
        if commands.len() > 16 {
            return Vec::new();
        }
        if index < chars.len() {
            index += 1;
        }
    }
    commands
}

/// `_literal_sed_script_is_safe`.
pub(crate) fn literal_sed_script_is_safe(script: &str) -> bool {
    let commands = split_literal_sed_commands(script);
    (1..=16).contains(&commands.len())
        && commands
            .iter()
            .all(|command| literal_sed_substitution_is_safe(command))
}

/// `_literal_sed_substitution_is_safe`.
pub(crate) fn literal_sed_substitution_is_safe(script: &str) -> bool {
    let chars: Vec<char> = script.chars().collect();
    if chars.len() > 4096 || chars.len() < 5 || chars[0] != 's' {
        return false;
    }
    let delimiter = chars[1];
    if is_delimiter_rejected(delimiter) {
        return false;
    }
    let mut fields: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for &character in &chars[2..] {
        if escaped {
            current.push('\\');
            current.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == delimiter && fields.len() < 2 {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(character);
        }
    }
    if escaped || fields.len() != 2 {
        return false;
    }
    let (pattern, replacement) = (&fields[0], &fields[1]);
    !pattern.is_empty()
        && (current.is_empty() || current == "g")
        && sed_pattern_is_literal(pattern, delimiter)
        && sed_replacement_is_literal(replacement, delimiter)
}

/// `_sed_pattern_is_literal`.
pub(crate) fn sed_pattern_is_literal(pattern: &str, delimiter: char) -> bool {
    sed_pattern_is_literal_with_delimiter(pattern, Some(delimiter))
}

pub(crate) fn sed_pattern_is_literal_with_delimiter(
    pattern: &str,
    delimiter: Option<char>,
) -> bool {
    let mut escaped = false;
    for character in pattern.chars() {
        if escaped {
            if !(REGEX_METACHARACTERS.contains(character)
                || Some(character) == delimiter
                || character == '\\')
            {
                return false;
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if REGEX_METACHARACTERS.contains(character) {
            return false;
        }
    }
    !escaped
}

/// `_sed_replacement_is_literal`.
pub(crate) fn sed_replacement_is_literal(replacement: &str, delimiter: char) -> bool {
    sed_replacement_is_literal_with_delimiter(replacement, Some(delimiter))
}

pub(crate) fn sed_replacement_is_literal_with_delimiter(
    replacement: &str,
    delimiter: Option<char>,
) -> bool {
    let mut escaped = false;
    for character in replacement.chars() {
        if escaped {
            if !(Some(character) == delimiter || matches!(character, '\\' | '&' | '$')) {
                return false;
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '&' | '\n' | '$') {
            return false;
        }
    }
    !escaped
}

pub(crate) fn py_path(path: &Path) -> PyPath {
    PyPath::new(&path.to_string_lossy())
}

/// `Path.resolve(strict=True)`; `None` is the `OSError`/`RuntimeError`.
pub(crate) fn resolve_strict(path: &PyPath) -> Option<PyPath> {
    // `realpath(strict=True)` raises at the first missing component, which the
    // non-strict resolver would otherwise tidy away (`missing/../file`).
    let components = path.components();
    for end in 1..=components.len() {
        let prefix = PyPath::new(&format!("{}{}", path.root(), components[..end].join("/")));
        if pyfs::exists(&prefix) != Ok(true) {
            return None;
        }
    }
    let resolved = pyfs::resolve(path)?;
    (pyfs::exists(&resolved) == Ok(true)).then_some(resolved)
}

/// `os.path.abspath` for an absolute POSIX path.
fn normalized(path: &PyPath) -> PyPath {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.components() {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    PyPath::new(&format!("{}{}", path.root(), parts.join("/")))
}

/// `_bounded_edit_workspace_is_safe`.
pub(crate) fn bounded_edit_workspace_is_safe(workspace_root: &Path, home_dir: &Path) -> bool {
    let Some(home) = resolve_strict(&py_path(home_dir)) else {
        return false;
    };
    let workspace = py_path(workspace_root);
    let Some(relative) = workspace.relative_to(&home) else {
        return false;
    };
    if relative.first().is_none_or(|part| part.starts_with('.')) {
        return false;
    }
    WORKSPACE_MARKERS
        .iter()
        .any(|marker| pyfs::exists(&workspace.join(marker)) == Ok(true))
}

/// `_bounded_in_place_sed_target`: the single file operand of `sed -i ''`.
pub(crate) fn bounded_in_place_sed_target(
    args: &[String],
    cwd: &Path,
    workspace_root: &Path,
) -> Option<String> {
    if args.len() < 4 || args[0] != "-i" || !args[1].is_empty() {
        return None;
    }
    let mut scripts: Vec<&str> = Vec::new();
    let mut index = 2;
    if args[index] == "-e" {
        while index < args.len() && args[index] == "-e" {
            if index + 1 >= args.len() {
                return None;
            }
            scripts.push(&args[index + 1]);
            index += 2;
        }
    } else {
        scripts.push(&args[index]);
        index += 1;
    }
    let targets = &args[index..];
    if !(1..=16).contains(&scripts.len()) || targets.len() != 1 {
        return None;
    }
    if scripts
        .iter()
        .any(|script| !literal_sed_script_is_safe(script))
    {
        return None;
    }
    let target = &targets[0];
    if target.starts_with('-') || !read_only_lookup_target_is_safe(target, false, Some(cwd)) {
        return None;
    }
    let candidate = py_path(cwd).join(target);
    let lexical = normalized(&candidate);
    let resolved = resolve_strict(&candidate)?;
    resolved.relative_to(&resolve_strict(&py_path(workspace_root))?)?;
    (resolved == lexical && pyfs::is_file(&resolved) == Ok(true)).then(|| target.clone())
}

/// `_same_workspace_file`.
pub(crate) fn same_workspace_file(left: &str, right: &str, cwd: &Path) -> bool {
    let base = py_path(cwd);
    match (
        resolve_strict(&base.join(left)),
        resolve_strict(&base.join(right)),
    ) {
        (Some(one), Some(two)) => one == two,
        _ => false,
    }
}
