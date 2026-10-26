//! Static shell path and inspection-chain safety checks (`shell_static_safety.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{is_py_space, py_strip, strip_quotes, PyPath};
use crate::sfrs_constants::SHELL_COMMAND_STRING_INTERPRETERS;
use crate::shell_execution_context::ShellExecutionContext;

/// `_shell_token_has_command_substitution`.
pub(crate) fn shell_token_has_command_substitution(token: &str) -> bool {
    if token.contains("$(") || token.contains('`') {
        return true;
    }
    token
        .chars()
        .any(|c| matches!(c, '$' | '<' | '>' | '|' | '&' | ';' | '\n'))
}

/// `_without_safe_inspection_redirections`.
pub(crate) fn without_safe_inspection_redirections(args: &[String]) -> Option<Vec<String>> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if token == "2>&1" || token == "2>/dev/null" {
            index += 1;
            continue;
        }
        if token == "2>" && args.get(index + 1).is_some_and(|next| next == "/dev/null") {
            index += 2;
            continue;
        }
        if token.contains(['>', '<']) && !token.chars().any(is_py_space) {
            return None;
        }
        filtered.push(token.to_owned());
        index += 1;
    }
    Some(filtered)
}

/// `_shell_syntax_check_segment_is_safe`.
pub(crate) fn shell_syntax_check_segment_is_safe(command_name: &str, args: &[String]) -> bool {
    if !SHELL_COMMAND_STRING_INTERPRETERS.contains(&command_name)
        || args.len() != 2
        || args[0] != "-n"
    {
        return false;
    }
    let target = PyPath::new(strip_quotes(&args[1]));
    target.suffix() == ".sh"
        && target
            .components()
            .iter()
            .all(|part| !part.starts_with('.'))
}

/// `os.path.commonpath` for two paths (POSIX); `None` is `ValueError`.
fn commonpath(first: &str, second: &str) -> Option<String> {
    let first_abs = first.starts_with('/');
    if first_abs != second.starts_with('/') {
        return None;
    }
    let split = |text: &str| -> Vec<String> {
        text.split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .map(str::to_owned)
            .collect()
    };
    let (left, right) = (split(first), split(second));
    let common: Vec<String> = left
        .iter()
        .zip(&right)
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a.clone())
        .collect();
    let prefix = if first_abs { "/" } else { "" };
    Some(format!("{prefix}{}", common.join("/")))
}

/// `_path_text_is_within_root_text`.
pub(crate) fn path_text_is_within_root_text(path_text: &str, root_text: &str) -> bool {
    commonpath(path_text, root_text).is_some_and(|common| common == root_text)
}

/// `os.path.realpath(root)` as text; a symlink loop keeps the lexical path.
fn realpath_text(root: &Path) -> String {
    let text = root.to_string_lossy();
    let path = PyPath::new(&text);
    pyfs::resolve(&path).map_or_else(|| path.to_string(), |resolved| resolved.to_string())
}

/// `_path_text_is_within_root`.
pub(crate) fn path_text_is_within_root(path_text: &str, root: &Path) -> bool {
    path_text_is_within_root_text(path_text, &realpath_text(root))
}

/// `_shell_token_escapes_root`.
pub(crate) fn shell_token_escapes_root(token: &str, cwd: &Path, root: &Path) -> bool {
    let stripped = strip_quotes(py_strip(token));
    if stripped.is_empty() {
        return false;
    }
    let mut candidate = PyPath::new(stripped);
    if let Some(rest) = stripped.strip_prefix("~/") {
        candidate = PyPath::new(&root.to_string_lossy()).join(rest);
    } else if stripped.starts_with('~') {
        return true;
    } else if !candidate.is_absolute() {
        if !candidate.components().iter().any(|part| part == "..") {
            return false;
        }
        candidate = PyPath::new(&cwd.to_string_lossy()).join(&candidate.to_string());
    }
    !path_text_is_within_root(&candidate.to_string(), root)
}

/// `_leading_literal_cd_workspace_root`.
pub(crate) fn leading_literal_cd_workspace_root(
    context: &ShellExecutionContext,
    home_dir: &Path,
) -> Option<PathBuf> {
    let first = context.segments.first()?;
    if !first.control_before.is_empty()
        || first.directory_operation.as_deref() != Some("cd")
        || first.tokens.len() != 2
    {
        return None;
    }
    if strip_quotes(&first.tokens[0]).to_lowercase() != "cd" {
        return None;
    }
    let operand = py_strip(&first.tokens[1]);
    if operand.is_empty()
        || shell_token_has_command_substitution(operand)
        || ["$", "`", "\0"]
            .iter()
            .any(|marker| operand.contains(marker))
    {
        return None;
    }
    let home = PyPath::new(&home_dir.to_string_lossy());
    let candidate = if operand == "~" {
        home
    } else if let Some(rest) = operand.strip_prefix("~/") {
        home.join(rest)
    } else if operand.starts_with('~') {
        return None;
    } else {
        let plain = PyPath::new(operand);
        if plain.is_absolute() {
            plain
        } else {
            home.join(operand)
        }
    };
    let resolved = pyfs::resolve(&candidate)?;
    if pyfs::exists(&resolved) != Ok(true) || pyfs::is_dir(&resolved) != Ok(true) {
        return None;
    }
    Some(PathBuf::from(resolved.to_string()))
}

/// `which_for_execution_cwd`: PATH lookup with relative entries read from `cwd`.
pub(crate) fn which_for_execution_cwd(command: &str, cwd: &Path, ctx: &Ctx) -> Option<String> {
    let path_value = ctx
        .host
        .env("PATH")
        .unwrap_or_else(|| "/bin:/usr/bin".to_owned());
    let cwd = PyPath::new(&cwd.to_string_lossy());
    let mut seen: Vec<String> = Vec::new();
    let mut entries = Vec::new();
    for entry in path_value.split(':') {
        let text = if entry.is_empty() { "." } else { entry };
        let expanded = expand_user(text, &ctx.default_home);
        let candidate = if PyPath::new(&expanded).is_absolute() {
            PyPath::new(&expanded)
        } else {
            cwd.join(&expanded)
        };
        entries.push(candidate.to_string());
    }
    if command.contains('/') {
        return is_executable_file(command).then(|| command.to_owned());
    }
    for directory in entries {
        if seen.contains(&directory) {
            continue;
        }
        seen.push(directory.clone());
        let name = format!("{directory}/{command}");
        if is_executable_file(&name) {
            return Some(name);
        }
    }
    None
}

fn expand_user(text: &str, home: &PyPath) -> String {
    if text == "~" {
        return home.to_string();
    }
    match text.strip_prefix("~/") {
        Some(rest) => home.join(rest).to_string(),
        None => text.to_owned(),
    }
}

fn is_executable_file(path: &str) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// `_safe_cli_metadata_segment_is_safe`.
///
/// `managed_bin_dirs` are the bin directories of the managed install that owns
/// this guard; the resident supplies them where Python used `sys.prefix`.
pub(crate) fn safe_cli_metadata_segment_is_safe(
    command_name: &str,
    args: &[String],
    cwd: &Path,
    command_token: &str,
    command_index: usize,
    ctx: &Ctx,
    managed_bin_dirs: &[PathBuf],
) -> bool {
    if command_index != 0 || command_token != command_name {
        return false;
    }
    let single = |value: &str| args.len() == 1 && args[0] == value;
    if command_name == "git" && (single("--version") || single("version")) {
        let Some(git_path) = which_for_execution_cwd("git", cwd, ctx) else {
            return false;
        };
        let (Some(resolved), Some(resolved_cwd)) = (
            pyfs::resolve(&PyPath::new(&git_path)),
            pyfs::resolve(&PyPath::new(&cwd.to_string_lossy())),
        ) else {
            return false;
        };
        return ctx
            .host
            .git_binary_trusted(&resolved.to_string(), &resolved_cwd.to_string());
    }
    if command_name != "hol-guard" || !is_managed_metadata_args(args) {
        return false;
    }
    let Some(executable) = which_for_execution_cwd("hol-guard", cwd, ctx) else {
        return false;
    };
    let Some(actual) = pyfs::resolve(&PyPath::new(&executable)) else {
        return false;
    };
    if pyfs::exists(&actual) != Ok(true) {
        return false;
    }
    managed_bin_dirs.iter().any(|directory| {
        let candidate = PyPath::new(&directory.to_string_lossy()).join("hol-guard");
        pyfs::resolve(&candidate)
            .is_some_and(|resolved| pyfs::exists(&resolved) == Ok(true) && resolved == actual)
    })
}

fn is_managed_metadata_args(args: &[String]) -> bool {
    const ALLOWED: [&[&str]; 9] = [
        &["--version"],
        &["status"],
        &["status", "--json"],
        &["daemon", "status"],
        &["daemon", "status", "--json"],
        &["doctor"],
        &["doctor", "--json"],
        &["settings"],
        &["settings", "--json"],
    ];
    ALLOWED
        .iter()
        .any(|allowed| allowed.len() == args.len() && allowed.iter().zip(args).all(|(a, b)| a == b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn commonpath_keeps_dot_dot_like_cpython() {
        assert!(path_text_is_within_root_text("/a/b/../c", "/a"));
        assert!(path_text_is_within_root_text("/a//b/./c", "/a/b"));
        assert!(!path_text_is_within_root_text("/ab", "/a"));
        assert!(!path_text_is_within_root_text("rel", "/a"));
        assert!(path_text_is_within_root_text("/x", "/"));
    }

    #[test]
    fn redirections_and_syntax_checks() {
        assert_eq!(
            without_safe_inspection_redirections(&strings(&["a", "2>&1", "2>", "/dev/null"])),
            Some(strings(&["a"]))
        );
        assert_eq!(
            without_safe_inspection_redirections(&strings(&["a>b"])),
            None
        );
        assert!(shell_syntax_check_segment_is_safe(
            "bash",
            &strings(&["-n", "run/x.sh"])
        ));
        assert!(!shell_syntax_check_segment_is_safe(
            "bash",
            &strings(&["-n", "../x.sh"])
        ));
        assert!(!shell_syntax_check_segment_is_safe(
            "bash",
            &strings(&["-n", ".hid/x.sh"])
        ));
    }

    #[test]
    fn token_escapes() {
        let root = Path::new("/");
        assert!(!shell_token_escapes_root(
            "'sub/file'",
            Path::new("/w"),
            root
        ));
        assert!(shell_token_escapes_root("~other", Path::new("/w"), root));
        assert!(shell_token_has_command_substitution("a|b"));
        assert!(!shell_token_has_command_substitution("abc"));
    }
}
