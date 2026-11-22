//! Whether a Python install writes only into an environment that holds no
//! Guard installation.
//!
//! Guard's own distribution from a direct source normally keeps its review
//! whatever the settings say, because such an install could replace the
//! Guard that is running. An install that names a separate environment
//! (`uv pip install --python <venv>`, `<venv>/bin/pip install`,
//! `pip install --target <dir>`) and finds no Guard there cannot do that:
//! it is the same as building a fresh checkout, so the user's ordinary
//! package settings decide it instead.
//!
//! Every uncertain shape answers `false` and keeps the review: a chained or
//! prefixed command, an interpreter chosen by name or `PATH`, `--user`,
//! `--system`, an environment that already holds Guard, or one that contains
//! the running Guard executable.

use std::path::{Path, PathBuf};

use super::source_identity::FIRST_PARTY_PYPI_PACKAGES;

/// Characters that join, redirect or substitute another command. `shlex`
/// keeps `a.whl;` as one token, so tokens are searched, not compared.
const SHELL_METACHARACTERS: &[char] = &[';', '&', '|', '`', '<', '>', '(', ')', '\n'];

/// Executables a Python environment holds when Guard is installed in it.
const GUARD_EXECUTABLES: &[&str] = &[
    "hol-guard",
    "plugin-guard",
    "hol-guard.exe",
    "plugin-guard.exe",
];

/// Whether `redacted_command` installs only into Python environments that
/// hold no Guard installation and do not contain `running_executable`.
pub(super) fn installs_into_guard_free_environment(
    redacted_command: &str,
    base_dir: Option<&Path>,
    running_executable: Option<&Path>,
) -> bool {
    let Ok(tokens) = crate::command_launcher_floors::shlex_split(redacted_command) else {
        return false;
    };
    let Some(roots) = target_environment_roots(&tokens, base_dir) else {
        return false;
    };
    !roots.is_empty()
        && roots
            .iter()
            .all(|root| environment_is_guard_free(root, running_executable))
}

/// The environments a single pip or `uv pip` install writes into, or `None`
/// when the command does not name them unambiguously.
fn target_environment_roots(tokens: &[String], base_dir: Option<&Path>) -> Option<Vec<PathBuf>> {
    if tokens
        .iter()
        .any(|t| t.contains(SHELL_METACHARACTERS) || t.contains("$("))
    {
        return None;
    }
    let program = tokens.first()?;
    let name = program_name(program);
    let mut roots = Vec::new();
    let options: &[String] = if name == "uv" {
        if tokens.get(1).map(String::as_str) != Some("pip")
            || !matches!(tokens.get(2).map(String::as_str), Some("install" | "sync"))
        {
            return None;
        }
        &tokens[3..]
    } else if is_pip_name(&name) {
        if tokens.get(1).map(String::as_str) != Some("install") {
            return None;
        }
        roots.push(interpreter_environment(program, base_dir)?);
        &tokens[2..]
    } else if is_python_name(&name) {
        if tokens.get(1).map(String::as_str) != Some("-m")
            || tokens.get(2).map(String::as_str) != Some("pip")
            || tokens.get(3).map(String::as_str) != Some("install")
        {
            return None;
        }
        roots.push(interpreter_environment(program, base_dir)?);
        &tokens[4..]
    } else {
        return None;
    };
    let mut index = 0;
    while index < options.len() {
        let token = options[index].as_str();
        if matches!(token, "--user" | "--system" | "--break-system-packages") {
            return None;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_string())),
            _ => (token, None),
        };
        let takes_root = match flag {
            "--python" | "-p" if name == "uv" => Some(true),
            "--target" | "-t" | "--prefix" | "--root" => Some(false),
            _ => None,
        };
        if let Some(is_interpreter) = takes_root {
            let value = match inline {
                Some(value) => value,
                None => {
                    index += 1;
                    options.get(index)?.clone()
                }
            };
            let path = resolve_path(&value, base_dir)?;
            roots.push(if is_interpreter {
                interpreter_environment_path(&path)?
            } else {
                path
            });
        }
        index += 1;
    }
    // `uv pip install` with no `--python`, `--target` or `--prefix` picks its
    // environment from the shell and working directory, which the command
    // alone does not show.
    if name == "uv" && roots.is_empty() {
        return None;
    }
    Some(roots)
}

fn program_name(program: &str) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

fn is_pip_name(name: &str) -> bool {
    name == "pip" || name.strip_prefix("pip3").is_some_and(version_suffix)
}

fn is_python_name(name: &str) -> bool {
    name == "python" || name.strip_prefix("python3").is_some_and(version_suffix)
}

fn version_suffix(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .strip_prefix('.')
            .is_some_and(|minor| !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit()))
}

/// The environment an interpreter or pip program spelled as a path lives in.
/// A bare name is found on `PATH`, which the command does not show.
fn interpreter_environment(program: &str, base_dir: Option<&Path>) -> Option<PathBuf> {
    if !program.contains(['/', '\\']) {
        return None;
    }
    interpreter_environment_path(&resolve_path(program, base_dir)?)
}

/// `<env>/bin/python3` or `<env>\Scripts\python.exe` gives `<env>`; a
/// directory names the environment itself, as `uv pip --python` accepts.
fn interpreter_environment_path(path: &Path) -> Option<PathBuf> {
    if path.is_dir() {
        return Some(path.to_path_buf());
    }
    let name = program_name(&path.file_name()?.to_string_lossy());
    if !is_python_name(&name) && !is_pip_name(&name) {
        return None;
    }
    let bin = path.parent()?;
    let bin_name = bin.file_name()?.to_string_lossy().to_ascii_lowercase();
    if bin_name != "bin" && bin_name != "scripts" {
        return None;
    }
    bin.parent().map(Path::to_path_buf)
}

fn resolve_path(value: &str, base_dir: Option<&Path>) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
        return Some(PathBuf::from(home).join(rest));
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Some(path);
    }
    // A bare interpreter request such as `3.12` is a version, not a path.
    if !value.contains(['/', '\\']) && !value.starts_with('.') {
        return None;
    }
    base_dir.map(|base| base.join(path))
}

/// Whether `root` holds no Guard installation and does not contain the
/// running Guard executable. A root that does not exist yet holds nothing.
fn environment_is_guard_free(root: &Path, running_executable: Option<&Path>) -> bool {
    let root = match std::fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return !root.exists() && root.symlink_metadata().is_err();
        }
        Err(_) => return false,
    };
    if let Some(running) = running_executable.and_then(|p| std::fs::canonicalize(p).ok()) {
        if running.starts_with(&root) {
            return false;
        }
    }
    for bin in ["bin", "Scripts"] {
        for executable in GUARD_EXECUTABLES {
            if root.join(bin).join(executable).symlink_metadata().is_ok() {
                return false;
            }
        }
    }
    let mut package_dirs = vec![root.clone(), root.join("Lib").join("site-packages")];
    for lib in ["lib", "lib64"] {
        if let Ok(entries) = std::fs::read_dir(root.join(lib)) {
            for entry in entries.flatten() {
                package_dirs.push(entry.path().join("site-packages"));
            }
        }
    }
    !package_dirs.iter().any(|dir| holds_guard_distribution(dir))
}

/// Whether a site-packages or `--target` directory holds Guard's metadata.
/// An unreadable directory that exists counts as holding it.
fn holds_guard_distribution(dir: &Path) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => return error.kind() != std::io::ErrorKind::NotFound,
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        let stem = [".dist-info", ".egg-info", ".egg-link"]
            .iter()
            .find_map(|suffix| name.strip_suffix(suffix))
            .map(str::to_string)
            .or_else(|| {
                name.strip_prefix("__editable__")
                    .map(|rest| rest.trim_start_matches(['_', '.']).to_string())
            });
        stem.is_some_and(|stem| {
            let normalized = stem.replace(['_', '.'], "-");
            FIRST_PARTY_PYPI_PACKAGES.iter().any(|package| {
                normalized == *package || normalized.starts_with(&format!("{package}-"))
            })
        })
    })
}

#[cfg(test)]
#[path = "guard_free_target_tests.rs"]
mod tests;
