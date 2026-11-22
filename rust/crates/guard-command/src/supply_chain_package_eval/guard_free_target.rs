//! Whether a `uv pip` install writes only into an environment that holds no
//! Guard installation.
//!
//! Guard's own distribution from a direct source normally keeps its review
//! whatever the settings say, because such an install could replace the
//! Guard that is running. An install that names a separate virtual
//! environment (`uv pip install --python <venv>`) or a separate directory
//! (`--target`, `--prefix`) and finds no Guard there cannot do that: it is
//! the same as building a fresh checkout, so the user's ordinary package
//! settings decide it instead.
//!
//! Only `uv pip install|sync` is accepted, with a closed list of options;
//! every other shape answers `false` and keeps the review. That includes
//! `pip` and `python -m pip`, whose option parser accepts abbreviated and
//! attached forms and whose launchers can run another environment's
//! interpreter, any option this module does not know, a value the shell
//! could still expand, a chained or redirected command, an interpreter
//! chosen by name or `PATH`, `--system`, an environment that already holds
//! Guard, and one that contains the running Guard executable.
//!
//! Settings that do not appear in the command, such as environment
//! variables and `uv.toml`, are not read here. They come from the same shell
//! that decides whether Guard's install wrapper runs at all.

use std::io::Read;
use std::path::{Path, PathBuf};

use super::source_identity::FIRST_PARTY_PYPI_PACKAGES;

/// Characters that join, redirect or substitute another command. `shlex`
/// keeps `a.whl;` as one token, so tokens are searched, not compared.
const SHELL_METACHARACTERS: &[char] = &[';', '&', '|', '`', '<', '>', '(', ')', '\n'];

/// Characters a shell may still expand inside a path value, so the literal
/// text is not the path the installer receives.
const EXPANDABLE_PATH_CHARACTERS: &[char] = &['$', '`', '*', '?', '[', ']', '{', '}', '%', '!'];

/// `uv pip install|sync` options that select nothing about where packages
/// are written. Anything else, including `--directory`, `--project` and
/// `--config-file`, keeps the review.
const NEUTRAL_OPTIONS: &[&str] = &[
    "--no-deps",
    "--no-cache",
    "-n",
    "-q",
    "--quiet",
    "-v",
    "--verbose",
    "-U",
    "--upgrade",
    "--reinstall",
    "--force-reinstall",
    "--no-index",
    "--offline",
    "--compile-bytecode",
    "--strict",
    "--exact",
];

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

/// The directories a single `uv pip install|sync` writes into, or `None`
/// when the command does not name them unambiguously.
fn target_environment_roots(tokens: &[String], base_dir: Option<&Path>) -> Option<Vec<PathBuf>> {
    if tokens
        .iter()
        .any(|t| t.contains(SHELL_METACHARACTERS) || t.contains("$("))
    {
        return None;
    }
    if program_name(tokens.first()?) != "uv"
        || tokens.get(1).map(String::as_str) != Some("pip")
        || !matches!(tokens.get(2).map(String::as_str), Some("install" | "sync"))
    {
        return None;
    }
    let options = &tokens[3..];
    let mut roots = Vec::new();
    let mut index = 0;
    while index < options.len() {
        let token = options[index].as_str();
        index += 1;
        if !token.starts_with('-') || NEUTRAL_OPTIONS.contains(&token) {
            continue;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
            _ => (token, None),
        };
        let is_interpreter = match flag {
            "--python" | "-p" => true,
            "--target" | "--prefix" => false,
            _ => return None,
        };
        if inline.is_some() && flag == "-p" {
            return None;
        }
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                options.get(index - 1)?.as_str()
            }
        };
        let path = resolve_path(value, base_dir)?;
        roots.push(if is_interpreter {
            interpreter_environment(&path)?
        } else {
            path
        });
    }
    Some(roots)
}

fn program_name(program: &str) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

fn is_python_name(name: &str) -> bool {
    name == "python"
        || name.strip_prefix("python3").is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix('.').is_some_and(|minor| {
                    !minor.is_empty() && minor.chars().all(|c| c.is_ascii_digit())
                })
        })
}

/// The virtual environment an interpreter given to `uv pip --python` writes
/// into. It must hold `pyvenv.cfg`: Python takes its prefix from that file
/// beside the interpreter it was started as, not from wherever a linked
/// interpreter points. A script standing in for the interpreter could start
/// another environment's Python, so a `#!` file keeps the review.
fn interpreter_environment(path: &Path) -> Option<PathBuf> {
    let environment = if path.is_dir() {
        path.to_path_buf()
    } else {
        if starts_with_shebang(path) {
            return None;
        }
        environment_of_interpreter(path)?
    };
    environment
        .join("pyvenv.cfg")
        .is_file()
        .then_some(environment)
}

/// Whether `path` is a script rather than an interpreter. An unreadable
/// file counts as a script.
fn starts_with_shebang(path: &Path) -> bool {
    let mut head = [0u8; 2];
    match std::fs::File::open(path).and_then(|mut file| file.read(&mut head)) {
        Ok(read) => read == 2 && &head == b"#!",
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// `<env>/bin/python3` or `<env>\Scripts\python.exe` gives `<env>`.
fn environment_of_interpreter(path: &Path) -> Option<PathBuf> {
    if !is_python_name(&program_name(&path.file_name()?.to_string_lossy())) {
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
    if value.is_empty() || value.contains(EXPANDABLE_PATH_CHARACTERS) {
        return None;
    }
    if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
        return Some(PathBuf::from(home).join(rest));
    }
    // `~user` expands to another home directory.
    if value.starts_with('~') {
        return None;
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Some(path);
    }
    // A bare interpreter request such as `3.12` or `python3` is a version or
    // a `PATH` lookup, not a path.
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
