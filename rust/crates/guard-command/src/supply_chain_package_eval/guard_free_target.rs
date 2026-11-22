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

/// Interpreters uv may start inside a virtual environment directory.
const VENV_INTERPRETERS: &[&str] = &[
    "bin/python",
    "bin/python3",
    "Scripts/python.exe",
    "Scripts/python3.exe",
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
        && roots.iter().all(|(root, is_directory)| {
            environment_is_guard_free(root, running_executable)
                && (!is_directory || !inside_a_guard_environment(root))
        })
}

/// The directories a single `uv pip install|sync` writes into, each marked
/// `true` when it is a `--target` or `--prefix` directory rather than a
/// virtual environment, or `None` when the command does not name them
/// unambiguously.
fn target_environment_roots(
    tokens: &[String],
    base_dir: Option<&Path>,
) -> Option<Vec<(PathBuf, bool)>> {
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
            (interpreter_environment(&path)?, false)
        } else {
            (path, true)
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
/// another environment's Python, so a `#!` file keeps the review. For a
/// directory, uv starts the interpreter inside it, so every interpreter it
/// could pick gets the same check, and a directory without one keeps the
/// review.
fn interpreter_environment(path: &Path) -> Option<PathBuf> {
    let environment = if path.is_dir() {
        let interpreters: Vec<PathBuf> = VENV_INTERPRETERS
            .iter()
            .map(|relative| path.join(relative))
            .filter(|candidate| candidate.symlink_metadata().is_ok())
            .collect();
        if interpreters.is_empty() || interpreters.iter().any(|i| starts_with_shebang(i)) {
            return None;
        }
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
    !holds_guard_installation(&root, true)
}

/// Whether a `--target` or `--prefix` directory sits inside an environment
/// that holds Guard, such as a folder under Guard's own `site-packages`.
/// For a directory that does not exist yet, its nearest existing parent and
/// that parent's parents are checked.
fn inside_a_guard_environment(directory: &Path) -> bool {
    let Some(existing) = directory.ancestors().find(|a| a.symlink_metadata().is_ok()) else {
        return true;
    };
    let Ok(existing) = std::fs::canonicalize(existing) else {
        return true;
    };
    // Parents such as `/var` can hold unrelated folders the user cannot read
    // (`/var/lib/postfix`); only Guard's own markers count there.
    existing
        .ancestors()
        .any(|ancestor| holds_guard_installation(ancestor, false))
}

/// Whether `root` holds a Guard console script or Guard's package metadata
/// in itself or in one of its `site-packages` directories. With
/// `unreadable_holds_guard`, a directory that exists but cannot be read
/// counts as holding Guard.
fn holds_guard_installation(root: &Path, unreadable_holds_guard: bool) -> bool {
    for bin in ["bin", "Scripts"] {
        for executable in GUARD_EXECUTABLES {
            if root.join(bin).join(executable).symlink_metadata().is_ok() {
                return true;
            }
        }
    }
    let mut package_dirs = vec![root.to_path_buf(), root.join("Lib").join("site-packages")];
    for lib in ["lib", "lib64"] {
        if let Ok(entries) = std::fs::read_dir(root.join(lib)) {
            for entry in entries.flatten() {
                package_dirs.push(entry.path().join("site-packages"));
            }
        }
    }
    package_dirs
        .iter()
        .any(|dir| holds_guard_distribution(dir, unreadable_holds_guard))
}

/// Whether a site-packages or `--target` directory holds Guard's metadata.
fn holds_guard_distribution(dir: &Path, unreadable_holds_guard: bool) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            return unreadable_holds_guard && error.kind() != std::io::ErrorKind::NotFound;
        }
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
