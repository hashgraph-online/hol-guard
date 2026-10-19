//! Python virtual environments whose interpreter is an approved runtime.
//!
//! A venv launcher is a symlink in `<venv>/bin`; the image it runs is the base
//! interpreter its symlink chain ends in. An external venv is granted
//! read-only, so it must look like a venv and nothing broader: a fixed set of
//! top-level entries, a single `pyvenv.cfg` whose `home` is a trusted or
//! approved runtime, and no ancestor relation to HOME or the workspace. A venv
//! inside the workspace needs no grant of its own; what it needs is the
//! interpreter install its launchers point out of the workspace to.
use super::*;

const VENV_ENTRIES: &[&str] = &[
    ".gitignore",
    ".lock",
    ".project",
    "CACHEDIR.TAG",
    "bin",
    "etc",
    "include",
    "lib",
    "lib64",
    "pyvenv.cfg",
    "share",
];
const PYVENV_CFG_MAX_BYTES: u64 = 16 * 1024;
/// Credential and agent-state directories no venv grant may sit inside.
const PROTECTED_COMPONENTS: &[&str] = &[
    ".aws",
    ".azure",
    ".claude",
    ".codex",
    ".config",
    ".cursor",
    ".docker",
    ".git",
    ".gnupg",
    ".guard",
    ".hol-guard",
    ".kube",
    ".ssh",
];

fn protected(root: &Path) -> bool {
    root.components().any(|part| {
        let name = part.as_os_str().to_string_lossy().to_ascii_lowercase();
        name.starts_with(".env") || PROTECTED_COMPONENTS.contains(&name.as_str())
    })
}

fn python_named(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &name.to_string_lossy()))
}

/// A trusted system interpreter or an exact managed user runtime.
fn approved_runtime(path: &Path) -> bool {
    path_is_within_any(path, &TRUSTED_EXECUTABLE_ROOTS) || approved_user_python_runtime(path)
}

/// `path` is a Python-named entry directly inside `<root>/bin`.
pub(super) fn in_bin(path: &Path, root: &Path) -> bool {
    python_named(path)
        && path
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .is_some_and(|parent| parent == root.join("bin"))
}

fn entries_are_venv_only(root: &Path) -> bool {
    let Ok(mut entries) = fs::read_dir(root) else {
        return false;
    };
    entries.all(|entry| {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| VENV_ENTRIES.contains(name)) else {
            return false;
        };
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            return false;
        };
        // POSIX venvs link `lib64 -> lib`; no other entry may point elsewhere.
        !metadata.is_symlink()
            || (name == "lib64"
                && fs::read_link(entry.path()).is_ok_and(|target| target == Path::new("lib")))
    })
}

/// The canonical `home` of a single regular `pyvenv.cfg`.
fn configured_home(root: &Path) -> Option<PathBuf> {
    let config = root.join("pyvenv.cfg");
    let metadata = fs::symlink_metadata(&config).ok()?;
    if !metadata.is_file() || metadata.len() > PYVENV_CFG_MAX_BYTES {
        return None;
    }
    let text = fs::read_to_string(&config).ok()?;
    let mut homes = text.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "home").then(|| value.trim().to_owned())
    });
    let home = homes.next()?;
    if homes.next().is_some() || !Path::new(&home).is_absolute() {
        return None;
    }
    Path::new(&home).canonicalize().ok()
}

/// Whether `root` is a venv whose read grant cannot widen to unrelated files.
fn venv_shape(root: &Path) -> bool {
    if root.parent().is_none()
        || protected(root)
        || !fs::symlink_metadata(root.join("bin")).is_ok_and(|m| m.is_dir())
        || host_home_directory().is_some_and(|home| path_is_within(&home, root))
        || !entries_are_venv_only(root)
    {
        return false;
    }
    configured_home(root)
        .is_some_and(|home| !path_is_within(&home, root) && approved_runtime(&home))
}

/// The venv root of a Python-named symlink launcher in `<venv>/bin`.
pub(super) fn launcher_root(launch: &Path) -> Option<PathBuf> {
    if !python_named(launch) || !launch.is_symlink() {
        return None;
    }
    let bin = launch.parent()?.canonicalize().ok()?;
    if bin.file_name() != Some(OsStr::new("bin")) {
        return None;
    }
    let root = bin.parent()?.to_path_buf();
    venv_shape(&root).then_some(root)
}

/// The root of an external venv launcher whose interpreter is an approved
/// runtime; venvs inside, or holding, the workspace are not external.
pub(super) fn external_root(launch: &Path, executable: &Path, workspace: &Path) -> Option<PathBuf> {
    if !python_named(executable) || !approved_runtime(executable) {
        return None;
    }
    let root = launcher_root(launch)?;
    if path_is_within(&root, workspace) || path_is_within(workspace, &root) {
        return None;
    }
    Some(root)
}

/// The `lib/pythonX.Y` standard libraries an install prefix holds.
fn standard_libraries(prefix: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(prefix.join("lib")) else {
        return Vec::new();
    };
    let mut libraries: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten().take(64) {
        let name = entry.file_name();
        let Some(version) = name.to_str().and_then(|name| name.strip_prefix("python")) else {
            continue;
        };
        if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
            continue;
        }
        let Ok(canonical) = entry.path().canonicalize() else {
            continue;
        };
        if !canonical.is_dir() || !path_is_within(&canonical, prefix) {
            continue;
        }
        if !libraries.contains(&canonical) {
            libraries.push(canonical);
        }
        if libraries.len() == 4 {
            break;
        }
    }
    libraries
}

/// A prefix that holds one runtime's install of its own, so granting it whole
/// stays inside that runtime. A trusted root named exactly, such as
/// `/usr/local` or `/opt/homebrew`, is not one: it holds every program and
/// configuration file installed below it, and a `pyvenv.cfg` in the workspace
/// chooses the `home` this prefix comes from.
/// Whether the configured `home` is an install's launcher directory: a `bin`
/// that holds a runnable interpreter.
///
/// `pyvenv.cfg` sits in the workspace, so its `home` is the repository's
/// choice. Without this, any directory below a trusted root could name itself
/// the runtime and have its whole prefix granted; with it, the directory has
/// to be one an install actually starts Python from.
fn interpreter_home(home: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if home.file_name() != Some(OsStr::new("bin")) {
        return false;
    }
    let Ok(entries) = fs::read_dir(home) else {
        return false;
    };
    entries.flatten().take(256).any(|entry| {
        python_named(&entry.path())
            && entry.path().metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
    })
}

fn managed_prefix(prefix: &Path) -> bool {
    approved_user_python_runtime(prefix)
        || TRUSTED_EXECUTABLE_ROOTS
            .iter()
            .any(|root| prefix != root.as_path() && path_is_within(prefix, root))
}

/// The install a workspace venv's launchers run, as the directory that holds
/// both the interpreter and its standard library.
///
/// The sandbox reads and runs the workspace, so a project's `.venv` is already
/// there, but `bin/python` is a symlink to an interpreter installed elsewhere.
/// Unless that install is an executable root the sandbox cannot start it, and
/// ordinary Python work in a project venv would be contained and then fail.
/// The venv must have a venv's shape and name a trusted or managed runtime.
/// A managed install is granted whole; anywhere else only the interpreter's
/// own directory and the standard library beside it are.
pub(super) fn workspace_base_roots(bin: &Path, workspace: &Path) -> Vec<PathBuf> {
    if bin.file_name() != Some(OsStr::new("bin")) {
        return Vec::new();
    }
    let Some(root) = bin.parent() else {
        return Vec::new();
    };
    if !path_is_within(root, workspace) || !venv_shape(root) {
        return Vec::new();
    }
    let Some(home) = configured_home(root) else {
        return Vec::new();
    };
    let Some(prefix) = home.parent().map(Path::to_path_buf) else {
        return Vec::new();
    };
    if !approved_runtime(&home) || !interpreter_home(&home) || path_is_within(&prefix, workspace) {
        return Vec::new();
    }
    if managed_prefix(&prefix) {
        return vec![prefix];
    }
    let mut roots = vec![home];
    roots.extend(standard_libraries(&prefix));
    roots
}

#[cfg(test)]
#[path = "venv_tests.rs"]
mod tests;
