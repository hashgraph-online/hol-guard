//! Python virtual environments whose interpreter is an approved runtime.
//!
//! A venv launcher is a symlink in `<venv>/bin`; the image it runs is the base
//! interpreter its symlink chain ends in. An external venv is granted
//! read-only, so it must look like a venv and nothing broader: a fixed set of
//! top-level entries, a single `pyvenv.cfg` whose `home` is a trusted or
//! approved runtime, and no ancestor relation to HOME or the workspace. A venv
//! inside the workspace needs no grant of its own; what it needs is the
//! interpreter install its launchers point out of the workspace to.
use super::launch_shebang::sole_interpreter;
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

/// The image a launcher chain ends in, once `resolve_executable` has answered
/// a `/usr/bin` shim. The shim sits under a trusted root, so the developer tool
/// it forwards to stands on the same terms, as `allowed_executable_path` and
/// the pytest executable check already accept. Only the resolved image is
/// judged this way; a `pyvenv.cfg` `home` still has to pass `approved_runtime`.
fn approved_image(path: &Path) -> bool {
    approved_runtime(path) || super::developer_shim::is_developer_tool(path)
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

/// The venv root of an entry point script in `<venv>/bin`.
///
/// `pip` and `uv` write a console script as a regular file, not a symlink, so
/// the chain `resolve_executable` answers ends in the script itself and there
/// is no launcher to read a venv out of. The script's `#!` line names one. It
/// has to name it outright and hand it nothing else: `env` would look the
/// interpreter up on `PATH`, which containment does not set, a wrapper such
/// as `/bin/sh` would run something the line does not say, and an operand
/// such as `-mother_module` would send the interpreter to that module instead
/// of to this script. The interpreter it names has to be a launcher of the
/// script's own `bin`, ending in an approved image rather than a `/usr/bin`
/// shim, exactly as a Python-named launch does.
///
/// Running `<venv>/bin/pytest` is then that venv's interpreter over that
/// venv's packages, which `<venv>/bin/python -m pytest` already reaches, so
/// the grant is the one `launcher_root` would have made for it.
fn entry_point_root(executable: &Path) -> Option<PathBuf> {
    let bin = executable.parent()?.canonicalize().ok()?;
    let interpreter = sole_interpreter(executable)?;
    let interpreter = Path::new(&interpreter);
    if !interpreter.is_absolute() || interpreter.parent()?.canonicalize().ok()? != bin {
        return None;
    }
    let root = launcher_root(interpreter)?;
    let image = interpreter.canonicalize().ok()?;
    if super::developer_shim::forwarded_tool(&image).is_some() || !approved_image(&image) {
        return None;
    }
    Some(root)
}

/// Whether `path` is the entry point script the venv grant was made for.
///
/// The venv's Python launchers are admitted by the name they carry in `bin`;
/// the script the command named is admitted by identity, because
/// `external_root` read its `#!` line back to that venv's own interpreter
/// before granting the venv. A spelling that reaches the same file through a
/// symlinked directory is that same script.
fn is_entry_point(path: &Path, executable: &Path) -> bool {
    if python_named(executable) {
        return false;
    }
    if path == executable {
        return true;
    }
    match (path.canonicalize(), executable.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Whether `path` is part of the launcher an external venv grant was made for:
/// one of the venv's own Python launchers, or the entry point script itself.
pub(super) fn in_launcher(path: &Path, root: &Path, executable: &Path) -> bool {
    in_bin(path, root) || is_entry_point(path, executable)
}

/// The root of an external venv launcher whose interpreter is an approved
/// runtime; venvs inside, or holding, the workspace are not external.
pub(super) fn external_root(launch: &Path, executable: &Path, workspace: &Path) -> Option<PathBuf> {
    // The contained run execs the launcher, so its chain has to end in the
    // executable itself. One that still ends in a `/usr/bin` shim would run
    // the shim's developer-directory lookup inside containment, where it fails.
    if launch.canonicalize().ok().as_deref() != Some(executable) {
        return None;
    }
    let root = if python_named(executable) {
        if !approved_image(executable) {
            return None;
        }
        launcher_root(launch)?
    } else {
        entry_point_root(executable)?
    };
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

/// The `bin` directories of the venvs a workspace holds at its top level that
/// `text` starts a program from. `None` asks for every one of them, which is
/// what a reachability check needs.
///
/// A command can start `.venv/bin/pytest` by naming its path, and nothing
/// puts the venv on the session's PATH when it does. Discovery that reads
/// only the PATH misses that venv, so the install its launchers link out to
/// is never an executable root, the sandbox cannot start the program the
/// command names, and ordinary project work is reviewed instead of contained.
/// Only a directory holding a `pyvenv.cfg` is considered; what it names still
/// has to pass `workspace_base_roots`.
///
/// A run that names no venv is planned without one. The install a venv links
/// out to is a whole interpreter prefix, and a command that never starts the
/// venv has no reason to read or run it.
pub(super) fn workspace_resident_bins(workspace: &Path, text: Option<&str>) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(workspace) else {
        return Vec::new();
    };
    let mut bins: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten().take(256) {
        let root = entry.path();
        if !root.join("pyvenv.cfg").is_file() {
            continue;
        }
        // A command names the venv at the path the workspace holds it at,
        // which is not the canonical one when the entry is a symbolic link
        // to another directory. Both spellings are matched; the canonical
        // path is what admission and the deduplication below read.
        let named = root.join("bin");
        let Ok(bin) = named.canonicalize() else {
            continue;
        };
        // The limit counts the venvs the command starts a program from, so a
        // named one is found wherever the directory order puts it.
        if text.is_some_and(|text| {
            !starts_program_from(text, workspace, &named)
                && !starts_program_from(text, workspace, &bin)
        }) {
            continue;
        }
        if !bins.contains(&bin) {
            bins.push(bin);
        }
        if bins.len() == 4 {
            break;
        }
    }
    bins
}

/// Whether `text` starts a program from `bin`, named by its own path or by
/// the one the workspace holds it at.
///
/// The path has to stand where a program is read from. `.venv/bin/pytest -q`
/// starts the venv's interpreter; `echo .venv/bin/pytest` writes the path and
/// starts nothing out of the venv, so the prefix that venv links out to has no
/// reason to be an executable root of that run.
fn starts_program_from(text: &str, workspace: &Path, bin: &Path) -> bool {
    let relative = bin.strip_prefix(workspace).unwrap_or(bin);
    [bin, relative]
        .iter()
        .filter_map(|path| path.to_str())
        .any(|path| {
            text.match_indices(path).any(|(at, _)| {
                names_program(&text[at + path.len()..]) && starts_a_command(&text[..at])
            })
        })
}

/// Whether a program of the `bin` directory follows it. A deeper path that
/// only begins with the venv's is a different directory, not its program.
fn names_program(rest: &str) -> bool {
    rest.strip_prefix('/').is_some_and(|rest| {
        let name = rest.split_whitespace().next().unwrap_or_default();
        !name.is_empty() && !name.contains('/')
    })
}

/// Whether what runs next after `before` is a program: `before` is the start
/// of the command or of one of its lists, plus the assignments and the verbs
/// a command stamps on the program it starts.
fn starts_a_command(before: &str) -> bool {
    /// Verbs that take a program as their own first word.
    const PREFIX_VERBS: &[&str] = &[
        "command", "do", "else", "env", "exec", "nohup", "then", "time",
    ];
    // A relative prefix written against the path is part of how the program is
    // spelled, so it comes off before the words are read. Detached, it is a
    // program of its own: in `./ .venv/bin/pytest` what runs is `./`, and the
    // venv's program is only its argument.
    let cut = before.len() - before.trim_end_matches(['.', '/']).len();
    let before = if leads_a_path(&before[before.len() - cut..]) {
        &before[..before.len() - cut]
    } else {
        before
    };
    // A line ending separates two commands as a semicolon does, so only the
    // blanks are taken off the end; trimming every kind of whitespace would
    // take the separator away with them.
    let mut head = before.trim_end_matches([' ', '\t']);
    loop {
        head = head.trim_end_matches(['\'', '"']);
        if head.is_empty() || head.ends_with([';', '&', '|', '(', '{']) || ends_a_line(head) {
            return true;
        }
        let word = head.rsplit(char::is_whitespace).next().unwrap_or_default();
        if word.is_empty() || !(stamps_a_variable(word) || PREFIX_VERBS.contains(&word)) {
            return false;
        }
        head = head[..head.len() - word.len()].trim_end_matches([' ', '\t']);
    }
}

/// Whether `head` ends at a line ending that separates two commands. A line
/// ending a backslash escapes is a continuation instead: the shell joins the
/// two lines, so what follows stays part of the command before it. A carriage
/// return on its own ends no line, and the shell keeps it inside the word.
fn ends_a_line(head: &str) -> bool {
    let Some(body) = head.strip_suffix('\n') else {
        return false;
    };
    let body = body.strip_suffix('\r').unwrap_or(body);
    (body.len() - body.trim_end_matches('\\').len()) % 2 == 0
}

/// Whether `word` is the prefix a relative path is written from: `./`, `../`,
/// `../../`. It names where the program is read from rather than something
/// standing in front of it, so what runs next is still read from the text
/// before it. Every segment has to be one of those, and the prefix has to end
/// at a separator, so a directory whose own name begins with dots is not read
/// as one.
///
/// It says nothing about where the path lands. `../` written from a directory
/// of the workspace reaches the workspace's own venv, which is the spelling
/// this reads; written from the workspace root it reaches a venv outside it,
/// and that one is granted the same interpreter prefix the plain spelling
/// grants it, so the weaker justification adds no reach. Separating the two
/// needs the path resolved against the command's working directory, which
/// this layer is not given.
fn leads_a_path(word: &str) -> bool {
    word.ends_with('/')
        && word
            .split_terminator('/')
            .all(|segment| segment == "." || segment == "..")
}

/// Whether `word` is a `NAME=value` assignment the command stamps on the
/// program it starts.
fn stamps_a_variable(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|first: char| first.is_ascii_alphabetic() || first == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

#[cfg(test)]
#[path = "venv_tests.rs"]
mod tests;
