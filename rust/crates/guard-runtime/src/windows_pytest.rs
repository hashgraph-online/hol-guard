//! Windows planner for the read-only pytest profile (`pytest-readonly-v2`).
//!
//! macOS and Linux run pytest inside the seatbelt and bubblewrap restricted
//! profiles. Windows had no pytest backend at all, so a project that runs its
//! own `pytest` had no quiet route and every run became a review prompt. This
//! plans the same profile onto the LPAC snapshot runner the inline evaluation
//! and local Node tool profiles already use: the workspace is copied into a
//! credential-filtered read-only snapshot, the virtual environment the run
//! needs is copied with it, and the environment's own interpreter runs
//! `-m pytest` inside the container with no network, no user profile, a
//! private HOME and TEMP, and a kill-on-close job.
//!
//! The interpreter that runs is the copy inside the snapshot, so the run keeps
//! the prefix and the `site-packages` of the environment it was launched from.
//! What it does not keep is any path written outside that environment: a
//! `.pth` line or an `__editable__` finder holds the absolute path it was
//! installed with, and the snapshot has no copy there. The planner declines
//! such an environment rather than running a pytest that cannot import the
//! project, and declines one built from hardlinked files, which is how `uv`
//! installs packages and which the snapshot leaves out because a second
//! directory entry may be another name for a withheld file. Both fall back to
//! the review the profile replaces.
//!
//! The bytes that do run are the repository's own, but so is every
//! `conftest.py` pytest imports: the container, not the provenance of the
//! interpreter, is what bounds this profile. The environment still has to
//! record an all-users Python install as its base, which keeps a run that
//! cannot name a real interpreter out of the profile altogether.
use guard_command::restricted_command::{normalized_command, RestrictedPytestError};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(crate) const PROFILE: &str = "pytest-readonly-v2";
const INVALID: &str = "pytest_restricted_invalid_command";
const UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";
/// A `pyvenv.cfg` holds a handful of `key = value` lines; a larger file is
/// not one, and reading it whole stays bounded.
const PYVENV_CFG_MAX_BYTES: u64 = 64 * 1024;
/// Where an environment keeps its executables: `Scripts` is what `venv`,
/// `virtualenv` and `uv` create on Windows; `bin` is what a POSIX-shaped
/// environment left by an MSYS or Cygwin Python uses.
const BINARY_DIRECTORIES: [&str; 2] = ["Scripts", "bin"];
/// The launcher names a pytest run is started through.
const PYTEST_NAMES: [&str; 8] = [
    "pytest",
    "pytest.exe",
    "pytest.cmd",
    "pytest.bat",
    "py.test",
    "py.test.exe",
    "py.test.cmd",
    "py.test.bat",
];

fn error(reason_code: &str, message: &str) -> RestrictedPytestError {
    RestrictedPytestError {
        reason_code: reason_code.to_owned(),
        message: message.to_owned(),
    }
}

fn invalid() -> RestrictedPytestError {
    error(
        INVALID,
        "Contained pytest receives argv directly and accepts only a pytest launcher or a Python `-m pytest` invocation.",
    )
}

fn unavailable(message: &str) -> RestrictedPytestError {
    error(UNAVAILABLE, message)
}

/// The name an interpreter inside an environment is created with.
fn interpreter_named(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    matches!(stem, "python" | "pythonw" | "python3")
        || stem.strip_prefix("python3.").is_some_and(|minor| {
            !minor.is_empty() && minor.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Argv reaches the container directly, so a shell operator in it is a sign
/// the caller did not split the command the way this profile assumes.
fn screened(arguments: &[String]) -> Result<(), RestrictedPytestError> {
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(invalid());
    }
    Ok(())
}

/// The spellings a launcher is found under when the command names it without
/// a path. `PATHEXT` decides this for a shell; the three that matter here are
/// what `venv`, `virtualenv` and `uv` write into `Scripts`, and the bare name
/// is what a POSIX-shaped environment leaves for Git Bash.
const LAUNCHER_EXTENSIONS: [&str; 3] = [".exe", ".cmd", ".bat"];

/// The file a command's first word names.
///
/// A command that carries a path is resolved against the working directory. A
/// bare name is resolved on the search path the hook recorded, which is how an
/// activated environment's `pytest -q` or `python -m pytest` names an
/// interpreter at all. Resolution does not decide whether the profile applies:
/// the launcher still has to sit in a virtual environment inside the
/// workspace, which is checked once it is known.
fn resolved(name: &str, cwd: &Path, search_path: &str) -> Option<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return crate::windows_readonly::canonical(&cwd.join(name)).filter(|path| path.is_file());
    }
    let mut names = vec![name.to_owned()];
    names.extend(
        LAUNCHER_EXTENSIONS
            .iter()
            .map(|extension| format!("{name}{extension}")),
    );
    crate::windows_readonly::first_on_path(&names, search_path)
        .as_deref()
        .and_then(crate::windows_readonly::canonical)
        .filter(|path| path.is_file())
}

/// A workspace-relative path whose components are all ordinary names.
fn relative_within(path: &Path, workspace: &Path) -> Option<PathBuf> {
    let relative = path.strip_prefix(workspace).ok()?;
    relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
        .then(|| relative.to_path_buf())
}

/// The environment a launcher belongs to: `<environment>/<Scripts|bin>/<name>`.
fn environment_root(launcher: &Path) -> Option<PathBuf> {
    let binaries = launcher.parent()?;
    let named = binaries.file_name()?.to_str()?;
    if !BINARY_DIRECTORIES
        .iter()
        .any(|directory| named.eq_ignore_ascii_case(directory))
    {
        return None;
    }
    binaries.parent().map(Path::to_path_buf)
}

/// The all-users install a `pyvenv.cfg` records as the environment's base.
///
/// The interpreter the container runs is the environment's own copy, so this
/// does not decide which bytes execute. It decides whether the directory is a
/// virtual environment of a Python the machine installed for every user at
/// all: an environment that cannot name one is not a shape this profile
/// contains, and it keeps its review.
fn base_interpreter(environment: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let configuration = environment.join("pyvenv.cfg");
    let unreadable = || {
        unavailable("Contained pytest on Windows runs from a virtual environment; this directory has no readable `pyvenv.cfg`.")
    };
    let mut file = std::fs::File::open(&configuration).map_err(|_| unreadable())?;
    if file.metadata().map(|data| data.len()).unwrap_or(u64::MAX) > PYVENV_CFG_MAX_BYTES {
        return Err(unreadable());
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|_| unreadable())?;
    let home = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("home"))
        .map(|(_, value)| PathBuf::from(value.trim()))
        .ok_or_else(unreadable)?;
    // `home` names the directory the base interpreter lives in; an all-users
    // install ships `python.exe` there under a trusted install root.
    crate::windows_readonly::trusted_executable(&home.join("python.exe"))
}

/// The environment's own interpreter, as a path relative to the environment.
fn environment_interpreter(environment: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let missing = || {
        unavailable(
            "The virtual environment holds no interpreter of its own; execution was not started.",
        )
    };
    for directory in BINARY_DIRECTORIES {
        for name in ["python.exe", "python3.exe", "pythonw.exe"] {
            let relative = Path::new(directory).join(name);
            if environment.join(&relative).is_file() {
                return Ok(relative);
            }
        }
    }
    Err(missing())
}

/// Where an environment keeps the packages a run imports.
const SITE_PACKAGES: [&str; 2] = ["Lib/site-packages", "lib/site-packages"];
/// A `site-packages` holds a handful of `.pth` files among its packages;
/// reading the directory stays bounded whatever it holds. A directory with
/// more entries than this is one the planner never finishes reading, so it is
/// refused rather than cleared on the part that was read.
const SITE_ENTRIES_MAX: usize = 4096;
/// A `.pth` file is a short list of paths; a larger one is not one.
const PTH_MAX_BYTES: u64 = 64 * 1024;

/// Whether the environment imports through a path out of itself.
///
/// The snapshot is a copy of the workspace at a path of its own, and the
/// container grants nothing outside it. A `.pth` line or an editable-install
/// finder holds the absolute path it was written with, which inside the
/// container names a directory the run cannot read, so `pip install -e .` and
/// a src-layout project would fail on import rather than run. An environment
/// that depends on one keeps its review instead.
fn imports_outside_itself(environment: &Path) -> bool {
    for relative in SITE_PACKAGES {
        let Ok(entries) = std::fs::read_dir(environment.join(relative)) else {
            continue;
        };
        for (seen, entry) in entries.flatten().enumerate() {
            // `read_dir` hands entries back in no particular order, so the
            // finder or `.pth` that decides this may be past the bound. Having
            // read as far as the bound allows settles nothing.
            if seen >= SITE_ENTRIES_MAX {
                return true;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with("__editable__") {
                return true;
            }
            if !name.ends_with(".pth") {
                continue;
            }
            if entry.metadata().map(|data| data.len()).unwrap_or(u64::MAX) > PTH_MAX_BYTES {
                return true;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                return true;
            };
            // A line that starts with `import` is startup code, not a path.
            if text
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with("import ")
                })
                .any(|line| {
                    let path = Path::new(line);
                    // `site` joins a relative line onto the site directory.
                    // A rooted line (`\src`, `/src`) or a drive-relative one
                    // (`C:src`) escapes that join and names a directory the
                    // snapshot holds no copy of, as a fully absolute line does.
                    path.has_root()
                        || matches!(path.components().next(), Some(Component::Prefix(_)))
                })
            {
                return true;
            }
        }
    }
    false
}

/// How many of the environment's own files are probed for a second directory
/// entry. A package manager that hardlinks does it to everything it installs,
/// so a bounded sample settles the question for the whole environment.
const LINK_PROBE_MAX: usize = 256;
/// How deep the probe looks inside `site-packages`: a distribution's modules
/// sit a directory or two below it.
const LINK_PROBE_DEPTH: usize = 3;

/// Whether the snapshot would stage the environment without some of its files.
///
/// The snapshot omits any workspace file with a second directory entry,
/// because that entry may be another name for a withheld one such as `.env`.
/// `uv` installs packages by hardlinking them out of its cache, so such an
/// environment would be staged with holes and the run would fail on import
/// inside the container rather than report anything a reader could act on.
/// Declining here keeps the review the profile would have replaced.
fn stages_incompletely(environment: &Path, interpreter: &Path) -> bool {
    // An interpreter that cannot be read at all is not one this run can stage.
    if !guard_runtime_windows_process::is_single_link_file(&environment.join(interpreter))
        .unwrap_or(false)
    {
        return true;
    }
    let mut remaining = LINK_PROBE_MAX;
    SITE_PACKAGES.iter().any(|relative| {
        probe_links(
            &environment.join(relative),
            LINK_PROBE_DEPTH,
            &mut remaining,
        )
    })
}

/// Whether any file the probe reaches has a second directory entry. A file
/// whose link count cannot be read is passed over rather than counted against
/// the environment; the snapshot reports its own failure to copy one.
fn probe_links(directory: &Path, depth: usize, remaining: &mut usize) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return false;
    };
    for entry in entries.flatten() {
        if *remaining == 0 {
            return false;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if depth > 0 && probe_links(&entry.path(), depth - 1, remaining) {
                return true;
            }
        } else if kind.is_file() {
            *remaining -= 1;
            if guard_runtime_windows_process::is_single_link_file(&entry.path())
                .is_ok_and(|single| !single)
            {
                return true;
            }
        }
    }
    false
}

/// The snapshot-relative interpreter and its environment, read back from a
/// launch plan's own argv.
pub(crate) fn staged_interpreter(executable: &Path) -> Option<(PathBuf, PathBuf)> {
    let text = executable.to_str()?.replace('\\', "/");
    let path = PathBuf::from(&text);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || !interpreter_named(path.file_name()?.to_str()?)
    {
        return None;
    }
    let environment = environment_root(&path)?;
    (!environment.as_os_str().is_empty()).then_some((environment, path))
}

/// A path to `target` from `base`, both relative to the same root.
///
/// The snapshot root exists only once the run starts, so the container's own
/// `PATH` names the environment's executables this way instead.
pub(crate) fn relative_from(base: &Path, target: &Path) -> PathBuf {
    let mut path = PathBuf::new();
    for _ in base.components() {
        path.push("..");
    }
    path.push(target);
    path
}

fn plan(input: &Value) -> Result<Value, RestrictedPytestError> {
    if input.get("read_only_workspace") != Some(&Value::Bool(true)) {
        return Err(unavailable(
            "Windows contains pytest read-only; a writable restricted run has no Windows backend.",
        ));
    }
    let command: Vec<String> = input
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .ok_or_else(invalid)?;
    let command = normalized_command(&command)?;
    let path = |key: &str| input.get(key).and_then(Value::as_str).map(PathBuf::from);
    let (workspace, cwd) = crate::windows_readonly::workspace_and_cwd(
        &path("workspace").ok_or_else(invalid)?,
        &path("cwd").ok_or_else(invalid)?,
    )?;
    let search_path = input
        .get("search_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let launcher = resolved(&command[0], &cwd, search_path)
        .ok_or_else(|| unavailable("The pytest launcher could not be resolved."))?;
    let named = launcher
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(invalid)?;
    screened(&command[1..])?;
    let arguments: Vec<String> = if PYTEST_NAMES.contains(&named.as_str()) {
        ["-m", "pytest"]
            .into_iter()
            .map(str::to_owned)
            .chain(command[1..].iter().cloned())
            .collect()
    } else if interpreter_named(&named)
        && guard_command::pytest_argv::python_args_target_pytest(&command[1..])
    {
        command[1..].to_vec()
    } else {
        return Err(invalid());
    };
    let environment = environment_root(&launcher).ok_or_else(|| {
        unavailable(
            "Contained pytest on Windows runs a virtual environment's own launcher; this command names none.",
        )
    })?;
    let relative = relative_within(&environment, &workspace)
        // An environment equal to the workspace root leaves nothing for the
        // runner to read the environment back out of its own launch plan, and
        // a directory holding a project is not a virtual environment anyway.
        .filter(|relative| !relative.as_os_str().is_empty())
        .ok_or_else(|| {
            unavailable(
                "Contained pytest on Windows runs a virtual environment inside the workspace; this one is outside it.",
            )
        })?;
    base_interpreter(&environment)?;
    let interpreter = environment_interpreter(&environment)?;
    if stages_incompletely(&environment, &interpreter) {
        return Err(unavailable(
            "The virtual environment is built from hardlinked files, which a read-only snapshot does not carry; execution was not started.",
        ));
    }
    if imports_outside_itself(&environment) {
        return Err(unavailable(
            "The virtual environment imports through an absolute path outside itself, which the snapshot does not hold; execution was not started.",
        ));
    }
    let backend = std::env::current_exe()
        .ok()
        .and_then(|path| crate::windows_readonly::canonical(&path))
        .ok_or_else(|| unavailable("The Guard runtime path is unavailable."))?;
    // The snapshot root is created at launch, so the plan names the
    // interpreter by its place inside the workspace copy.
    let staged = relative.join(&interpreter);
    let live = environment.join(&interpreter);
    let mut launch = vec![staged.to_string_lossy().replace('\\', "/")];
    launch.extend(arguments);
    Ok(json!({
        "profile_version": PROFILE,
        "backend": crate::windows_readonly::BACKEND,
        "backend_executable": backend,
        "workspace": workspace,
        "cwd": cwd,
        "executable": live,
        "command": launch,
        "allowed_executables": [live],
        "denied_capabilities": [
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "write-outside-workspace-and-private-temp",
            "unapproved-process-exec",
            "privileged-operation",
            "workspace-write",
            "workspace-credential-read",
        ],
    }))
}

/// Resident `prepare` on Windows: the read-only pytest profile's planner.
pub(crate) fn prepare(input: &Value) -> Value {
    match plan(input) {
        Ok(plan) => json!({ "value": plan }),
        Err(error) => json!({ "reason_code": error.reason_code, "message": error.message }),
    }
}

#[cfg(test)]
#[path = "windows_pytest_tests.rs"]
mod tests;
