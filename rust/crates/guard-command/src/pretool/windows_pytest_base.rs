//! Whether the Windows read-only pytest profile can run a command at all.
//!
//! The AppContainer that profile launches can read an interpreter only under
//! the machine's Program Files folders, so the Windows planner refuses a
//! virtual environment whose `pyvenv.cfg` names a base Python installed for
//! one user (`%LOCALAPPDATA%\Programs\Python`, a uv-managed Python, a copy in
//! the home directory). Routing such a run to containment replaced its review
//! with a contained run that could only exit 126, so the run never happened
//! and no approval could start it. This reads the same `home` line the planner
//! reads and keeps the review when it names a base the container cannot run.
//!
//! Only a command that names its environment's launcher by path is read: the
//! activation projection rewrites `source .venv/bin/activate && pytest` to
//! `.venv/bin/pytest`. A bare `pytest` is resolved on the shell's `PATH`,
//! which the hook does not see, and keeps its containment.

// Only the Windows hook calls the reading; tests run it on every host.
#![cfg_attr(not(windows), allow(dead_code))]

use crate::CanonicalCommandV1;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A `pyvenv.cfg` holds a handful of `key = value` lines.
const PYVENV_CFG_MAX_BYTES: u64 = 64 * 1024;
const BINARY_DIRECTORIES: [&str; 2] = ["Scripts", "bin"];

/// The `home` a virtual environment's `pyvenv.cfg` records.
fn recorded_home(environment: &Path) -> Option<PathBuf> {
    let mut file = std::fs::File::open(environment.join("pyvenv.cfg")).ok()?;
    if file.metadata().ok()?.len() > PYVENV_CFG_MAX_BYTES {
        return None;
    }
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    text.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| key.trim().eq_ignore_ascii_case("home"))
        .map(|(_, value)| PathBuf::from(value.trim()))
}

/// The environment a launcher path belongs to: `<environment>/<Scripts|bin>/<name>`.
fn environment_of(executable: &str, cwd: &Path) -> Option<PathBuf> {
    if !executable.contains(['/', '\\']) {
        return None;
    }
    let launcher = cwd.join(executable.replace('\\', "/"));
    let binaries = launcher.parent()?;
    let named = binaries.file_name()?.to_str()?;
    if !BINARY_DIRECTORIES
        .iter()
        .any(|directory| named.eq_ignore_ascii_case(directory))
    {
        return None;
    }
    binaries
        .parent()
        .filter(|environment| environment.join("pyvenv.cfg").is_file())
        .map(Path::to_path_buf)
}

/// Whether the pytest run names a virtual environment whose base Python sits
/// outside every one of `roots`, which the Windows planner refuses.
///
/// A command whose environment cannot be found here is left to the planner.
pub(super) fn base_outside_install_roots(
    model: &CanonicalCommandV1,
    cwd: Option<&str>,
    roots: &[PathBuf],
) -> bool {
    let (Some(cwd), [segment]) = (cwd, model.segments.as_slice()) else {
        return false;
    };
    let Some(environment) = segment
        .executable
        .as_deref()
        .and_then(|executable| environment_of(executable, Path::new(cwd)))
    else {
        return false;
    };
    // The planner refuses an environment whose base it cannot resolve.
    let Some(base) =
        recorded_home(&environment).and_then(|home| home.join("python.exe").canonicalize().ok())
    else {
        return true;
    };
    !roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| base.starts_with(root))
}

/// [`base_outside_install_roots`] against the machine's Program Files folders.
#[cfg(windows)]
pub(super) fn base_outside_program_files(model: &CanonicalCommandV1, cwd: Option<&str>) -> bool {
    base_outside_install_roots(
        model,
        cwd,
        &guard_runtime_windows_process::trusted_install_roots(),
    )
}

/// Only the Windows planner reads the base install; other hosts run the
/// environment's interpreter wherever it was installed.
#[cfg(not(windows))]
pub(super) fn base_outside_program_files(_model: &CanonicalCommandV1, _cwd: Option<&str>) -> bool {
    false
}

#[cfg(test)]
#[path = "windows_pytest_base_tests.rs"]
mod tests;
