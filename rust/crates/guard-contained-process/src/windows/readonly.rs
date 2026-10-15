//! Read-only contained execution of one installed interpreter.
//!
//! The live workspace is never granted. A bounded, handle-bound copy is staged
//! in a private directory; only that copy (read-only) and private HOME/TEMP
//! directories (read-write) are granted to a fresh LPAC AppContainer SID. The
//! rest of the user profile stays unreadable and the container requests no
//! network capability. Callers own the withholding policy and environment.
//!
//! An LPAC process cannot read the registry policy the loader consults when it
//! first builds a module's activation context, so a manifest-bearing DLL fails
//! to load until one exists. The runner builds those contexts beforehand for
//! the installation's and the snapshot's binaries; this parses manifests only
//! and runs no module code. Granting `registryRead` instead would also expose
//! the user's HKCU hive, including persisted environment variables.
use super::AppContainer;
use crate::bound_fs::{self, Directory};
use crate::{CapturedOutput, Isolation, PinnedCommand};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

const REPARSE_POINT: u32 = 0x400;
const MAX_ACTIVATION_ENTRIES: usize = 20_000;
const MAX_ACTIVATION_DEPTH: usize = 12;
/// Profile locations always name the private staging directories.
const PROFILE_VARIABLES: [&str; 8] = [
    "APPDATA",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "USERPROFILE",
];

pub struct ReadonlySnapshotRun<'a> {
    pub workspace: &'a Path,
    /// Working directory inside `workspace`.
    pub cwd: &'a Path,
    pub executable: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a [(OsString, OsString)],
    /// Workspace-relative paths that never enter the snapshot.
    pub withhold: &'a dyn Fn(&Path) -> bool,
    pub max_entries: usize,
    pub max_bytes: usize,
    pub output_cap: usize,
    pub deadline: Instant,
    pub cancel: &'a AtomicBool,
    pub job_limits: guard_runtime_windows_process::ResourceLimits,
}

struct Budget {
    entries: usize,
    bytes: usize,
}

pub fn run_readonly_snapshot(run: ReadonlySnapshotRun<'_>) -> io::Result<CapturedOutput> {
    let workspace = Directory::open(run.workspace)?;
    let cwd = run
        .cwd
        .strip_prefix(workspace.path())
        .map_err(|_| bound_fs::changed())?
        .to_path_buf();
    if !cwd.as_os_str().is_empty() {
        bound_fs::relative_components(&cwd)?;
    }
    let staging = tempfile::Builder::new()
        .prefix("hol-guard-readonly-")
        .tempdir()?;
    let snapshot = staging.path().join("workspace");
    let home = staging.path().join("home");
    let temp = staging.path().join("tmp");
    for directory in [&snapshot, &home, &temp] {
        fs::create_dir(directory)?;
    }
    let mut budget = Budget {
        entries: 0,
        bytes: 0,
    };
    copy_tree(&workspace, Path::new("."), &snapshot, &run, &mut budget)?;
    drop(workspace);
    let mut remaining = MAX_ACTIVATION_ENTRIES;
    if let Some(installation) = run.executable.parent() {
        build_activation_contexts(installation, 0, &mut remaining);
    }
    build_activation_contexts(&snapshot, 0, &mut remaining);
    let mut suffix = [0u8; 12];
    getrandom::fill(&mut suffix).map_err(io::Error::other)?;
    let name = format!("hol-guard-ro-{}", hex::encode(suffix));
    let container = AppContainer::create(&name)?;
    grant_snapshot(&container, &snapshot)?;
    container.grant(&home, true, true)?;
    container.grant(&temp, true, true)?;
    // Windows points an AppContainer's TEMP and LOCALAPPDATA at its package
    // folder under the supplied LOCALAPPDATA; create it inside private HOME.
    fs::create_dir_all(home.join("Packages").join(&name).join("AC").join("Temp"))?;
    let environment = private_environment(run.environment, &home, &temp);
    let arguments: Vec<&OsStr> = run.arguments.iter().map(OsString::as_os_str).collect();
    let command = PinnedCommand::new(
        run.executable,
        &arguments,
        &snapshot.join(&cwd),
        &environment,
    )?;
    command.capture(
        &[],
        run.output_cap,
        run.deadline,
        run.cancel,
        Isolation {
            app_container: Some(container),
            job_limits: Some(run.job_limits),
            output_per_stream: true,
            ..Isolation::default()
        },
    )
}

/// Links and other reparse points are never followed into the snapshot.
fn copy_tree(
    source: &Directory,
    relative: &Path,
    target: &Path,
    run: &ReadonlySnapshotRun<'_>,
    budget: &mut Budget,
) -> io::Result<()> {
    let remaining = run.max_entries.saturating_sub(budget.entries);
    for name in source.entries(relative, remaining)? {
        let child = if relative == Path::new(".") {
            PathBuf::from(&name)
        } else {
            relative.join(&name)
        };
        if (run.withhold)(&child) {
            continue;
        }
        budget.entries += 1;
        if budget.entries > run.max_entries {
            return Err(budget_exceeded());
        }
        let metadata = source.metadata(&child)?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0 {
            continue;
        }
        let destination = target.join(&child);
        if metadata.is_dir() {
            fs::create_dir(&destination)?;
            copy_tree(source, &child, target, run, budget)?;
        } else if metadata.is_file() {
            let file = source.read(&child, run.max_bytes.saturating_sub(budget.bytes))?;
            budget.bytes += file.bytes.len();
            fs::write(&destination, &file.bytes)?;
        }
    }
    Ok(())
}

/// Best effort: a context that cannot be built only makes that module fail to
/// load inside the container.
fn build_activation_contexts(directory: &Path, depth: usize, remaining: &mut usize) {
    if depth > MAX_ACTIVATION_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if *remaining == 0 {
            return;
        }
        *remaining -= 1;
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0 {
            continue;
        }
        let path = entry.path();
        if metadata.is_dir() {
            build_activation_contexts(&path, depth + 1, remaining);
        } else if path.extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("pyd") || extension.eq_ignore_ascii_case("dll")
        }) {
            super::build_activation_context(&path);
        }
    }
}

/// Children first: a granted directory's protected DACL stops inheritance, so
/// granting it before its children would strip the access their grants need.
fn grant_snapshot(container: &AppContainer, directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            grant_snapshot(container, &entry.path())?;
        } else if file_type.is_file() {
            container.grant(&entry.path(), false, false)?;
        } else {
            return Err(bound_fs::changed());
        }
    }
    container.grant(directory, false, true)
}

fn private_environment(
    source: &[(OsString, OsString)],
    home: &Path,
    temp: &Path,
) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<(OsString, OsString)> = source
        .iter()
        .filter(|(name, _)| {
            !PROFILE_VARIABLES
                .iter()
                .any(|profile| name.eq_ignore_ascii_case(profile))
        })
        .cloned()
        .collect();
    for name in ["APPDATA", "HOME", "LOCALAPPDATA", "USERPROFILE"] {
        environment.push((name.into(), home.as_os_str().to_owned()));
    }
    for name in ["TEMP", "TMP"] {
        environment.push((name.into(), temp.as_os_str().to_owned()));
    }
    environment
}

fn budget_exceeded() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "read-only snapshot budget exceeded",
    )
}

#[cfg(test)]
#[path = "readonly_tests.rs"]
mod tests;
