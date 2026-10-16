//! Contained execution of one interpreter against a private workspace copy.
//!
//! The live workspace is never granted. A bounded, handle-bound copy is staged
//! in a private directory; only that copy (read-only) and private HOME/TEMP
//! directories (read-write) are granted to a fresh LPAC AppContainer SID. The
//! rest of the user profile stays unreadable and the container requests no
//! network capability. Callers own the withholding policy and environment.
//!
//! A build run (`BuildRun`) differs in three ways. The copy is writable, so
//! the tool can write caches and its output inside it. The interpreter binary
//! and the dependency directories it needs are copied in too, because an LPAC
//! process cannot read a per-user install. After a clean exit, only the
//! declared output directories are synced back to the live workspace, through
//! handle-bound writes that never follow a link.
//!
//! An LPAC process cannot read the registry policy the loader consults when it
//! first builds a module's activation context, so a manifest-bearing DLL fails
//! to load until one exists. The runner builds those contexts beforehand for
//! the installation's and the snapshot's binaries; this parses manifests only
//! and runs no module code. Granting `registryRead` instead would also expose
//! the user's HKCU hive, including persisted environment variables, so only a
//! build run, whose Node runtime cannot start Winsock without it, requests it.
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
const MAX_EXECUTABLE_BYTES: usize = 512 * 1024 * 1024;
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
    pub build: Option<BuildRun<'a>>,
}

pub struct BuildRun<'a> {
    /// `(live directory, workspace-relative destination)` pairs copied into
    /// the snapshot, such as a `node_modules` the workspace copy withholds.
    pub dependencies: &'a [(PathBuf, PathBuf)],
    /// Dependency-relative paths that never enter the snapshot.
    pub withhold_dependency: &'a dyn Fn(&Path) -> bool,
    pub max_dependency_entries: usize,
    pub max_dependency_bytes: usize,
    /// Workspace-relative directories published back after exit code 0.
    pub outputs: &'a [PathBuf],
    pub max_output_entries: usize,
    pub max_output_bytes: usize,
}

struct Limits<'a> {
    withhold: &'a dyn Fn(&Path) -> bool,
    max_entries: usize,
    max_bytes: usize,
}

#[derive(Default)]
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
    let mut suffix = [0u8; 12];
    getrandom::fill(&mut suffix).map_err(io::Error::other)?;
    let name = format!("hol-guard-ro-{}", hex::encode(suffix));
    let mut container = AppContainer::create(&name)?;
    if run.build.is_some() {
        container.allow_registry_read()?;
        // Granted while empty, so every copied object inherits write access.
        container.grant(&snapshot, true, true)?;
    }
    let workspace_limits = Limits {
        withhold: run.withhold,
        max_entries: run.max_entries,
        max_bytes: run.max_bytes,
    };
    copy_tree(
        &workspace,
        Path::new("."),
        &snapshot,
        &workspace_limits,
        &mut Budget::default(),
    )?;
    drop(workspace);
    let mut executable = run.executable.to_path_buf();
    if let Some(build) = &run.build {
        let limits = Limits {
            withhold: build.withhold_dependency,
            max_entries: build.max_dependency_entries,
            max_bytes: build.max_dependency_bytes,
        };
        let mut budget = Budget::default();
        for (source, destination) in build.dependencies {
            bound_fs::relative_components(destination)?;
            let target = snapshot.join(destination);
            fs::create_dir_all(&target)?;
            let source = Directory::open(source)?;
            copy_tree(&source, Path::new("."), &target, &limits, &mut budget)?;
        }
        executable = stage_executable(run.executable, &staging.path().join("bin"))?;
        grant_snapshot(&container, executable.parent().unwrap_or(staging.path()))?;
    }
    let mut remaining = MAX_ACTIVATION_ENTRIES;
    if let Some(installation) = executable.parent() {
        build_activation_contexts(installation, 0, &mut remaining);
    }
    build_activation_contexts(&snapshot, 0, &mut remaining);
    if run.build.is_none() {
        grant_snapshot(&container, &snapshot)?;
    }
    container.grant(&home, true, true)?;
    container.grant(&temp, true, true)?;
    // Windows points an AppContainer's TEMP and LOCALAPPDATA at its package
    // folder under the supplied LOCALAPPDATA; create it inside private HOME.
    fs::create_dir_all(home.join("Packages").join(&name).join("AC").join("Temp"))?;
    let mut environment = private_environment(run.environment, &home, &temp);
    if run.build.is_some() {
        staged_search_path(&mut environment, &executable);
    }
    let arguments: Vec<&OsStr> = run.arguments.iter().map(OsString::as_os_str).collect();
    let command = PinnedCommand::new(&executable, &arguments, &snapshot.join(&cwd), &environment)?;
    let output = command.capture(
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
    )?;
    if let Some(build) = &run.build {
        if output.exit_code == Some(0) && !output.timed_out {
            super::publish::publish_outputs(run.workspace, &snapshot, build, run.withhold)?;
        }
    }
    Ok(output)
}

/// An LPAC process cannot read a per-user install, so the binary itself is
/// copied next to the snapshot. Only a self-contained executable such as
/// `node.exe` runs this way; it loads nothing else from its install.
fn stage_executable(source: &Path, directory: &Path) -> io::Result<PathBuf> {
    let name = source.file_name().ok_or_else(bound_fs::changed)?;
    let mut file = bound_fs::open_executable(source)?;
    let image = bound_fs::read_executable(&mut file, MAX_EXECUTABLE_BYTES)?;
    fs::create_dir(directory)?;
    let target = directory.join(name);
    fs::write(&target, &image.bytes)?;
    Ok(target)
}

/// The staged binary's directory and the system directories, nothing from
/// the user's own search path.
fn staged_search_path(environment: &mut Vec<(OsString, OsString)>, executable: &Path) {
    environment.retain(|(name, _)| !name.eq_ignore_ascii_case("PATH"));
    let mut path = vec![executable.parent().unwrap_or(executable).to_path_buf()];
    if let Some((_, root)) = environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("SystemRoot"))
    {
        let root = PathBuf::from(root);
        path.push(root.join("System32"));
        path.push(root);
    }
    if let Ok(path) = std::env::join_paths(path) {
        environment.push(("PATH".into(), path));
    }
}

/// Links and other reparse points are never followed into the snapshot.
fn copy_tree(
    source: &Directory,
    relative: &Path,
    target: &Path,
    run: &Limits<'_>,
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
            ["pyd", "dll", "node"]
                .iter()
                .any(|known| extension.eq_ignore_ascii_case(known))
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
