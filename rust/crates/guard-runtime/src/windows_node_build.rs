//! Windows backend for the Vite build profile.
//!
//! The resident plans `node <node_modules>/vite/bin/vite.js build ...` for the
//! first `node.exe` on the caller's `PATH`, and `contained-readonly-windows
//! --profile node-build-output-v1` runs it as a build run of the LPAC
//! snapshot runner. The workspace copy, the `node_modules` directories between
//! the run directory and the workspace root and the `node.exe` binary are
//! staged into a writable private copy, and only the declared output
//! directories are published back after a clean exit.
//!
//! Only a flat npm or Yarn classic install is staged. A pnpm store links
//! packages across directories, and a Plug'n'Play install has no
//! `node_modules` to copy, so both keep the review prompt.
use crate::windows_readonly::{canonical, first_on_path, workspace_and_cwd, BACKEND};
use guard_command::restricted_command::RestrictedPytestError;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub(crate) const PROFILE: &str = "node-build-output-v1";
const TOOL_ENTRY: &str = "vite/bin/vite.js";
const INVALID: &str = "pytest_restricted_invalid_command";
const UNAVAILABLE: &str = "pytest_restricted_sandbox_unavailable";
const PNPM_MARKERS: [&str; 2] = [".modules.yaml", ".pnpm"];

fn error(reason_code: &str, message: &str) -> RestrictedPytestError {
    RestrictedPytestError {
        reason_code: reason_code.to_owned(),
        message: message.to_owned(),
    }
}

fn unavailable() -> RestrictedPytestError {
    error(
        UNAVAILABLE,
        "The local Vite install cannot be staged for a protected build on Windows.",
    )
}

/// Below this a `node.exe` is a launcher rather than the runtime. Node links
/// V8 into one image of tens of megabytes, while Volta, Scoop and Chocolatey
/// each put a small program named `node.exe` on `PATH` that finds the real
/// runtime through its own install. The snapshot stages this one file, where a
/// launcher has nothing left to find, so the build would fail inside the
/// container instead of asking for review.
pub(crate) const MINIMUM_RUNTIME_BYTES: u64 = 8 * 1024 * 1024;

/// A `node.exe` image; the runner copies it, so it must not need its install.
pub(crate) fn node_executable(path: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let missing = || error(UNAVAILABLE, "The Node.js runtime could not be resolved.");
    let executable = canonical(path)
        .filter(|path| path.is_file())
        .ok_or_else(missing)?;
    let named = executable
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("node.exe"));
    let mut magic = [0u8; 2];
    let image = std::fs::File::open(&executable)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_ok()
        && magic == *b"MZ";
    if !named || !image {
        return Err(missing());
    }
    let size = std::fs::metadata(&executable).map_err(|_| missing())?.len();
    if size < MINIMUM_RUNTIME_BYTES {
        return Err(error(
            UNAVAILABLE,
            "The `node.exe` on PATH is a launcher for another Node.js install, which a protected build cannot stage.",
        ));
    }
    Ok(executable)
}

/// `--max-old-space-size=<MiB>` is the only runtime option the sink accepts.
pub(crate) fn runtime_option(argument: &str) -> bool {
    argument
        .strip_prefix("--max-old-space-size=")
        .and_then(|value| {
            (value.bytes().all(|byte| byte.is_ascii_digit()) && value.len() <= 6)
                .then(|| value.parse::<u32>().ok())
                .flatten()
        })
        .is_some_and(|size| (16..=131_072).contains(&size))
}

/// The `node_modules` directories Node would search from `cwd` up to the
/// workspace root, as `(link target, workspace-relative location)` pairs.
/// Each must resolve to a directory still named `node_modules` and hold no
/// pnpm store.
pub(crate) fn dependencies(
    workspace: &Path,
    cwd: &Path,
) -> Result<Vec<(PathBuf, PathBuf)>, RestrictedPytestError> {
    let mut found = Vec::new();
    let mut directory = cwd.to_path_buf();
    while directory.starts_with(workspace) {
        let location = directory.join("node_modules");
        if std::fs::symlink_metadata(&location).is_ok() {
            let target = canonical(&location)
                .filter(|target| {
                    target.is_dir()
                        && target
                            .file_name()
                            .is_some_and(|name| name.eq_ignore_ascii_case("node_modules"))
                })
                .ok_or_else(unavailable)?;
            if PNPM_MARKERS
                .iter()
                .any(|marker| std::fs::symlink_metadata(target.join(marker)).is_ok())
            {
                return Err(error(
                    UNAVAILABLE,
                    "A pnpm install cannot be staged for a protected build on Windows yet.",
                ));
            }
            if links_a_package(&target) {
                return Err(error(
                    UNAVAILABLE,
                    "A linked package cannot be staged for a protected build on Windows yet.",
                ));
            }
            let relative = location
                .strip_prefix(workspace)
                .map_err(|_| unavailable())?
                .to_path_buf();
            found.push((target, relative));
        }
        if directory == workspace || !directory.pop() {
            break;
        }
    }
    Ok(found)
}

/// Whether an installed package is a link rather than a directory of its own.
/// `npm link`, a Yarn workspace and a junction into a sibling checkout all
/// leave a reparse point where the package should be, and the copy that stages
/// the snapshot walks directories and files only. The build would then start
/// with that package missing and fail inside the container, so the command
/// keeps the review prompt instead. Scoped names hold their packages one level
/// down, which is where their links are.
fn links_a_package(modules: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(modules) else {
        // A directory this cannot read is one the copy cannot read either.
        return true;
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            return true;
        };
        if kind.is_symlink() {
            return true;
        }
        let name = entry.file_name();
        if kind.is_dir()
            && name.to_string_lossy().starts_with('@')
            && links_a_package(&entry.path())
        {
            return true;
        }
    }
    false
}

/// The entry as the snapshot's run directory reaches it: the staged copy of
/// the dependency that holds it, relative to `cwd`.
pub(crate) fn staged_entry(
    entry: &Path,
    dependencies: &[(PathBuf, PathBuf)],
    cwd: &Path,
) -> Option<PathBuf> {
    let entry = canonical(entry).filter(|entry| entry.is_file())?;
    let (target, location) = dependencies
        .iter()
        .find(|(target, _)| entry.starts_with(target))?;
    let mut staged: PathBuf = cwd
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .map(|_| Component::ParentDir)
        .collect();
    staged.push(location);
    staged.push(entry.strip_prefix(target).ok()?);
    Some(staged)
}

/// A declared output as a workspace-relative path below an existing parent.
pub(crate) fn output_location(output: &Path, workspace: &Path) -> Option<PathBuf> {
    let name = match output.components().next_back()? {
        Component::Normal(name) => name,
        _ => return None,
    };
    let parent = canonical(output.parent()?)?;
    let relative = parent.strip_prefix(workspace).ok()?.join(name);
    relative
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
        .then_some(relative)
}

fn plan(input: &Value) -> Result<Value, RestrictedPytestError> {
    let invalid = || error(INVALID, "Protected builds require direct Vite argv.");
    let strings = |key: &str| -> Result<Vec<String>, RestrictedPytestError> {
        input
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or_else(invalid)
    };
    let runtime = strings("runtime_arguments")?;
    let arguments = strings("arguments")?;
    if runtime.len() > 1
        || !runtime.iter().all(|argument| runtime_option(argument))
        || arguments.first().map(String::as_str) != Some("build")
    {
        return Err(invalid());
    }
    let path = |key: &str| input.get(key).and_then(Value::as_str).map(PathBuf::from);
    let (workspace, cwd) = workspace_and_cwd(
        &path("workspace").ok_or_else(invalid)?,
        &path("cwd").ok_or_else(invalid)?,
    )?;
    let search_path = input
        .get("search_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let node = first_on_path(&["node.exe".to_owned()], search_path)
        .ok_or_else(|| error(UNAVAILABLE, "The Node.js runtime could not be resolved."))?;
    let node = node_executable(&node)?;
    // `nearest_project_root`: the closest directory holding the entry.
    let mut directory = cwd.clone();
    while directory != workspace
        && std::fs::symlink_metadata(directory.join("node_modules").join(TOOL_ENTRY)).is_err()
    {
        directory.pop();
    }
    let modules = canonical(&directory.join("node_modules")).ok_or_else(unavailable)?;
    let entry = canonical(&modules.join(TOOL_ENTRY))
        .filter(|entry| entry.is_file() && entry.starts_with(&modules))
        .ok_or_else(unavailable)?;
    if let Some(expected) = path("expected_entry") {
        // A relative entrypoint names a file below the command's directory.
        if canonical(&cwd.join(expected)).as_ref() != Some(&entry) {
            return Err(unavailable());
        }
    }
    let staged = dependencies(&workspace, &cwd)?;
    if staged_entry(
        &entry,
        &staged,
        cwd.strip_prefix(&workspace).unwrap_or(&cwd),
    )
    .is_none()
    {
        return Err(unavailable());
    }
    let backend = std::env::current_exe()
        .ok()
        .and_then(|path| canonical(&path))
        .ok_or_else(|| error(UNAVAILABLE, "The Guard runtime path is unavailable."))?;
    let mut command = vec![node.to_string_lossy().into_owned()];
    command.extend(runtime);
    // Forward slashes, as the hook's own `node <dir>/node_modules/<entry>`
    // recognition reads them; Node accepts either separator.
    command.push(entry.to_string_lossy().replace('\\', "/"));
    command.extend(arguments);
    Ok(json!({
        "profile_version": PROFILE,
        "backend": BACKEND,
        "backend_executable": backend,
        "workspace": workspace,
        "cwd": cwd,
        "executable": node,
        "command": command,
        "allowed_executables": [node],
        "denied_capabilities": ["host-home-read","host-secret-environment","network","workspace-source-write","workspace-credential-read","privileged-operation"],
    }))
}

/// Resident `prepare_node_build` on Windows.
pub(crate) fn prepare_node_build(input: &Value) -> Value {
    match plan(input) {
        Ok(plan) => json!({ "value": plan }),
        Err(error) => json!({ "reason_code": error.reason_code, "message": error.message }),
    }
}

#[cfg(test)]
#[path = "windows_node_build_tests.rs"]
mod tests;
