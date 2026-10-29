//! The one directory a contained Node build may write, and whether Guard
//! grants it.
//!
//! A build's output root is the only place the run may overwrite, so naming it
//! is a verdict rather than a convenience. The reading lives here once: the
//! command's own `--outDir`, the config the command names, the conventional
//! `dist` beside a package manifest, and the walk that refuses an existing
//! directory holding protected data or aliased files. The planner that grants
//! the write and the recheck the sandbox performs just before it launches both
//! ask this module, so a build cannot be granted one directory and started
//! against another.

use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};

use crate::vite_output::{bundle_directory, declared_output, Declared};

const REASON: &str = "node_build_invalid_output";
const MAX_VISITED: usize = 20_000;
const CONVENTIONAL: [&str; 3] = ["dist", "build", "out"];

/// The refusal a build reports instead of failing later on a denied write.
pub struct Refusal(&'static str);

impl Refusal {
    fn reply(&self) -> Value {
        json!({"reason_code": REASON, "message": self.0})
    }
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// Whether an existing regular file has exactly one directory entry.
///
/// A second hard link to a file inside the output directory is a way to reach
/// a file outside it, since emptying the directory and rewriting the name
/// would write through the alias.
fn single_link_file(path: &Path, metadata: &std::fs::Metadata) -> bool {
    if !metadata.is_file() {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        metadata.nlink() == 1
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        guard_runtime_windows_process::is_single_link_file(path).unwrap_or(false)
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (path, metadata);
        false
    }
}

/// The workspace root, or a package directory below it reached without links.
///
/// Only plain names stand between the workspace and the package: a `.` or `..`
/// component, a hidden directory, or `node_modules` leaves the directory
/// outside the set a build may own.
fn package_directory(directory: &Path, workspace: &Path) -> bool {
    if directory == workspace {
        return true;
    }
    let Ok(relative) = directory.strip_prefix(workspace) else {
        return false;
    };
    if !directory.join("package.json").is_file() {
        return false;
    }
    let mut reached = workspace.to_path_buf();
    for part in relative.components() {
        let Component::Normal(name) = part else {
            return false;
        };
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" {
            return false;
        }
        reached.push(part);
        if is_symlink(&reached) {
            return false;
        }
    }
    true
}

/// A package below the workspace (a monorepo app reached with `cd`) builds
/// into its own `dist`, next to its `package.json`.
fn conventional_output(path: &Path, workspace: &Path) -> bool {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    package_directory(parent, workspace) && CONVENTIONAL.contains(&name.to_string_lossy().as_ref())
}

/// Accept a conventional build directory, the config loader's own bundle
/// directory, or the literal output the Vite config in `cwd` names.
pub fn output_root_admissible(
    path: &Path,
    workspace: &Path,
    cwd: Option<&Path>,
) -> Result<(), Refusal> {
    let linked = is_symlink(path);
    let bundle = !linked
        && cwd.is_some_and(|cwd| {
            path.parent()
                .and_then(|modules| bundle_directory(cwd, workspace, modules))
                .as_deref()
                == Some(path)
        });
    let conventional = conventional_output(path, workspace);
    // A config that names a non-literal outDir refuses. Read the bundle
    // directory first so that recheck does not refuse a command-line --outDir.
    let declared = match cwd {
        Some(cwd) if !bundle && !conventional => match declared_output(cwd, workspace, None) {
            Declared::Unverified => return Err(Refusal(UNVERIFIED)),
            Declared::Output(output) => output == path,
            Declared::Default => false,
        },
        _ => false,
    };
    if linked || !(conventional || declared || bundle) {
        return Err(Refusal(
            "Build output must be a dedicated generated directory.",
        ));
    }
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    if !metadata.is_dir() {
        return Err(Refusal("Build output is not a directory."));
    }
    existing_contents_admissible(path, workspace)
}

/// The build empties its output first, so everything already there must be
/// Guard's to remove: no protected data, no link and no second name for a
/// file that lives elsewhere.
fn existing_contents_admissible(path: &Path, workspace: &Path) -> Result<(), Refusal> {
    let mut visited = 0usize;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        // An unreadable directory lists nothing, as the walk this ports does.
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return Err(Refusal(UNVERIFIED_LINKS));
            };
            visited += 1;
            let candidate = entry.path();
            // Every candidate is spelled absolutely, so no home expansion
            // applies and the workspace is the only anchor the tables need.
            if crate::secret_path_probe::is_secret_path(
                &candidate.to_string_lossy(),
                Some(workspace),
                None,
            ) {
                return Err(Refusal("Build output contains protected data."));
            }
            let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
                return Err(Refusal(UNVERIFIED_LINKS));
            };
            if visited > MAX_VISITED
                || metadata.file_type().is_symlink()
                || !single_link_file(&candidate, &metadata)
            {
                return Err(Refusal(UNVERIFIED_LINKS));
            }
            if metadata.is_dir() {
                pending.push(candidate);
            }
        }
    }
    Ok(())
}

const UNVERIFIED: &str =
    "The Vite config sets an output directory HOL Guard could not verify inside the project.";
const UNVERIFIED_LINKS: &str = "Build output has unverified links or exceeds the discovery budget.";

/// The file named by the command's last `--config`, relative to the build's
/// working directory.
fn explicit_config(arguments: &[String], cwd: &Path) -> Result<Option<PathBuf>, Refusal> {
    let mut chosen: Option<&str> = None;
    let mut index = 0;
    while index < arguments.len() {
        let value = arguments[index].as_str();
        if value == "-c" || value == "--config" {
            let next = arguments.get(index + 1);
            match next {
                Some(next) if !next.starts_with('-') => chosen = Some(next.as_str()),
                _ => return Err(Refusal("Missing Vite config.")),
            }
            index += 2;
            continue;
        }
        if let Some(named) = value.strip_prefix("--config=") {
            if named.is_empty() {
                return Err(Refusal("Missing Vite config."));
            }
            chosen = Some(named);
        }
        index += 1;
    }
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let path = Path::new(chosen);
    Ok(Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }))
}

/// The build's last `--outDir`, else the config's literal one, else `dist`.
///
/// `--outDir` wins. Otherwise read the config the command names, or the
/// default `vite.config.*` when it names none: skipping a named config used to
/// grant `dist` while Vite wrote the directory that file declared.
pub fn output_root(arguments: &[String], workspace: &Path, cwd: &Path) -> Result<PathBuf, Refusal> {
    let mut named: Option<&str> = None;
    for (index, value) in arguments.iter().enumerate() {
        if let Some(value) = value.strip_prefix("--outDir=") {
            named = Some(value);
        } else if value == "--outDir" {
            named = Some(
                arguments
                    .get(index + 1)
                    .ok_or(Refusal("Missing output directory."))?
                    .as_str(),
            );
        }
    }
    // An empty `--outDir=` names nothing, so the config is still read.
    let declared = match named.filter(|value| !value.is_empty()) {
        Some(_) => None,
        None => {
            match declared_output(cwd, workspace, explicit_config(arguments, cwd)?.as_deref()) {
                Declared::Unverified => return Err(Refusal(UNVERIFIED)),
                Declared::Output(output) => Some(output),
                Declared::Default => None,
            }
        }
    };
    let output = match &declared {
        Some(output) => output.clone(),
        None => cwd.join(named.filter(|value| !value.is_empty()).unwrap_or("dist")),
    };
    output_root_admissible(
        &output,
        workspace,
        if declared.is_some() { Some(cwd) } else { None },
    )?;
    Ok(output)
}

fn requested_path(input: &Value, field: &str) -> Option<PathBuf> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn requested_arguments(input: &Value) -> Option<Vec<String>> {
    input
        .get("arguments")?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// `node_build_output_root` answers the one directory the build may write, and
/// `node_build_output_admissible` answers whether a directory already named in
/// a plan is still one Guard grants.
///
/// A request that names no project, or whose arguments are not the command's
/// own words, describes no build Guard can place, so it refuses rather than
/// falling back to a directory nothing verified.
pub fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if !matches!(
        operation,
        "node_build_output_root" | "node_build_output_admissible"
    ) {
        return None;
    }
    let unreadable = Refusal("HOL Guard could not read the project this build writes into.");
    let Some(workspace) = requested_path(input, "workspace") else {
        return Some(unreadable.reply());
    };
    if operation == "node_build_output_admissible" {
        let Some(path) = requested_path(input, "path") else {
            return Some(unreadable.reply());
        };
        let cwd = requested_path(input, "cwd");
        return Some(
            match output_root_admissible(&path, &workspace, cwd.as_deref()) {
                Ok(()) => json!({"value": true}),
                Err(refusal) => refusal.reply(),
            },
        );
    }
    let (Some(cwd), Some(arguments)) = (requested_path(input, "cwd"), requested_arguments(input))
    else {
        return Some(unreadable.reply());
    };
    Some(match output_root(&arguments, &workspace, &cwd) {
        Ok(output) => json!({"value": output.to_string_lossy()}),
        Err(refusal) => refusal.reply(),
    })
}

#[cfg(test)]
#[path = "node_build_output_tests.rs"]
mod tests;
