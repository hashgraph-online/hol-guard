//! Where the Kit writes: the output folder rules for `package` and the file
//! writes shared with `init`.
//!
//! A write never follows a symlink, never lands inside a source folder the
//! Kit reads, and either finishes or removes what it created.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::emit::Output;
use crate::model::Plugin;
use crate::{walk, PROVENANCE_FILE, PROVENANCE_SCHEMA};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Create every file; fail if one already exists.
    Exclusive,
    /// Replace existing regular files.
    Replace,
}

/// A repository-relative output path from `hol.json` or the default. It must
/// be plain components, and no part that already exists may be a symlink.
pub fn inside_root(root: &Path, configured: &str) -> Result<PathBuf, String> {
    let relative = Path::new(configured);
    if relative.as_os_str().is_empty() || !plain(relative) {
        return Err("plugin_kit_output_path_invalid".to_owned());
    }
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("plugin_kit_output_path_blocked".to_owned());
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(_) => return Err("plugin_kit_output_unwritable".to_owned()),
        }
    }
    Ok(root.join(relative))
}

/// Refuses an output folder that is the repository root, or that contains or
/// sits inside a folder the Kit reads plugin files from. Provenance written
/// there would make the next run skip that folder as earlier output.
pub fn reject_source_overlap(root: &Path, out: &Path, plugin: &Plugin) -> Result<(), String> {
    let Ok(relative) = out.strip_prefix(root) else {
        return Ok(());
    };
    if relative.as_os_str().is_empty() {
        return Err("plugin_kit_output_inside_source".to_owned());
    }
    let base = Path::new(&plugin.base);
    let mut folders: Vec<PathBuf> = plugin
        .skills
        .iter()
        .filter(|skill| !skill.dir.is_empty())
        .map(|skill| PathBuf::from(&skill.dir))
        .collect();
    folders.push(base.join("commands"));
    folders.push(base.join("agents"));
    folders.push(base.join("hooks"));
    let overlaps = folders
        .iter()
        .any(|folder| relative.starts_with(folder) || folder.starts_with(relative));
    if overlaps {
        return Err("plugin_kit_output_inside_source".to_owned());
    }
    Ok(())
}

/// Refuses an output folder that is the plugin folder, a folder holding it,
/// the home folder or a filesystem root, with or without `--force`. Writing
/// there would mix generated files with the user's own.
pub fn reject_unsafe_out(root: &Path, out: &Path) -> Result<(), String> {
    let out = settled(out);
    let home = ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .filter(|value| !value.is_empty())
        .map(|value| settled(Path::new(&value)));
    if out.parent().is_none() || root.starts_with(&out) || home.into_iter().any(|home| home == out)
    {
        return Err("plugin_kit_output_unsafe".to_owned());
    }
    Ok(())
}

/// `path` with its longest existing ancestor resolved, so a symlinked home or
/// temp folder compares equal to its target.
fn settled(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    while existing.canonicalize().is_err() {
        let Some(name) = existing.file_name().map(ToOwned::to_owned) else {
            return path.to_path_buf();
        };
        rest.push(name);
        if !existing.pop() {
            return path.to_path_buf();
        }
    }
    let mut resolved = existing.canonicalize().unwrap_or(existing);
    for name in rest.iter().rev() {
        resolved.push(name);
    }
    resolved
}

pub fn require_empty(out: &Path) -> Result<(), String> {
    if let Ok(mut entries) = fs::read_dir(out) {
        if entries.next().is_some() {
            return Err("plugin_kit_output_not_empty".to_owned());
        }
    }
    Ok(())
}

/// Removes the files an earlier package recorded in its provenance, so a
/// forced rebuild does not keep runtimes or assets the new plan dropped.
/// Files the Kit did not write are left alone, and if the new plan would
/// replace one of them, or a provenance file the Kit cannot read claims
/// them, nothing is removed.
pub fn clear_previous(out: &Path, outputs: &[Output]) -> Result<(), String> {
    let paths = recorded(out)?;
    for path in &paths {
        if !real_folders(out, path)? {
            return Err("plugin_kit_output_path_blocked".to_owned());
        }
    }
    for output in outputs {
        planned_path_free(out, Path::new(&output.path), &paths)?;
    }
    for path in &paths {
        let target = out.join(path);
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.is_file()) {
            fs::remove_file(&target).map_err(|_| "plugin_kit_output_unwritable")?;
        }
    }
    // Remove folders the old package left empty, deepest first.
    let mut folders: Vec<PathBuf> = paths
        .iter()
        .flat_map(|path| path.ancestors().skip(1).map(Path::to_path_buf))
        .filter(|folder| !folder.as_os_str().is_empty())
        .collect();
    folders.sort_by_key(|folder| std::cmp::Reverse(folder.components().count()));
    folders.dedup();
    for folder in folders {
        let target = out.join(folder);
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.is_dir()) {
            let _ = fs::remove_dir(&target);
        }
    }
    Ok(())
}

/// True when every folder between `out` and `path` that exists is a real
/// folder, so removing `path` cannot follow a symlink out of `out`.
fn real_folders(out: &Path, path: &Path) -> Result<bool, String> {
    let mut current = out.to_path_buf();
    let components: Vec<_> = path.components().collect();
    for component in &components[..components.len().saturating_sub(1)] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
            Err(_) => return Err("plugin_kit_output_unwritable".to_owned()),
        }
    }
    Ok(true)
}

/// Refuses a planned output when anything on its path, other than a file the
/// earlier package recorded, is in the way.
fn planned_path_free(out: &Path, relative: &Path, recorded: &[PathBuf]) -> Result<(), String> {
    let mut current = out.to_path_buf();
    let mut prefix = PathBuf::new();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        prefix.push(component);
        let last = index + 1 == components.len();
        match fs::symlink_metadata(&current) {
            Ok(metadata) if !last && metadata.is_dir() => {}
            Ok(_) if recorded.contains(&prefix) => return Ok(()),
            Ok(_) if !last => return Err("plugin_kit_output_path_blocked".to_owned()),
            Ok(_) => return Err("plugin_kit_output_not_generated".to_owned()),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("plugin_kit_output_unwritable".to_owned()),
        }
    }
    Ok(())
}

/// The files an earlier package recorded in its provenance. No provenance
/// file means none; one the Kit cannot read proves nothing, so it stops the
/// rebuild rather than counting as empty.
fn recorded(out: &Path) -> Result<Vec<PathBuf>, String> {
    let location = out.join(PROVENANCE_FILE);
    match fs::symlink_metadata(&location) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Ok(metadata) if metadata.is_file() => {}
        _ => return Err("plugin_kit_output_not_generated".to_owned()),
    }
    let provenance = walk::read_text(&location)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(|value| value.get("schema").and_then(Value::as_str) == Some(PROVENANCE_SCHEMA))
        .ok_or_else(|| "plugin_kit_output_not_generated".to_owned())?;
    let files = provenance
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| "plugin_kit_output_not_generated".to_owned())?;
    let mut paths: Vec<PathBuf> = files
        .iter()
        .filter_map(|file| file.get("path").and_then(Value::as_str))
        .map(PathBuf::from)
        .filter(|path| plain(path))
        .collect();
    paths.push(PathBuf::from(PROVENANCE_FILE));
    Ok(paths)
}

/// Writes `outputs` under `out`. Every path is checked before the first
/// write; folders below `out` are created fresh or must be real folders, and
/// no symlink is written through. On failure, the files and folders this
/// call created are removed.
pub fn write(out: &Path, outputs: &[Output], mode: Mode) -> Result<Vec<String>, String> {
    if fs::symlink_metadata(out).is_ok_and(|metadata| !metadata.is_dir()) {
        return Err("plugin_kit_output_path_blocked".to_owned());
    }
    for output in outputs {
        let relative = Path::new(&output.path);
        if !plain(relative) {
            return Err("plugin_kit_output_path_invalid".to_owned());
        }
        let mut current = out.to_path_buf();
        let components: Vec<_> = relative.components().collect();
        for (index, component) in components.iter().enumerate() {
            current.push(component);
            let last = index + 1 == components.len();
            match fs::symlink_metadata(&current) {
                Ok(metadata) if !last && metadata.is_dir() => {}
                Ok(metadata) if last && metadata.is_file() && mode == Mode::Replace => {}
                Ok(_) if last && mode == Mode::Exclusive => {
                    return Err("plugin_kit_output_exists".to_owned());
                }
                Ok(_) => return Err("plugin_kit_output_path_blocked".to_owned()),
                Err(_) => break,
            }
        }
    }
    let mut created = Created::default();
    let result = write_all(out, outputs, mode, &mut created);
    if result.is_err() {
        created.undo();
    }
    result
}

#[derive(Default)]
struct Created {
    files: Vec<PathBuf>,
    folders: Vec<PathBuf>,
}

impl Created {
    fn undo(&self) {
        for file in self.files.iter().rev() {
            let _ = fs::remove_file(file);
        }
        for folder in self.folders.iter().rev() {
            let _ = fs::remove_dir(folder);
        }
    }

    fn folder(&mut self, path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            Ok(_) => Err("plugin_kit_output_path_blocked".to_owned()),
            Err(_) => {
                fs::create_dir(path).map_err(|_| "plugin_kit_output_unwritable")?;
                self.folders.push(path.to_path_buf());
                Ok(())
            }
        }
    }
}

fn write_all(
    out: &Path,
    outputs: &[Output],
    mode: Mode,
    created: &mut Created,
) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    let mut ancestor = out.to_path_buf();
    while fs::symlink_metadata(&ancestor).is_err() {
        missing.push(ancestor.clone());
        if !ancestor.pop() {
            return Err("plugin_kit_output_unwritable".to_owned());
        }
    }
    for folder in missing.iter().rev() {
        created.folder(folder)?;
    }
    let mut written = Vec::new();
    for output in outputs {
        let relative = Path::new(&output.path);
        let mut folder = out.to_path_buf();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                folder.push(component);
                created.folder(&folder)?;
            }
        }
        let target = out.join(relative);
        let existed = fs::symlink_metadata(&target).is_ok();
        let mut options = OpenOptions::new();
        options.write(true);
        if mode == Mode::Exclusive {
            options.create_new(true);
        } else {
            options.create(true).truncate(true);
        }
        let mut file = options.open(&target).map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                "plugin_kit_output_exists"
            } else {
                "plugin_kit_output_unwritable"
            }
        })?;
        if !existed {
            created.files.push(target.clone());
        }
        file.write_all(&output.content)
            .map_err(|_| "plugin_kit_output_unwritable")?;
        written.push(output.path.clone());
    }
    Ok(written)
}

fn plain(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}
