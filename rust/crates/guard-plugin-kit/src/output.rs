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
/// Files the Kit did not write are left alone.
pub fn clear_previous(out: &Path) -> Result<(), String> {
    let Some(text) = walk::read_text(&out.join(PROVENANCE_FILE)) else {
        return Ok(());
    };
    let Ok(provenance) = serde_json::from_str::<Value>(&text) else {
        return Ok(());
    };
    if provenance.get("schema").and_then(Value::as_str) != Some(PROVENANCE_SCHEMA) {
        return Ok(());
    }
    let files = provenance
        .get("files")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut paths: Vec<PathBuf> = files
        .iter()
        .filter_map(|file| file.get("path").and_then(Value::as_str))
        .map(PathBuf::from)
        .filter(|path| plain(path))
        .collect();
    paths.push(PathBuf::from(PROVENANCE_FILE));
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
