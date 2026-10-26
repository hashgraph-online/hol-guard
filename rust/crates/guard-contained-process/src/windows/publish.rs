//! Publishes a build run's declared output directories from the private
//! snapshot back to the live workspace.
//!
//! The container has exited by the time this runs, and only the declared
//! workspace-relative directories are written. The live side is reached
//! through handle-bound directories, so a link swapped into the path is
//! refused, not followed. The staged side is copied only as plain
//! directories and regular files; any link or other reparse point in it
//! fails the publish. A name the snapshot withheld is neither written nor
//! removed.
//!
//! The whole publish is weighed before any of it happens. A run that cannot
//! finish — a link or a device in the staged tree, or more entries or bytes
//! than the run allows — must not start, because a live output left part old
//! and part new is worse than one left alone. Everything the run would remove
//! is weighed too: a build that drops a large stale subtree pays for reading
//! and deleting it out of the same budget as the output it writes.
use super::readonly::BuildRun;
use crate::bound_fs::{self, identity, Directory};
use std::ffi::OsString;
use std::fs::Metadata;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::Path;

const REPARSE_POINT: u32 = 0x400;
/// One replaced or removed live file; built assets are far smaller.
const LIVE_FILE_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Budget {
    entries: usize,
    bytes: usize,
}

struct Publish<'a> {
    live: &'a Directory,
    staged: &'a Directory,
    withhold: &'a dyn Fn(&Path) -> bool,
    max_entries: usize,
    max_bytes: usize,
    budget: Budget,
}

pub(super) fn publish_outputs(
    workspace: &Path,
    snapshot: &Path,
    build: &BuildRun<'_>,
    withhold: &dyn Fn(&Path) -> bool,
) -> io::Result<()> {
    let live = Directory::open(workspace)?;
    let staged = Directory::open(snapshot)?;
    let mut publish = Publish {
        live: &live,
        staged: &staged,
        withhold,
        max_entries: build.max_output_entries,
        max_bytes: build.max_output_bytes,
        budget: Budget {
            entries: 0,
            bytes: 0,
        },
    };
    let mut planned = Vec::new();
    for output in build.outputs {
        bound_fs::relative_components(output)?;
        if withhold(output) {
            return Err(bound_fs::changed());
        }
        let metadata = match staged.metadata(output) {
            Ok(metadata) => metadata,
            // The build wrote nothing there; the live directory is left as is.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if linked(&metadata) || !metadata.is_dir() {
            return Err(bound_fs::changed());
        }
        publish.survey(output)?;
        planned.push(output);
    }
    for output in planned {
        live.mkdir_all(output)?;
        publish.apply(output)?;
    }
    Ok(())
}

fn linked(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0
}

fn missing(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

impl Publish<'_> {
    /// Weighs everything one output directory would write and remove, without
    /// touching the live side. Whatever this pass refuses, `apply` never sees.
    fn survey(&mut self, relative: &Path) -> io::Result<()> {
        let staged: Vec<OsString> = self.staged.entries(relative, self.remaining_entries())?;
        let live: Vec<OsString> = match self.live.entries(relative, self.max_entries) {
            Ok(live) => live,
            // Nothing is there to replace; the whole directory is new.
            Err(error) if missing(&error) => Vec::new(),
            Err(error) => return Err(error),
        };
        for name in live.iter().filter(|name| !staged.contains(name)) {
            let child = relative.join(name);
            if !(self.withhold)(&child) {
                self.survey_removal(&child)?;
            }
        }
        for name in staged {
            let child = relative.join(&name);
            if (self.withhold)(&child) {
                continue;
            }
            self.charge_entry()?;
            let metadata = self.staged.metadata(&child)?;
            if linked(&metadata) {
                return Err(bound_fs::changed());
            }
            if metadata.is_dir() {
                self.survey(&child)?;
            } else if metadata.is_file() {
                self.charge_bytes(metadata.len())?;
            } else {
                return Err(bound_fs::changed());
            }
        }
        Ok(())
    }

    /// Weighs one live entry the build no longer produces, and everything
    /// under it. Reading and deleting a stale tree is work the run asked for,
    /// so it is charged to the same entry budget as the output it writes.
    fn survey_removal(&mut self, relative: &Path) -> io::Result<()> {
        self.charge_entry()?;
        let metadata = self.live.metadata(relative)?;
        if linked(&metadata) {
            return Err(bound_fs::changed());
        }
        if !metadata.is_dir() {
            return Ok(());
        }
        for name in self.live.entries(relative, self.remaining_entries())? {
            let child = relative.join(&name);
            if !(self.withhold)(&child) {
                self.survey_removal(&child)?;
            }
        }
        Ok(())
    }

    fn remaining_entries(&self) -> usize {
        self.max_entries.saturating_sub(self.budget.entries)
    }

    fn charge_entry(&mut self) -> io::Result<()> {
        self.budget.entries += 1;
        if self.budget.entries > self.max_entries {
            return Err(exceeded());
        }
        Ok(())
    }

    fn charge_bytes(&mut self, bytes: u64) -> io::Result<()> {
        let bytes = usize::try_from(bytes).map_err(|_| exceeded())?;
        self.budget.bytes = self.budget.bytes.checked_add(bytes).ok_or_else(exceeded)?;
        if self.budget.bytes > self.max_bytes {
            return Err(exceeded());
        }
        Ok(())
    }

    /// Makes the live directory at `relative` hold what the staged one holds.
    /// `survey` has already weighed every entry this touches.
    fn apply(&mut self, relative: &Path) -> io::Result<()> {
        let staged: Vec<OsString> = self.staged.entries(relative, self.max_entries)?;
        let live: Vec<OsString> = self.live.entries(relative, self.max_entries)?;
        for name in live.iter().filter(|name| !staged.contains(name)) {
            let child = relative.join(name);
            if !(self.withhold)(&child) {
                self.remove(&child)?;
            }
        }
        for name in staged {
            let child = relative.join(&name);
            if (self.withhold)(&child) {
                continue;
            }
            let metadata = self.staged.metadata(&child)?;
            if linked(&metadata) {
                return Err(bound_fs::changed());
            }
            if metadata.is_dir() {
                match self.live.metadata(&child) {
                    Ok(current) if current.is_dir() && !linked(&current) => {}
                    Ok(_) => {
                        self.remove(&child)?;
                        self.live.mkdir_all(&child)?;
                    }
                    Err(error) if missing(&error) => self.live.mkdir_all(&child)?,
                    Err(error) => return Err(error),
                }
                self.apply(&child)?;
            } else if metadata.is_file() {
                self.write(&child)?;
            } else {
                return Err(bound_fs::changed());
            }
        }
        Ok(())
    }

    fn write(&mut self, relative: &Path) -> io::Result<()> {
        let file = self.staged.read(relative, self.max_bytes)?;
        match self.live.metadata(relative) {
            Ok(current) if current.is_file() && !linked(&current) => {
                let current = self.live.read(relative, LIVE_FILE_LIMIT)?;
                if current.digest != file.digest {
                    self.live.atomic_replace(
                        relative,
                        Some((&current.identity, &current.digest)),
                        &file.bytes,
                    )?;
                }
                Ok(())
            }
            Ok(_) => {
                self.remove(relative)?;
                self.live.create(relative, &file.bytes, false)
            }
            Err(error) if missing(&error) => self.live.create(relative, &file.bytes, false),
            Err(error) => Err(error),
        }
    }

    /// Removes one live entry the build no longer produces, and reports
    /// whether anything under it was kept. A live link is refused rather than
    /// removed, since its target is outside this tree. A withheld name is
    /// neither written nor removed, so a directory holding one — at any depth
    /// — is emptied of everything else and left standing.
    fn remove(&self, relative: &Path) -> io::Result<bool> {
        let metadata = self.live.metadata(relative)?;
        if linked(&metadata) {
            return Err(bound_fs::changed());
        }
        if !metadata.is_dir() {
            let file = self.live.read(relative, LIVE_FILE_LIMIT)?;
            self.live
                .atomic_remove(relative, (&file.identity, &file.digest))?;
            return Ok(false);
        }
        let mut kept = false;
        for name in self.live.entries(relative, self.max_entries)? {
            let child = relative.join(&name);
            if (self.withhold)(&child) {
                kept = true;
                continue;
            }
            kept |= self.remove(&child)?;
        }
        if kept {
            return Ok(true);
        }
        let directory = self.live.directory(relative)?;
        let expected = identity(directory.handle())?;
        drop(directory);
        self.live.atomic_remove_directory(relative, &expected)?;
        Ok(false)
    }
}

fn exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "build output budget exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Trees {
        workspace: tempfile::TempDir,
        snapshot: tempfile::TempDir,
    }

    fn trees() -> Trees {
        Trees {
            workspace: tempfile::tempdir().unwrap(),
            snapshot: tempfile::tempdir().unwrap(),
        }
    }

    fn write(root: &Path, relative: &str, bytes: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn publish(trees: &Trees, entries: usize, withhold: &dyn Fn(&Path) -> bool) -> io::Result<()> {
        let outputs = [PathBuf::from("dist")];
        let nothing = |_: &Path| false;
        publish_outputs(
            trees.workspace.path(),
            trees.snapshot.path(),
            &BuildRun {
                dependencies: &[],
                withhold_dependency: &nothing,
                max_dependency_entries: 100,
                max_dependency_bytes: 1024 * 1024,
                outputs: &outputs,
                max_output_entries: entries,
                max_output_bytes: 1024 * 1024,
            },
            withhold,
        )
    }

    #[test]
    fn a_withheld_file_under_a_dropped_directory_outlives_its_directory() {
        let trees = trees();
        write(trees.workspace.path(), "dist/cache/.env", "TOKEN=kept");
        write(trees.workspace.path(), "dist/cache/stale.js", "old");
        write(trees.workspace.path(), "dist/cache/deep/stale.js", "old");
        write(trees.snapshot.path(), "dist/out.js", "new");
        let withhold = |path: &Path| path.file_name().is_some_and(|name| name == ".env");
        publish(&trees, 100, &withhold).unwrap();
        let dist = trees.workspace.path().join("dist");
        assert_eq!(fs::read_to_string(dist.join("out.js")).unwrap(), "new");
        // The build no longer produces `cache`, but removing it would take the
        // credential file with it, so the directory stays and is emptied.
        assert_eq!(
            fs::read_to_string(dist.join("cache").join(".env")).unwrap(),
            "TOKEN=kept"
        );
        assert!(!dist.join("cache").join("stale.js").exists());
        assert!(!dist.join("cache").join("deep").exists());
    }

    #[test]
    fn a_dropped_directory_holding_nothing_withheld_is_removed() {
        let trees = trees();
        write(trees.workspace.path(), "dist/cache/deep/stale.js", "old");
        write(trees.snapshot.path(), "dist/out.js", "new");
        publish(&trees, 100, &|_: &Path| false).unwrap();
        assert!(!trees.workspace.path().join("dist").join("cache").exists());
    }

    #[test]
    fn an_output_over_the_entry_budget_leaves_the_live_tree_alone() {
        let trees = trees();
        write(trees.workspace.path(), "dist/stale.js", "old");
        for index in 0..8 {
            write(trees.snapshot.path(), &format!("dist/f{index}.js"), "new");
        }
        publish(&trees, 4, &|_: &Path| false).unwrap_err();
        // Nothing was written and nothing was deleted: an output left part old
        // and part new is worse than one left alone.
        let dist = trees.workspace.path().join("dist");
        assert_eq!(fs::read_to_string(dist.join("stale.js")).unwrap(), "old");
        assert!(!dist.join("f0.js").exists());
    }

    #[test]
    fn a_stale_subtree_too_large_to_remove_leaves_the_live_tree_alone() {
        let trees = trees();
        for index in 0..8 {
            write(
                trees.workspace.path(),
                &format!("dist/cache/f{index}.js"),
                "old",
            );
        }
        write(trees.snapshot.path(), "dist/out.js", "new");
        publish(&trees, 4, &|_: &Path| false).unwrap_err();
        let dist = trees.workspace.path().join("dist");
        assert!(dist.join("cache").join("f0.js").exists());
        assert!(!dist.join("out.js").exists());
    }
}
