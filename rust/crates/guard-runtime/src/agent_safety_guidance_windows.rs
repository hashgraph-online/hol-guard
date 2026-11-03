//! Support files off Unix, where there are no directory descriptors: every
//! operation names the file by path, after checking that the support
//! directory path still names the directory that was opened and is not a
//! link or junction. Files open without following a reparse point.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use guard_runtime_windows_process::{directory_file_id, handle_file_id, FileId};

use super::{
    changed, directory_name, failed, non_regular, prepare_directory, read_opened, temporary_name,
    BeforeCommit, ExistingFile, FileState, DEFAULT_MODE,
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Volume serial and file ID.
pub(super) type Identity = FileId;

pub(super) fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(super) struct SupportDirectory {
    path: PathBuf,
    identity: FileId,
}

impl SupportDirectory {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        prepare_directory(path)?;
        let identity = directory_file_id(path).map_err(|_| super::non_directory(path))?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
        })
    }

    pub(super) fn read(&self, name: &str) -> Result<Option<ExistingFile>, String> {
        self.assert_directory()?;
        let path = self.path.join(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed(name, &error)),
        };
        if is_reparse(&metadata) || !metadata.is_file() {
            return Err(non_regular(name));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|error| failed(name, &error))?;
        let metadata = file.metadata().map_err(|error| failed(name, &error))?;
        if is_reparse(&metadata) {
            return Err(non_regular(name));
        }
        let identity = handle_file_id(&file).map_err(|error| failed(name, &error))?;
        let mode = if metadata.permissions().readonly() {
            0o444
        } else {
            0o666
        };
        read_opened(file, &metadata, name, identity, mode).map(Some)
    }

    /// Replace `name` with `text` through a new temporary file, keeping its
    /// read-only attribute, unless it changed since `existing` was read.
    pub(super) fn write(
        &self,
        name: &str,
        text: &str,
        existing: Option<&ExistingFile>,
        before_commit: BeforeCommit<'_>,
    ) -> Result<(), String> {
        self.assert_directory()?;
        let temporary = self.path.join(temporary_name(name)?);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| failed(name, &error))?;
        let mode = existing.map_or(DEFAULT_MODE, |file| file.mode);
        let committed = fill(file, text, mode)
            .map_err(|error| failed(name, &error))
            .and_then(|()| {
                before_commit(name);
                self.assert_unchanged(name, existing.map(|file| &file.state))?;
                self.assert_directory()?;
                std::fs::rename(&temporary, self.path.join(name))
                    .map_err(|error| failed(name, &error))
            });
        let _ = std::fs::remove_file(&temporary);
        committed
    }

    pub(super) fn unlink(&self, name: &str, expected: &FileState) -> Result<(), String> {
        self.assert_unchanged(name, Some(expected))?;
        self.assert_directory()?;
        std::fs::remove_file(self.path.join(name)).map_err(|error| failed(name, &error))
    }

    fn assert_unchanged(&self, name: &str, expected: Option<&FileState>) -> Result<(), String> {
        let current = self.read(name)?;
        if current.as_ref().map(|file| &file.state) != expected {
            return Err(changed(name));
        }
        Ok(())
    }

    fn assert_directory(&self) -> Result<(), String> {
        let unchanged = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.is_dir() && !is_reparse(&metadata))
            && directory_file_id(&self.path).is_ok_and(|identity| identity == self.identity);
        if unchanged {
            return Ok(());
        }
        Err(format!(
            "Guard support directory changed during update: {}",
            directory_name(&self.path)
        ))
    }
}

fn fill(mut file: File, text: &str, mode: u32) -> std::io::Result<()> {
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    file.set_permissions(permissions)
}
