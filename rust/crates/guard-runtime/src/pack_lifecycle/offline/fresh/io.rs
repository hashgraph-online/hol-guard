//! Descriptor-relative publication for the exclusively created export only.
use super::*;
use nix::{
    fcntl::{openat, AtFlags, OFlag},
    sys::stat::{fstat, fstatat, mkdirat, FileStat, Mode},
    unistd::{linkat, unlinkat, UnlinkatFlags},
};
use std::{ffi::OsStr, fs::File, io::Write, path::Component};

pub(super) struct Directory {
    pub(super) file: File,
}

fn flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

impl Directory {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let start = if path.is_absolute() { "/" } else { "." };
        let mut file =
            File::from(nix::fcntl::open(start, flags(), Mode::empty()).map_err(|_| invalid())?);
        // Every caller-supplied component is opened without following links.
        // Keep the resulting descriptor instead of reopening paths at barriers.
        for part in path.components() {
            let name = match part {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir => return Err(invalid()),
                _ => return Err(invalid()),
            };
            file = File::from(openat(&file, name, flags(), Mode::empty()).map_err(|_| invalid())?);
        }
        Ok(Self { file })
    }

    pub(super) fn create(&self, name: &OsStr, mode: libc::mode_t) -> Result<Self> {
        mkdirat(&self.file, name, Mode::from_bits_truncate(mode)).map_err(|_| invalid())?;
        let file =
            File::from(openat(&self.file, name, flags(), Mode::empty()).map_err(|_| invalid())?);
        let child = Self { file };
        self.check(name, &child)?;
        Ok(child)
    }

    pub(super) fn check(&self, name: &OsStr, child: &Self) -> Result<()> {
        let linked =
            fstatat(&self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| invalid())?;
        let held = fstat(&child.file).map_err(|_| invalid())?;
        if linked.st_dev != held.st_dev
            || linked.st_ino != held.st_ino
            || linked.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn sync(
        &self,
        event: &str,
        name: &str,
        checkpoint: &mut impl FnMut(&str, &str) -> Result<()>,
    ) -> Result<()> {
        checkpoint("before_directory_sync", name)?;
        self.file.sync_all().map_err(|_| invalid())?;
        checkpoint(event, name)
    }

    pub(super) fn remove_owned(&self, name: &str, file: &File) -> Result<()> {
        let entry =
            fstatat(&self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| invalid())?;
        let held = fstat(file).map_err(|_| invalid())?;
        if entry.st_dev != held.st_dev || entry.st_ino != held.st_ino {
            return Err(invalid());
        }
        unlinkat(&self.file, name, UnlinkatFlags::NoRemoveDir).map_err(|_| invalid())
    }

    fn check_file(&self, name: &str, held: &FileStat, links: libc::nlink_t) -> Result<()> {
        let entry =
            fstatat(&self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| invalid())?;
        if held.st_mode & libc::S_IFMT != libc::S_IFREG
            || entry.st_dev != held.st_dev
            || entry.st_ino != held.st_ino
            || entry.st_mode != held.st_mode
            || entry.st_size != held.st_size
            || entry.st_nlink != links
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn publish(
        &self,
        name: &str,
        bytes: &[u8],
        checkpoint: &mut impl FnMut(&str, &str) -> Result<()>,
    ) -> Result<File> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| invalid())?;
        let temporary = format!(".transfer-{}", hex::encode(random));
        let descriptor = openat(
            &self.file,
            temporary.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(|_| invalid())?;
        let mut file = File::from(descriptor);
        let mut linked = false;
        let mut identity = None;
        let result = (|| {
            file.write_all(bytes).map_err(|_| invalid())?;
            checkpoint("before_file_sync", name)?;
            file.sync_all().map_err(|_| invalid())?;
            let held = fstat(&file).map_err(|_| invalid())?;
            checkpoint("file_synced", name)?;
            self.check_file(&temporary, &held, 1)?;
            // Never accept a competing object in our exclusively owned export.
            linkat(
                &self.file,
                temporary.as_str(),
                &self.file,
                name,
                AtFlags::empty(),
            )
            .map_err(|_| invalid())?;
            linked = true;
            self.check_file(name, &held, 2)?;
            identity = Some(held);
            checkpoint("published", name)
        })();
        let cleanup = self.remove_owned(&temporary, &file);
        let result = result.and(cleanup).and_then(|()| {
            checkpoint("temporary_removed", name)?;
            self.check_file(name, identity.as_ref().ok_or_else(invalid)?, 1)
        });
        if result.is_err() && linked {
            self.remove_owned(name, &file)?;
        }
        result.map(|()| file)
    }
}
