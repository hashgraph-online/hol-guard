//! Atomic discovery-only writes relative to an operation-local pinned directory.
use super::{io, CacheReader, Result};
use crate::native_command_program::source::PackObjectRef;
use serde_json::Value;

impl CacheReader {
    pub(crate) fn put_json(&self, value: &Value) -> Result<PackObjectRef> {
        if !self
            .path
            .ends_with("native-runtime/catalog-discovery/objects")
        {
            return Err("catalog_prepare_write_scope_invalid");
        }
        io::put_json_with(value, |bytes, kind, expanded| {
            self.put(bytes, kind, expanded)
        })
    }

    fn put(&self, bytes: &[u8], kind: &str, expanded: usize) -> Result<PackObjectRef> {
        if bytes.is_empty()
            || bytes.len() > io::OBJECT_BYTES
            || expanded == 0
            || expanded > io::BLOB_BYTES
        {
            return Err("catalog_prepare_object_budget");
        }
        #[cfg(not(unix))]
        {
            io::put(&self.path, bytes, kind, expanded)
        }
        #[cfg(unix)]
        {
            use nix::{
                errno::Errno,
                fcntl::{openat, renameat, AtFlags, OFlag},
                sys::stat::{fstatat, Mode},
                unistd::{linkat, unlinkat, UnlinkatFlags},
            };
            use std::{fs, io::Write};
            // Parent privacy/identity and lexical ancestry were checked when
            // this descriptor was opened, and finish rechecks before the step
            // can return a handle. Relative IO cannot follow a replaced parent.
            super::private_metadata(
                &self
                    .directory
                    .metadata()
                    .map_err(|_| "catalog_prepare_write_failed")?,
                true,
            )?;
            let digest = io::hash(bytes);
            let destination = format!("{digest}.json");
            let replace = match fstatat(
                &self.directory,
                destination.as_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Ok(_) => match self.read(&digest) {
                    Ok(saved) if saved == bytes => {
                        return Ok(reference(digest, bytes.len(), kind, expanded))
                    }
                    Err("catalog_prepare_object_corrupt") => true,
                    Err(error) => return Err(error),
                    _ => return Err("catalog_prepare_object_corrupt"),
                },
                Err(Errno::ENOENT) => false,
                Err(_) => return Err("catalog_prepare_write_failed"),
            };
            let temporary = format!(".{}", io::nonce()?);
            let publish = (|| {
                let mut file = fs::File::from(
                    openat(
                        &self.directory,
                        temporary.as_str(),
                        OFlag::O_WRONLY
                            | OFlag::O_CREAT
                            | OFlag::O_EXCL
                            | OFlag::O_NOFOLLOW
                            | OFlag::O_CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                    )
                    .map_err(|_| "catalog_prepare_write_failed")?,
                );
                file.write_all(bytes)
                    .map_err(|_| "catalog_prepare_write_failed")?;
                drop(file);
                if replace {
                    return renameat(
                        &self.directory,
                        temporary.as_str(),
                        &self.directory,
                        destination.as_str(),
                    )
                    .map_err(|_| "catalog_prepare_publish_failed");
                }
                match linkat(
                    &self.directory,
                    temporary.as_str(),
                    &self.directory,
                    destination.as_str(),
                    AtFlags::empty(),
                ) {
                    Ok(()) => Ok(()),
                    Err(Errno::EEXIST) if self.read(&digest)? == bytes => Ok(()),
                    _ => Err("catalog_prepare_publish_failed"),
                }
            })();
            let _ = unlinkat(
                &self.directory,
                temporary.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
            publish?;
            Ok(reference(digest, bytes.len(), kind, expanded))
        }
    }
}

#[cfg(unix)]
fn reference(sha256: String, length: usize, kind: &str, expanded_length: usize) -> PackObjectRef {
    PackObjectRef {
        sha256,
        length,
        expanded_length,
        kind: kind.into(),
    }
}
