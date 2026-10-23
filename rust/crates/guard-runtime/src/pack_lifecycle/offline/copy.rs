//! Native, digest-bound IO: never write bytes re-read unverified by an adapter.
use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
};

fn directory(path: &Path) -> Result<()> {
    if guard_secure_fs::contains_symlink_component(path) {
        return Err(invalid());
    }
    if !path.exists() {
        fs::create_dir(path).map_err(|_| invalid())?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| invalid())?;
        }
    }
    if !fs::symlink_metadata(path).map_err(|_| invalid())?.is_dir()
        || guard_secure_fs::contains_symlink_component(path)
    {
        return Err(invalid());
    }
    Ok(())
}
fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    directory(parent)?;
    if path.exists() {
        if read(path, bytes.len())? != bytes {
            return Err("offline_copy_existing_object_invalid".into());
        }
        return Ok(());
    }
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).map_err(|_| invalid())?;
    let temporary = parent.join(format!(".transfer-{}", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut owned = false;
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|_| invalid())?;
        owned = true;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| invalid())?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if read(path, bytes.len())? != bytes {
                    return Err("offline_copy_existing_object_invalid".into());
                }
            }
            Err(_) => return Err(invalid()),
        }
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| invalid())?;
        Ok(())
    })();
    if owned {
        fs::remove_file(temporary).map_err(|_| invalid())?;
    }
    result
}
pub(super) fn object(
    source: &Path,
    destination: &Path,
    identity: &str,
    maximum: usize,
) -> Result<()> {
    if !hex(identity, 64) {
        return Err(invalid());
    }
    let bytes = read(source, maximum)?;
    // This check is immediately before publication. A substituted private file
    // can never be written to a partial export, even if earlier admission passed.
    if hash(&bytes) != identity {
        return Err("offline_copy_source_integrity_invalid".into());
    }
    publish(destination, &bytes)
}
pub(super) fn batch(
    input: &Value,
    source: &Path,
    root: &[u8],
    objects: &BTreeSet<String>,
    archives: &BTreeSet<String>,
) -> Result<Value> {
    let destination = Path::new(input["destination"].as_str().ok_or_else(invalid)?);
    directory(destination)?;
    #[cfg(unix)]
    if let Some(parent) = destination.parent() {
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| invalid())?;
    }
    let total = objects
        .len()
        .checked_add(archives.len())
        .ok_or_else(invalid)?;
    for (family, suffix, id, maximum) in objects
        .iter()
        .map(|id| ("objects", "json", id, 65536))
        .chain(
            archives
                .iter()
                .map(|id| ("archives", "zip", id, 32 * 1024 * 1024)),
        )
    {
        directory(&destination.join(family))?;
        object(
            &source.join(family).join(format!("{id}.{suffix}")),
            &destination.join(family).join(format!("{id}.{suffix}")),
            id,
            maximum,
        )?;
    }
    if input["operation"] == "export-copy" {
        publish(&destination.join("root.json"), root)?;
    }
    Ok(json!({"complete":true,"files":total,"root":hash(root)}))
}
