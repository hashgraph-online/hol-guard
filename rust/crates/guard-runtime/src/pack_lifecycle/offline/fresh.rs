//! Fresh exports have no prior Root to preserve. Data directory entries may be
//! synchronized together, but every file is synchronized before publication and
//! Root is published only after the complete data and directory hierarchy.
use super::*;

#[cfg(unix)]
#[path = "fresh/io.rs"]
mod io;
#[cfg(all(test, not(unix)))]
#[path = "fresh/non_unix_tests.rs"]
mod non_unix_tests;
#[cfg(all(test, unix))]
#[path = "fresh/tests.rs"]
mod tests;

pub(super) fn batch(
    input: &Value,
    source: &Path,
    root: &[u8],
    objects: &BTreeSet<String>,
    archives: &BTreeSet<String>,
) -> Result<Value> {
    let destination = Path::new(input["destination"].as_str().ok_or_else(invalid)?);
    #[cfg(unix)]
    {
        run(destination, source, root, objects, archives, &mut |_, _| {
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        if guard_secure_fs::contains_symlink_component(destination) {
            return Err(invalid());
        }
        // Retain the existing platform IO behavior when directory sync is not
        // available. Native still owns exclusive creation, never an empty check.
        std::fs::create_dir(destination).map_err(|_| invalid())?;
        let mut request = input.clone();
        request["operation"] = json!("export-copy");
        copy::batch(&request, source, root, objects, archives)
    }
}

#[cfg(unix)]
fn run(
    destination: &Path,
    source: &Path,
    root: &[u8],
    objects: &BTreeSet<String>,
    archives: &BTreeSet<String>,
    checkpoint: &mut impl FnMut(&str, &str) -> Result<()>,
) -> Result<Value> {
    let total = objects
        .len()
        .checked_add(archives.len())
        .ok_or_else(invalid)?;
    let name = destination.file_name().ok_or_else(invalid)?;
    let parent = io::Directory::open(destination.parent().unwrap_or(Path::new(".")))?;
    // mkdirat is exclusive: no existing directory or old published Root can
    // authorize deferred durability. All subsequent writes use these handles.
    let target = parent.create(name, 0o700)?;
    let mut directories = Vec::new();
    for (family, suffix, ids, maximum) in [
        ("objects", "json", objects, 65536),
        ("archives", "zip", archives, 32 * 1024 * 1024),
    ] {
        let directory = target.create(family.as_ref(), 0o777)?;
        for id in ids {
            if !hex(id, 64) {
                return Err(invalid());
            }
            let file = format!("{id}.{suffix}");
            let bytes = read(&source.join(family).join(&file), maximum)?;
            // A replaced private file must never be copied into a partial
            // export, even when it passed earlier graph admission.
            if hash(&bytes) != *id {
                return Err("offline_copy_source_integrity_invalid".into());
            }
            directory.publish(&file, &bytes, checkpoint)?;
        }
        directories.push((family, directory));
    }
    // Includes final links AND removal of every owned temporary. The held
    // descriptors are exactly the directories receiving those operations.
    for (family, directory) in &directories {
        target.check(family.as_ref(), directory)?;
        directory.sync("data_directory_synced", family, checkpoint)?;
    }
    target.sync("hierarchy_synced", "export", checkpoint)?;
    parent.sync("hierarchy_synced", "parent", checkpoint)?;
    for (family, directory) in &directories {
        target.check(family.as_ref(), directory)?;
    }
    parent.check(name, &target)?;
    let published_root = target.publish("root.json", root, checkpoint)?;
    let result = target
        .sync("root_directory_synced", "export", checkpoint)
        .and_then(|()| {
            for (family, directory) in &directories {
                target.check(family.as_ref(), directory)?;
            }
            parent.check(name, &target)
        });
    if result.is_err() {
        // A failed final barrier cannot report completion. Remove our own Root
        // on ordinary IO errors; process interruption may leave partial data.
        target.remove_owned("root.json", &published_root)?;
        target.file.sync_all().map_err(|_| invalid())?;
    }
    result?;
    Ok(json!({"complete":true,"files":total,"root":hash(root)}))
}
