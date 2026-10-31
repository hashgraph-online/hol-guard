//! The harness coverage registry file: read only when it is a private
//! regular file of the trusted owner that held still while read and matches
//! the schema, and replaced whole with a restricted file.

use std::collections::BTreeSet;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path};

use guard_command::inventory_fingerprints::python_compact_json;
use serde_json::{Map, Value};

use super::artifacts::{open_without_following, stamp};
use super::{
    os_error, permission_error, value_error, CoverageError, CAPACITY_EXCEEDED,
    MAX_ARTIFACTS_PER_HARNESS, MAX_HARNESSES_PER_USER, MAX_NAME_CHARS, MAX_PATH_CHARS,
    MAX_REGISTRY_BYTES, MAX_USERS, REGISTRY_ACL_INVALID, REGISTRY_INVALID, REGISTRY_NAME,
    SCHEMA_VERSION,
};

/// The registry, or `None` when none was written. It is refused unless it is
/// a private regular file of the trusted owner that held still while read.
pub(super) fn read_registry(
    state_root: &Path,
    owner_uid: u32,
) -> Result<Option<Map<String, Value>>, CoverageError> {
    let target = state_root.join(REGISTRY_NAME);
    // Windows cannot open without following a reparse point, so a linked
    // registry is refused here and the opened file must be the one checked.
    let linked = match fs::symlink_metadata(&target) {
        Ok(linked) => linked,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(os_error(error)),
    };
    if linked.file_type().is_symlink() {
        return Err(os_error(io::Error::from(io::ErrorKind::InvalidInput)));
    }
    let mut file = match open_without_following(&target) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(os_error(error)),
    };
    let metadata = file.metadata().map_err(os_error)?;
    if !metadata.is_file()
        || metadata.len() > MAX_REGISTRY_BYTES
        || stamp(&linked) != stamp(&metadata)
    {
        return Err(value_error(REGISTRY_INVALID));
    }
    if !registry_acl_is_private(&metadata, owner_uid) {
        return Err(permission_error(REGISTRY_ACL_INVALID));
    }
    let mut payload = Vec::new();
    file.by_ref()
        .take(metadata.len())
        .read_to_end(&mut payload)
        .map_err(os_error)?;
    let after = file.metadata().map_err(os_error)?;
    if payload.len() as u64 != metadata.len() || stamp(&metadata) != stamp(&after) {
        return Err(value_error(REGISTRY_INVALID));
    }
    let Ok(Value::Object(registry)) = serde_json::from_slice::<Value>(&payload) else {
        return Err(value_error(REGISTRY_INVALID));
    };
    if registry_is_valid(&registry) {
        Ok(Some(registry))
    } else {
        Err(value_error(REGISTRY_INVALID))
    }
}

#[cfg(unix)]
fn registry_acl_is_private(metadata: &Metadata, owner_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.mode() & 0o077 == 0 && metadata.uid() == owner_uid
}

#[cfg(not(unix))]
fn registry_acl_is_private(_metadata: &Metadata, _owner_uid: u32) -> bool {
    true
}

fn registry_is_valid(registry: &Map<String, Value>) -> bool {
    let Some(users) = registry.get("users").and_then(Value::as_array) else {
        return false;
    };
    if registry.len() != 2
        || registry.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION)
        || users.len() > MAX_USERS
    {
        return false;
    }
    let mut homes = BTreeSet::new();
    users.iter().all(|user| {
        let Some(user) = user.as_object() else {
            return false;
        };
        let home = user.get("home").and_then(Value::as_str);
        let harnesses = user.get("harnesses").and_then(Value::as_array);
        let (Some(home), Some(harnesses)) = (home, harnesses) else {
            return false;
        };
        user.len() == 2
            && Path::new(home).is_absolute()
            && (1..=MAX_PATH_CHARS).contains(&home.chars().count())
            && homes.insert(home)
            && harnesses_are_valid(harnesses)
    })
}

fn harnesses_are_valid(harnesses: &[Value]) -> bool {
    if harnesses.len() > MAX_HARNESSES_PER_USER {
        return false;
    }
    let mut names = BTreeSet::new();
    harnesses.iter().all(|harness| {
        let Some(harness) = harness.as_object() else {
            return false;
        };
        let name = harness.get("name").and_then(Value::as_str);
        let artifacts = harness.get("artifacts").and_then(Value::as_array);
        let (Some(name), Some(artifacts)) = (name, artifacts) else {
            return false;
        };
        harness.len() == 2
            && (1..=MAX_NAME_CHARS).contains(&name.chars().count())
            && names.insert(name)
            && artifacts.len() <= MAX_ARTIFACTS_PER_HARNESS
            && artifacts
                .iter()
                .all(|artifact| artifact.as_object().and_then(artifact_fields).is_some())
    })
}

/// An artifact record's relative path, kind and recorded digest, or `None`
/// when the record is malformed. A `null` digest is no digest.
pub(super) fn artifact_fields(artifact: &Map<String, Value>) -> Option<(&str, &str, Option<&str>)> {
    let path = artifact.get("path")?.as_str()?;
    let kind = artifact.get("kind")?.as_str()?;
    let recorded = artifact.get("sha256");
    if artifact.len() != 2 + usize::from(recorded.is_some()) {
        return None;
    }
    let digest = match recorded {
        None | Some(Value::Null) => None,
        Some(Value::String(digest)) => Some(digest.as_str()),
        Some(_) => return None,
    };
    let relative = Path::new(path);
    if !(1..=MAX_PATH_CHARS).contains(&path.chars().count())
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return None;
    }
    let digest_is_valid = match kind {
        "file" | "directory" => digest.is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        }),
        "missing" | "mutable-file" => digest.is_none(),
        _ => false,
    };
    digest_is_valid.then_some((path, kind, digest))
}

pub(super) fn write_registry(
    state_root: &Path,
    registry: &Map<String, Value>,
) -> Result<(), CoverageError> {
    let mut payload = python_compact_json(&Value::Object(registry.clone())).into_bytes();
    payload.push(b'\n');
    if payload.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(value_error(CAPACITY_EXCEEDED));
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        builder.mode(0o700);
    }
    builder.create(state_root).map_err(os_error)?;
    if !fs::symlink_metadata(state_root).map_err(os_error)?.is_dir() {
        return Err(permission_error(REGISTRY_ACL_INVALID));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(state_root, fs::Permissions::from_mode(0o700)).map_err(os_error)?;
    }
    crate::managed_policy_file_trust::replace_restricted_file(
        &state_root.join(REGISTRY_NAME),
        &payload,
    )
    .map_err(os_error)?;
    sync_directory(state_root).map_err(os_error)
}

/// Make the registry's new name durable. A filesystem that cannot sync a
/// directory leaves the write as durable as it can be, not failed.
#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    match fs::File::open(directory).and_then(|handle| handle.sync_all()) {
        Err(error)
            if !matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
            ) =>
        {
            Err(error)
        }
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> io::Result<()> {
    Ok(())
}
