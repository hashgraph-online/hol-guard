//! Reuse the safe bounded native object/index readers.
use super::*;
use crate::active_pack_security::proofs as shared;
fn failure(error: shared::Failure) -> Failure {
    match error {
        shared::Failure::Need(v) => Failure::Need(v),
        shared::Failure::Archives(v) => Failure::Archives(v),
        shared::Failure::Invalid(s) => Failure::Invalid(s.into()),
    }
}
pub(super) fn object(directory: &Path, reference: &Value) -> Result<Value> {
    if reference.get("location").is_some() {
        located(reference)?;
    }
    shared::object(directory, reference).map_err(failure)
}
pub(super) fn located(reference: &Value) -> Result<()> {
    let map = reference.as_object().ok_or_else(invalid)?;
    if map.len() != 5
        || !["sha256", "length", "expanded_length", "kind", "location"]
            .iter()
            .all(|f| map.contains_key(*f))
    {
        return Err(invalid());
    }
    let sha = reference["sha256"].as_str().ok_or_else(invalid)?;
    location(&reference["location"], sha, "object")
}
pub(super) fn location(value: &Value, sha: &str, kind: &str) -> Result<()> {
    use regex::Regex;
    use std::sync::OnceLock;
    static TAG: OnceLock<Regex> = OnceLock::new();
    static CONTAINER: OnceLock<Regex> = OnceLock::new();
    let tag = TAG.get_or_init(|| {
        Regex::new(r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$").unwrap()
    });
    let container =
        CONTAINER.get_or_init(|| Regex::new(r"^(objects|packs)-[0-9]{6}\.zip$").unwrap());
    let map = value.as_object().ok_or_else(invalid)?;
    let expected = format!(
        "{kind}-{sha}.{}",
        if kind == "object" { "json" } else { "zip" }
    );
    if !tag.is_match(value["tag"].as_str().ok_or_else(invalid)?) {
        return Err("delivery asset location invalid".into());
    }
    if map.len() == 2 && map.contains_key("tag") && value["asset"] == expected {
        return Ok(());
    }
    let asset = value["asset"].as_str().ok_or_else(invalid)?;
    if map.len() != 3
        || value["member"] != expected
        || !container.is_match(asset)
        || !asset.starts_with(if kind == "object" {
            "objects-"
        } else {
            "packs-"
        })
    {
        return Err("delivery container location invalid".into());
    }
    Ok(())
}
pub(super) fn lookup(
    directory: &Path,
    reference: &Value,
    count: u64,
    id: &str,
) -> Result<Option<Value>> {
    shared::lookup(directory, reference, count, id).map_err(failure)
}
pub(super) fn policy_object(
    directory: &Path,
    reference: &Value,
    archives: &Value,
) -> Result<Value> {
    use guard_command::native_command_program::source::{
        read_pack_blob as read_blob, PackObjectRef as ObjectRef,
    };
    let reference: ObjectRef = serde_json::from_value(reference.clone()).map_err(|_| invalid())?;
    let mut missing = false;
    let bytes = read_blob(&reference, &mut |sha| {
        let path = directory.join("objects").join(format!("{sha}.json"));
        match guard_secure_fs::read_bounded(&path, 65536) {
            Ok(value) => Ok(value.bytes),
            Err(_) => {
                missing |= !path.exists() && !path.is_symlink();
                Err("pack policy object unavailable")
            }
        }
    });
    let bytes = match bytes {
        Ok(v) => v,
        Err(_) if missing => return Err(Failure::Archives(archives.clone())),
        Err(e) => return Err(e.into()),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if bytes != encoded(&value)? {
        return Err(invalid());
    }
    Ok(value)
}
