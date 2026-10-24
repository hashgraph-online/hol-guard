//! Asset names and locations of the catalog delivery channel.
//!
//! A located object is either a whole release asset or one member of a bounded
//! transfer container. The name carries the content digest, so every consumer
//! can check the bytes it receives against the name alone.
use super::{request, Outcome};
use serde_json::{json, Value};

const OBJECTS_BOUND: usize = 8 * 1024 * 1024;
pub(super) const PACKS_BOUND: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    Objects,
    Packs,
}

impl Family {
    pub(super) fn bound(self) -> usize {
        match self {
            Family::Objects => OBJECTS_BOUND,
            Family::Packs => PACKS_BOUND,
        }
    }
}

pub(super) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn digits(value: &str, least: usize, most: usize) -> bool {
    (least..=most).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
}

/// `objects-NNNNNN.zip` or `packs-NNNNNN.zip`.
pub(super) fn family(name: &str) -> Option<Family> {
    let (found, rest) = match (name.strip_prefix("objects-"), name.strip_prefix("packs-")) {
        (Some(rest), _) => (Family::Objects, rest),
        (_, Some(rest)) => (Family::Packs, rest),
        _ => return None,
    };
    digits(rest.strip_suffix(".zip")?, 6, 6).then_some(found)
}

/// `object-<digest>.json` or `pack-<digest>.zip`: the kind and the digest.
fn data_name(name: &str) -> Option<(&'static str, &str)> {
    let (kind, suffix, rest) = match (name.strip_prefix("object-"), name.strip_prefix("pack-")) {
        (Some(rest), _) => ("object", ".json", rest),
        (_, Some(rest)) => ("pack", ".zip", rest),
        _ => return None,
    };
    let (digest, tail) = rest.split_at_checked(64)?;
    (lower_hex(digest, 64) && tail == suffix).then_some((kind, digest))
}

/// The location of the object `kind` with `digest`: a whole asset named for it,
/// or a member of a container of the matching family. Distribution-root
/// validation applies the same check, so both accept exactly the same
/// locations.
pub(super) fn check(value: &Value, digest: &str, kind: &str) -> Result<(), String> {
    crate::pack_lifecycle::location::check(value, digest, kind)
        .map_err(|rejection| rejection.message().to_owned())
}

/// Resolve the asset a fetch names. `release` is the public release transport;
/// `installed` is the packaged bundle, which also binds the tag to its source
/// and names the directory the tag's assets sit in.
pub(super) fn asset(input: &Value) -> Outcome {
    let installed = match input["profile"].as_str() {
        Some("release") => false,
        Some("installed") => true,
        _ => return Err(request()),
    };
    let (shape, naming) = if installed {
        (
            "installed bundle location invalid",
            "installed bundle asset invalid",
        )
    } else {
        (
            "release object location invalid",
            "release object location invalid",
        )
    };
    let target = &input["target"];
    let map = target.as_object().ok_or(shape)?;
    let name = match map.get("member").or_else(|| map.get("asset")) {
        None => "",
        Some(Value::String(name)) => name,
        Some(_) => return Err(naming.into()),
    };
    let (kind, digest) = data_name(name).ok_or(naming)?;
    check(target, digest, kind)?;
    let tag = map["tag"].as_str().unwrap_or_default();
    let mut directory = Value::Null;
    if installed {
        let source = input["source"].as_str().filter(|s| lower_hex(s, 40));
        let bound = format!("extension-data-{}-0.0-", source.ok_or_else(request)?);
        let batch = tag
            .strip_prefix(&bound)
            .ok_or("installed bundle asset source differs")?;
        if !digits(batch, 6, 6) {
            return Err(shape.into());
        }
        // Only the batch varies between installed tags, so the bundle names
        // each tag's directory for it alone. The full tag would put wheel
        // members past the 260-character path limit of a stock Windows install.
        directory = json!(batch);
    }
    let asset = map["asset"].as_str().unwrap_or_default();
    let bound = map
        .contains_key("member")
        .then(|| family(asset).map(Family::bound));
    Ok(json!({
        "name": name,
        "digest": digest,
        "kind": kind,
        "tag": tag,
        "directory": directory,
        "asset": asset,
        "bound": bound.flatten(),
    }))
}

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;
