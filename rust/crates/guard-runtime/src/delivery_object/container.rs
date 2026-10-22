//! Bounded transfer containers.
//!
//! A container is a stored ZIP archive that batches many small delivery
//! objects into one release asset. Its members are named for their digests, so
//! a selected member is verified on its own: the container's layout is checked
//! as a whole, but only the member that is read has its bytes hashed.
use super::{
    files,
    location::{self, Family, PACKS_BOUND},
    request,
    stored_zip::{self as zip, Entry},
    Outcome,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};

const MAX_MEMBERS: usize = 256;
const OBJECT_BYTES: usize = 65536;
const UTF8_NAMES: usize = 0x800;
/// Structure the standard reader would refuse: a malformed entry or header.
const STRUCTURE: &str = "delivery container archive invalid";

struct Container<'a> {
    start: usize,
    rows: Vec<Entry<'a>>,
}

fn inspect<'a>(bytes: &'a [u8], asset: &str) -> Result<Container<'a>, String> {
    let family = location::family(asset).ok_or("delivery container name invalid")?;
    let bound = family.bound();
    if bytes.len() < 22
        || bytes.len() > bound
        || !bytes[bytes.len() - 22..].starts_with(b"PK\x05\x06")
    {
        return Err("delivery container size or terminator invalid".into());
    }
    let end = zip::end(bytes)
        .filter(|end| end.count <= MAX_MEMBERS && end.central <= end.count * 256)
        .ok_or("delivery container central directory exceeds bounds")?;
    let (prefix, suffix, member_limit) = match family {
        Family::Objects => ("object-", ".json", OBJECT_BYTES),
        Family::Packs => ("pack-", ".zip", PACKS_BOUND),
    };
    let mut at = end.start;
    let mut names = BTreeSet::new();
    let mut rows = Vec::new();
    let mut total = 0usize;
    while at < end.tail {
        let entry = zip::entry(bytes, at)
            .filter(|entry| entry.next <= end.tail)
            .ok_or(STRUCTURE)?;
        at = entry.next;
        let digest = entry
            .name
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(suffix))
            .unwrap_or("");
        total = total.saturating_add(entry.size);
        if !names.insert(entry.name)
            || !location::lower_hex(digest, 64)
            || entry.method != 0
            || entry.packed != entry.size
            || !(1..=member_limit).contains(&entry.size)
            || (entry.flags & !UTF8_NAMES) != 0
            || entry.extra != 0
            || entry.comment != 0
            || !entry.regular()
            || total > bound
        {
            return Err("delivery container member invalid".into());
        }
        rows.push(entry);
    }
    if rows.len() != end.count {
        return Err("delivery container member count differs".into());
    }
    Ok(Container {
        start: end.start,
        rows,
    })
}

/// Read one member of the container file at `path`, which the caller has
/// already resolved. The member must be named, sized and hashed as asked.
pub(super) fn member(input: &Value) -> Outcome {
    let text = |key: &str| input[key].as_str().ok_or_else(request);
    let (path, asset, name) = (text("path")?, text("asset")?, text("name")?);
    let length = input["length"].as_u64().ok_or_else(request)?;
    members(Path::new(path), asset, [(name, length)])?
        .pop()
        .ok_or_else(request)
}

/// Verify members against one bounded, immutable read of their container.
/// The bytes and inspected directory are dropped before the caller reads the
/// next container; only the selected member replies leave this function.
pub(super) fn members<'a>(
    path: &Path,
    asset: &str,
    members: impl IntoIterator<Item = (&'a str, u64)>,
) -> Result<Vec<Value>, String> {
    let family = location::family(asset).ok_or("delivery container name invalid")?;
    #[cfg(test)]
    READS.with(|reads| reads.set(reads.get() + 1));
    let bytes = files::read(path, family.bound()).map_err(|_| "delivery container unreadable")?;
    let container = inspect(&bytes, asset)?;
    members
        .into_iter()
        .map(|(name, length)| selected(&bytes, &container, name, length))
        .collect()
}

fn selected(bytes: &[u8], container: &Container<'_>, name: &str, length: u64) -> Outcome {
    let entry = container
        .rows
        .iter()
        .find(|row| row.name == name)
        .ok_or("delivery container member missing")?;
    if u64::try_from(entry.size).ok() != Some(length) {
        return Err("delivery container member length differs".into());
    }
    let range = zip::data(bytes, entry, container.start).ok_or(STRUCTURE)?;
    let digest = name
        .split_once('-')
        .and_then(|(_, rest)| rest.split_once('.'))
        .map_or("", |(digest, _)| digest);
    let data = &bytes[range];
    if hex::encode(Sha256::digest(data)) != digest {
        return Err("delivery container member integrity invalid".into());
    }
    Ok(json!({"data": STANDARD.encode(data)}))
}

#[cfg(test)]
thread_local! {
    static READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn read_count() -> usize {
    READS.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod tests;
