//! Bounded mountinfo projection retaining the host's locked atime flags.
use super::BoundaryResult as Result;
use std::collections::BTreeMap;
use std::path::{Component, PathBuf};

#[cfg(target_os = "linux")]
pub(super) const BIND: u64 = 4096;
#[cfg(target_os = "linux")]
pub(super) const REMOUNT: u64 = 32;
pub(super) const READONLY: u64 = 1;
pub(super) const NOSUID: u64 = 2;
pub(super) const NODEV: u64 = 4;
pub(super) const NOEXEC: u64 = 8;

pub(super) fn path(text: &str) -> Result<PathBuf> {
    let path = PathBuf::from(text);
    if text.contains('\0')
        || !path.is_absolute()
        || path.components().any(|part| part == Component::ParentDir)
    {
        return Err("Invalid executable mapping path.");
    }
    Ok(path)
}

fn decode(raw: &str) -> Result<PathBuf> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\\'
            && cursor + 3 < bytes.len()
            && bytes[cursor + 1..cursor + 4]
                .iter()
                .all(|v| (b'0'..=b'7').contains(v))
        {
            let value = (bytes[cursor + 1] - b'0') as u16 * 64
                + (bytes[cursor + 2] - b'0') as u16 * 8
                + (bytes[cursor + 3] - b'0') as u16;
            decoded.push(u8::try_from(value).map_err(|_| "Invalid executable mapping path.")?);
            cursor += 4;
        } else {
            decoded.push(bytes[cursor]);
            cursor += 1;
        }
    }
    path(std::str::from_utf8(&decoded).map_err(|_| "Invalid executable mapping path.")?)
}

pub(super) fn targets(raw: &[u8]) -> Result<Vec<(PathBuf, u64)>> {
    if raw.len() > 8 * 1024 * 1024 {
        return Err("Mount snapshot exceeds its budget.");
    }
    let text = std::str::from_utf8(raw).map_err(|_| "Malformed namespace mount snapshot.")?;
    let lines: Vec<_> = text.lines().collect();
    if lines.is_empty() || lines.len() > 4096 {
        return Err("Invalid namespace mount count.");
    }
    let mut targets = BTreeMap::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 10 || !fields[6..].contains(&"-") {
            return Err("Malformed namespace mount snapshot.");
        }
        let destination = decode(fields[4])?;
        let options: Vec<_> = fields[5].split(',').collect();
        if options.contains(&"ro") == options.contains(&"rw") {
            return Err("Ambiguous namespace mount permissions.");
        }
        let mut flags = NOSUID | NOEXEC;
        if options.contains(&"ro") {
            flags |= READONLY;
        }
        if options.contains(&"nodev") {
            flags |= NODEV;
        }
        flags |= if options.contains(&"noatime") {
            1024
        } else if options.contains(&"relatime") {
            1 << 21
        } else {
            1 << 24
        };
        if options.contains(&"nodiratime") {
            flags |= 2048;
        }
        targets.insert(destination, flags);
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    Ok(targets)
}
