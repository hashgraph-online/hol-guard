//! Pure inode/type checks shared by the live descriptor grant and old replay.
use super::plan::Result;
use std::path::Path;

pub(super) struct Evidence {
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
    pub links: u64,
    pub major: u32,
    pub minor: u32,
}

pub(super) fn rights(
    path: &Path,
    mut access: u64,
    directory: Option<bool>,
    identity: Option<(u64, u64)>,
    device: bool,
    evidence: &Evidence,
) -> Result<u64> {
    if !path.is_absolute() {
        return Err("Linux access plans require absolute paths.");
    }
    let kind = evidence.mode & 0o170000;
    if device {
        let expected = match path.to_str() {
            Some("/dev/null") => 3,
            Some("/dev/random") => 8,
            Some("/dev/urandom") => 9,
            _ => return Err("Unexpected namespace device."),
        };
        if kind != 0o020000 || evidence.major != 1 || evidence.minor != expected {
            return Err("Unexpected namespace device.");
        }
    }
    if identity.is_some_and(|v| v != (evidence.device, evidence.inode) || evidence.links != 1) {
        return Err("Linux read target changed after discovery.");
    }
    let is_directory = kind == 0o040000;
    if kind == 0o120000 || directory.is_some_and(|v| v != is_directory) {
        return Err("Linux access target changed or has an unexpected type.");
    }
    if !is_directory {
        access &= 1 | (1 << 1) | (1 << 2) | (1 << 14);
    }
    Ok(access)
}
