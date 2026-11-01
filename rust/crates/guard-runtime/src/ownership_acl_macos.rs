//! `ownership-acl`'s `macos-verify` op: walk each protected surface's path
//! chain from its trust root without following links, as `mdm/acl.py` did.
//!
//! Every component must be owned by the expected account, carry no group or
//! world write bit and no extended ACL entry that lets anyone but `root`
//! change it. Each component is `lstat`ed before and after those checks and
//! once more after the whole chain is walked, so a component swapped while
//! it was being read reports `ownership_acl_probe_failed` instead of health.
//! Components shared by several surfaces are checked once per request.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{Surface, ABSENT, PATH_ESCAPE, PROBE_FAILED, USER_WRITABLE, VALID, WRONG_OWNER};

const MAX_ACL_OUTPUT_BYTES: usize = 1024 * 1024;
const ACL_QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const ACL_QUERY_POLL: Duration = Duration::from_millis(5);
const MUTATING_ACL_RIGHTS: [&str; 10] = [
    "add_file",
    "add_subdirectory",
    "append",
    "chown",
    "delete",
    "delete_child",
    "write",
    "writeattr",
    "writeextattr",
    "writesecurity",
];
const SYMLINK_TYPE: u32 = 0o120_000;
const DIRECTORY_TYPE: u32 = 0o040_000;
const REGULAR_TYPE: u32 = 0o100_000;

/// One protected path and the root its chain is walked from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MacosSurface {
    pub(super) name: String,
    pub(super) path: String,
    pub(super) directory: bool,
    pub(super) trust_root: String,
}

/// What `acl.py` compared between two `lstat` calls: device, inode, file
/// type, owner, group, permission bits and change time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Fingerprint {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) kind: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: u32,
    pub(super) ctime_ns: i128,
}

/// The two filesystem questions the walk asks, so tests can stage races.
pub(super) trait Probe {
    fn lstat(&mut self, path: &Path) -> io::Result<Fingerprint>;
    fn acl_is_mutable(&mut self, path: &Path) -> io::Result<bool>;
}

pub(super) struct SystemProbe;

impl Probe for SystemProbe {
    fn lstat(&mut self, path: &Path) -> io::Result<Fingerprint> {
        lstat(path)
    }

    fn acl_is_mutable(&mut self, path: &Path) -> io::Result<bool> {
        list_acl(path).map(|text| acl_text_is_mutable(&text))
    }
}

#[cfg(unix)]
pub(super) fn lstat(path: &Path) -> io::Result<Fingerprint> {
    use std::os::unix::fs::MetadataExt;

    const FILE_TYPE_MASK: u32 = 0o170_000;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(Fingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        kind: metadata.mode() & FILE_TYPE_MASK,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
    })
}

#[cfg(not(unix))]
pub(super) fn lstat(_path: &Path) -> io::Result<Fingerprint> {
    Err(io::ErrorKind::Unsupported.into())
}

enum Checked {
    Refused(&'static str),
    Verified(Fingerprint),
}

/// One result per surface, in request order.
pub(super) fn verify_surfaces(
    surfaces: &[MacosSurface],
    expected_uid: u32,
    probe: &mut impl Probe,
) -> Vec<Surface> {
    let mut cache = HashMap::new();
    surfaces
        .iter()
        .map(|surface| {
            let (state, reason_code) = verify_surface(surface, expected_uid, &mut cache, probe);
            Surface::new(&surface.name, state, reason_code)
        })
        .collect()
}

fn refused(reason_code: &'static str) -> (&'static str, &'static str) {
    let state = if reason_code == ABSENT {
        "absent"
    } else {
        "tampered"
    };
    (state, reason_code)
}

fn verify_surface(
    surface: &MacosSurface,
    expected_uid: u32,
    cache: &mut HashMap<PathBuf, Checked>,
    probe: &mut impl Probe,
) -> (&'static str, &'static str) {
    let unknown = ("unknown", PROBE_FAILED);
    let target = Path::new(&surface.path);
    let Some(chain) = path_chain(target, Path::new(&surface.trust_root)) else {
        return unknown;
    };
    for candidate in &chain {
        match cache.get(candidate) {
            Some(Checked::Refused(reason_code)) => return refused(reason_code),
            Some(Checked::Verified(_)) => {
                if !unchanged(probe, cache, candidate) {
                    return unknown;
                }
                continue;
            }
            None => {}
        }
        let before = match probe.lstat(candidate) {
            Ok(fingerprint) => fingerprint,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                cache.insert(candidate.clone(), Checked::Refused(ABSENT));
                return refused(ABSENT);
            }
            Err(_) => return unknown,
        };
        let refusal = if before.kind == SYMLINK_TYPE {
            Some(PATH_ESCAPE)
        } else if before.uid != expected_uid {
            Some(WRONG_OWNER)
        } else if before.mode & 0o022 != 0 {
            Some(USER_WRITABLE)
        } else {
            match probe.acl_is_mutable(candidate) {
                Ok(true) => Some(USER_WRITABLE),
                Ok(false) => None,
                Err(_) => return unknown,
            }
        };
        if let Some(reason_code) = refusal {
            cache.insert(candidate.clone(), Checked::Refused(reason_code));
            return refused(reason_code);
        }
        match probe.lstat(candidate) {
            Ok(after) if after == before => {
                cache.insert(candidate.clone(), Checked::Verified(after));
            }
            _ => return unknown,
        }
    }
    for candidate in &chain {
        if !unchanged(probe, cache, candidate) {
            return unknown;
        }
    }
    let Ok(last) = probe.lstat(target) else {
        return unknown;
    };
    match cache.get(target) {
        Some(Checked::Verified(fingerprint)) if *fingerprint == last => {}
        _ => return unknown,
    }
    let expected_kind = if surface.directory {
        DIRECTORY_TYPE
    } else {
        REGULAR_TYPE
    };
    if last.kind != expected_kind {
        return ("tampered", PATH_ESCAPE);
    }
    ("healthy", VALID)
}

/// Whether `path` was verified earlier and still reads the same.
fn unchanged(probe: &mut impl Probe, cache: &HashMap<PathBuf, Checked>, path: &Path) -> bool {
    match cache.get(path) {
        Some(Checked::Verified(fingerprint)) => probe.lstat(path).ok() == Some(*fingerprint),
        _ => false,
    }
}

/// The trust root, then each component down to `path`. `None` when `path`
/// is not absolute, spells `.` or `..`, or lies outside `trust_root`.
fn path_chain(path: &Path, trust_root: &Path) -> Option<Vec<PathBuf>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return None;
    }
    let mut chain = Vec::new();
    let mut current = path;
    loop {
        chain.push(current.to_path_buf());
        if current == trust_root {
            chain.reverse();
            return Some(chain);
        }
        if !current.starts_with(trust_root) {
            return None;
        }
        current = current.parent()?;
    }
}

/// `/bin/ls -lde` for one path in the C locale, bounded in time and size.
fn list_acl(path: &Path) -> io::Result<String> {
    let mut child = Command::new("/bin/ls")
        .arg("-lde")
        .arg(path)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("ls stdout unavailable"))?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_ACL_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + ACL_QUERY_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(ACL_QUERY_POLL);
    };
    let bytes = reader
        .join()
        .map_err(|_| io::Error::other("ls reader failed"))??;
    if !status.success() || bytes.len() > MAX_ACL_OUTPUT_BYTES {
        return Err(io::Error::other("macOS ACL query failed"));
    }
    String::from_utf8(bytes).map_err(|_| io::Error::other("macOS ACL query not UTF-8"))
}

/// Whether an `ls -lde` listing grants anyone but `root` a right that
/// changes the entry. The first line is the entry itself; each numbered
/// `allow` line after it is one ACL entry.
pub(super) fn acl_text_is_mutable(text: &str) -> bool {
    text.split(is_line_break).skip(1).any(|line| {
        let tokens: Vec<&str> = line.split(is_space).filter(|t| !t.is_empty()).collect();
        let Some(index) = tokens.first().map(|first| first.trim_end_matches(':')) else {
            return false;
        };
        if index.is_empty() || !index.chars().all(char::is_numeric) {
            return false;
        }
        let Some(allow) = tokens.iter().position(|token| *token == "allow") else {
            return false;
        };
        if fold(tokens[1]) == "user:root" {
            return false;
        }
        tokens[allow + 1..]
            .iter()
            .flat_map(|token| token.split(','))
            .any(|right| MUTATING_ACL_RIGHTS.contains(&fold(right.trim_matches(is_space)).as_str()))
    })
}

/// Python's `str.splitlines` boundaries.
fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Python's `str.split()` whitespace.
fn is_space(character: char) -> bool {
    character.is_whitespace() || matches!(character, '\x1c'..='\x1f')
}

/// Lowercase with the one case fold that maps a letter onto ASCII that
/// lowercasing leaves alone, so a right never escapes the list by spelling.
fn fold(text: &str) -> String {
    text.to_lowercase().replace('\u{17f}', "s")
}

#[cfg(test)]
#[path = "ownership_acl_macos_tests.rs"]
mod tests;
