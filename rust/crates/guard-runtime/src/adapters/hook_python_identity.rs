//! `runner_authority` kind `hook_python_identity`: the stable identity of the
//! executable a managed hook launches Guard with, which
//! `_executable_identity` in `guard/adapters/hook_python.py` read before it
//! moved here.
//!
//! The identity is the invocation path as the hook spells it, whether that is
//! a symlink and where it points, the canonical target, the stat fields of
//! both and the target's SHA-256. Everything is read twice around the hash:
//! an invocation, target or stat that moved while the content was read is
//! answered as changed rather than bound to content it may no longer have.
//!
//! The stat fields are the ones `os.stat` reports, so an identity Guard
//! recorded before reads the same here. On Windows the device is the volume
//! serial, the inode the `FILE_ID_INFO` identifier, and the mode is spelled
//! from the read-only attribute and the four extensions the shell runs.
//!
//! `attest` runs that interpreter to confirm what it imports; see
//! `hook_python_attest.rs`.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::{json, Number, Value};
use sha2::{Digest, Sha256};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const UNAVAILABLE: &str = "guard_hook_python_interpreter_unavailable";
const UNTRUSTED: &str = "guard_hook_python_interpreter_untrusted";
const CHANGED: &str = "guard_hook_python_interpreter_changed";
const CHUNK: usize = 1024 * 1024;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    match map.get("op").and_then(Value::as_str) {
        Some("executable") if map.len() == 2 => {}
        Some("attest") => return attest::attest(map),
        _ => return Err(ERR_INVALID),
    }
    let path = map
        .get("path")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or(ERR_INVALID)?;
    Ok(match identity(path) {
        Ok(identity) => json!({ "identity": identity }),
        Err(error) => json!({ "error": error }),
    })
}

/// The `os.stat_result` fields an identity records.
#[derive(Debug, PartialEq, Eq)]
struct Stat {
    device: u64,
    inode: u128,
    mode: u32,
    size: u64,
    mtime_ns: i128,
}

impl Stat {
    fn payload(&self) -> Value {
        json!({
            "device": self.device,
            "inode": integer(&self.inode.to_string()),
            "mode": self.mode,
            "size": self.size,
            "mtime_ns": integer(&self.mtime_ns.to_string()),
        })
    }
}

/// An integer past 64 bits, as Python writes it.
fn integer(digits: &str) -> Value {
    digits.parse::<Number>().map_or(Value::Null, Value::Number)
}

fn identity(invocation: &Path) -> Result<Value, &'static str> {
    let (invocation_before, symlink) = lstat(invocation).map_err(|_| UNAVAILABLE)?;
    let target = resolve(invocation).map_err(|_| UNAVAILABLE)?;
    let (target_before, target_regular) = stat(&target).map_err(|_| UNAVAILABLE)?;
    let link_target = match symlink {
        Some(true) => Some(
            fs::read_link(invocation)
                .map_err(|_| UNAVAILABLE)?
                .to_string_lossy()
                .into_owned(),
        ),
        _ => None,
    };
    let invocation_type = match symlink {
        Some(true) => "symlink",
        Some(false) => "file",
        None => return Err(UNTRUSTED),
    };
    if !target_regular || !executable(invocation) {
        return Err(UNTRUSTED);
    }
    let sha256 = sha256(&target).map_err(|_| CHANGED)?;
    let (invocation_after, _) = lstat(invocation).map_err(|_| CHANGED)?;
    let target_after_path = resolve(invocation).map_err(|_| CHANGED)?;
    let (target_after, _) = stat(&target_after_path).map_err(|_| CHANGED)?;
    if invocation_before != invocation_after
        || target_after_path != target
        || target_before != target_after
    {
        return Err(CHANGED);
    }
    Ok(json!({
        "invocation_path": invocation.to_string_lossy(),
        "invocation_type": invocation_type,
        "invocation_link_target": link_target,
        "invocation_stat": invocation_before.payload(),
        "target_path": target.to_string_lossy(),
        "target_stat": target_before.payload(),
        "target_sha256": sha256,
    }))
}

/// `Path.resolve(strict=True)`, without the verbatim prefix `canonicalize`
/// adds on Windows.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    let resolved = fs::canonicalize(path)?;
    let text = resolved.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return Ok(PathBuf::from(format!(r"\\{unc}")));
    }
    Ok(match text.strip_prefix(r"\\?\") {
        Some(stripped) => PathBuf::from(stripped),
        None => resolved,
    })
}

fn sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// `os.access(path, os.X_OK)`, which off POSIX holds for any file that exists.
fn executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

/// `os.lstat` and whether the entry is a symlink (`Some(true)`), a regular
/// file (`Some(false)`) or anything else (`None`).
fn lstat(path: &Path) -> io::Result<(Stat, Option<bool>)> {
    let metadata = fs::symlink_metadata(path)?;
    let kind = if metadata.file_type().is_symlink() {
        Some(true)
    } else if metadata.is_file() {
        Some(false)
    } else {
        None
    };
    Ok((platform::lstat(path, &metadata)?, kind))
}

/// `os.stat` and whether it names a regular file.
fn stat(path: &Path) -> io::Result<(Stat, bool)> {
    let metadata = fs::metadata(path)?;
    Ok((platform::stat(path, &metadata)?, metadata.is_file()))
}

#[cfg(unix)]
mod platform {
    use std::fs::Metadata;
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    use super::Stat;

    pub(super) fn lstat(_path: &Path, metadata: &Metadata) -> io::Result<Stat> {
        Ok(of(metadata))
    }

    pub(super) fn stat(_path: &Path, metadata: &Metadata) -> io::Result<Stat> {
        Ok(of(metadata))
    }

    fn of(metadata: &Metadata) -> Stat {
        Stat {
            device: metadata.dev(),
            inode: u128::from(metadata.ino()),
            mode: metadata.mode(),
            size: metadata.size(),
            mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::Metadata;
    use std::io;
    use std::path::Path;

    use guard_runtime_windows_process::{link_stat, path_stat, PathStat};

    use super::Stat;

    const S_IFREG: u32 = 0o100_000;
    const S_IFLNK: u32 = 0o120_000;
    /// `FILETIME` ticks between 1601-01-01 and the Unix epoch.
    const EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    pub(super) fn lstat(path: &Path, metadata: &Metadata) -> io::Result<Stat> {
        let kind = if metadata.file_type().is_symlink() {
            S_IFLNK
        } else {
            S_IFREG
        };
        Ok(of(path, metadata, kind, link_stat(path)?))
    }

    pub(super) fn stat(path: &Path, metadata: &Metadata) -> io::Result<Stat> {
        Ok(of(path, metadata, S_IFREG, path_stat(path)?))
    }

    /// CPython's `win32_xstat`: the read-only attribute picks the permission
    /// bits and four extensions add the execute bits.
    fn of(path: &Path, metadata: &Metadata, kind: u32, stat: PathStat) -> Stat {
        let mut mode = kind
            | if metadata.permissions().readonly() {
                0o444
            } else {
                0o666
            };
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if matches!(extension.as_str(), "bat" | "cmd" | "exe" | "com") {
            mode |= 0o111;
        }
        Stat {
            device: stat.volume_serial,
            inode: stat.file_index,
            mode,
            size: stat.size,
            mtime_ns: (i128::from(stat.last_write_time) - EPOCH_TICKS) * 100,
        }
    }
}

#[path = "hook_python_attest.rs"]
mod attest;

#[cfg(test)]
#[path = "hook_python_identity_tests.rs"]
mod tests;
