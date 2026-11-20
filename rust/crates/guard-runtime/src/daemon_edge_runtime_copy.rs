//! Place and first-run the Guard home's kept runtime copy while the daemon starts.
//!
//! The worker host's first step after its imports is the installed-bundle
//! check, which runs this runtime from the Guard home's private `native-exec`
//! folder (`extension_builder/native_executable_root.py`). In a fresh Guard
//! home that folder is empty, so the host writes a copy of over 100 MB and
//! runs a new executable image for the first time. macOS assesses every new
//! image and Windows scans it, so that first run alone cost one to two
//! seconds of every first start, after the host's own imports.
//!
//! The daemon starts the host and, beside it on a thread of its own, places
//! the same copy under the same name, using the same privacy rules, and runs
//! it once. The host's Python start then overlaps the write and the first
//! run. Nothing here is trusted: before every run the host still compares the
//! copy byte for byte with the bytes it verified, and it replaces a copy that
//! differs. A copy that is already in place and differs is left for the host
//! to replace. A Guard home whose folder is not private, or a test home, is
//! left alone, and every failure leaves the host to write the copy as before.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const PRIVATE_ROOT_NAME: &str = "native-exec";
const KEPT_PREFIX: &str = "hol-guard-runtime-";
// The host removes a folder with this prefix once the process id in its name
// has ended, so a copy this daemon left half written is cleaned up.
const DIRECTORY_PREFIX: &str = "hol-guard-source-compiler-";
#[cfg(windows)]
const EXECUTABLE_NAME: &str = "hol-guard-runtime.exe";
#[cfg(not(windows))]
const EXECUTABLE_NAME: &str = "hol-guard-runtime";
/// A source-compiler operation that answers from built-in data and exits.
const FIRST_RUN_OPERATION: &str = "compiler-info";
const FIRST_RUN_LIMIT: Duration = Duration::from_secs(30);
const CHUNK: usize = 1024 * 1024;

/// Place and first-run this runtime's kept copy on a thread of its own.
pub(super) fn prime_in_background(home: &Path) {
    if super::resident_prewarm::ephemeral_home(home) {
        return;
    }
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let home = home.to_path_buf();
    let _ = std::thread::Builder::new()
        .name("runtime-copy-prime".to_owned())
        .spawn(move || {
            if let Some(copy) = place(&home, &executable) {
                first_run(&copy);
            }
        });
}

/// The kept copy of `source` in `home`'s private folder, written when absent.
/// None when the folder is not private, or a different copy is in the way.
pub(super) fn place(home: &Path, source: &Path) -> Option<PathBuf> {
    let root = private_root(home)?;
    let digest = sha256_file(source).ok()?;
    let kept = root.join(format!("{KEPT_PREFIX}{digest}"));
    let copy = kept.join(EXECUTABLE_NAME);
    if fs::symlink_metadata(&kept).is_ok() {
        return same_bytes(&copy, source).then_some(copy);
    }
    let staged = stage(&root, source, &digest)?;
    // A copy another process placed first stays; only a matching one is run.
    let renamed = fs::rename(&staged, &kept).is_ok();
    if !renamed {
        let _ = fs::remove_dir_all(&staged);
    }
    same_bytes(&copy, source).then_some(copy)
}

/// Write `source` under a private name in `root`, checking its digest.
fn stage(root: &Path, source: &Path, digest: &str) -> Option<PathBuf> {
    let staged = root.join(format!(
        "{DIRECTORY_PREFIX}{}-{}",
        std::process::id(),
        super::random_hex(8)
    ));
    create_private_directory(&staged).ok()?;
    let written = write_copy(source, &staged.join(EXECUTABLE_NAME));
    if written.as_deref().ok() != Some(digest) {
        let _ = fs::remove_dir_all(&staged);
        return None;
    }
    Some(staged)
}

fn write_copy(source: &Path, target: &Path) -> io::Result<String> {
    let mut input = File::open(source)?;
    let mut output = create_private_file(target)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.sync_all()?;
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

/// Whether `copy` is a regular file holding exactly the bytes of `source`.
fn same_bytes(copy: &Path, source: &Path) -> bool {
    let compare = || -> io::Result<bool> {
        let metadata = fs::symlink_metadata(copy)?;
        if !metadata.is_file() || metadata.len() != fs::metadata(source)?.len() {
            return Ok(false);
        }
        let (mut left, mut right) = (File::open(copy)?, File::open(source)?);
        let (mut a, mut b) = (vec![0u8; CHUNK], vec![0u8; CHUNK]);
        loop {
            let read = read_full(&mut left, &mut a)?;
            if read != read_full(&mut right, &mut b)? || a[..read] != b[..read] {
                return Ok(false);
            }
            if read == 0 {
                return Ok(true);
            }
        }
    };
    compare().unwrap_or(false)
}

fn read_full(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// Run the new copy once, so the system's first look at the image is paid
/// here rather than by the host's bundle check. Its answer is not used.
fn first_run(copy: &Path) {
    let Ok(mut child) = Command::new(copy)
        .arg(FIRST_RUN_OPERATION)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let started = Instant::now();
    while started.elapsed() < FIRST_RUN_LIMIT {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// `home`'s private folder, under the rules the host applies before it keeps a copy there.
#[cfg(unix)]
fn private_root(home: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let euid = nix::unistd::geteuid().as_raw();
    let closed = |metadata: &fs::Metadata, open_bits: u32| {
        metadata.is_dir() && metadata.uid() == euid && metadata.mode() & open_bits == 0
    };
    // Another account that can write the Guard home, or a directory above it,
    // could rename the private folder away and put its own in its place.
    if !closed(&fs::symlink_metadata(home).ok()?, 0o022) || replaceable_above(home, euid) {
        return None;
    }
    let root = home.join(PRIVATE_ROOT_NAME);
    match create_private_directory(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    closed(&fs::symlink_metadata(&root).ok()?, 0o077).then_some(root)
}

/// Whether another account could rename a directory above `directory` away,
/// on the path as named or on the path its links resolve to.
#[cfg(unix)]
fn replaceable_above(directory: &Path, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(resolved) = fs::canonicalize(directory) else {
        return true;
    };
    for ancestor in directory
        .ancestors()
        .skip(1)
        .chain(resolved.ancestors().skip(1))
    {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(ancestor) else {
            return true;
        };
        if metadata.uid() != 0 && metadata.uid() != euid {
            return true;
        }
        if metadata.file_type().is_symlink() {
            continue;
        }
        // The sticky bit limits renames to the entry's owner, as on /tmp.
        if !metadata.is_dir() || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0) {
            return true;
        }
    }
    false
}

/// On Windows, only a Guard home reached from the user's profile through
/// plain folders, which inherit the profile's access list, keeps a copy.
#[cfg(windows)]
fn private_root(home: &Path) -> Option<PathBuf> {
    let profile = PathBuf::from(std::env::var_os("USERPROFILE")?);
    let relative = home.strip_prefix(&profile).ok()?;
    let mut current = profile;
    for part in relative.components() {
        current.push(part);
        if !plain_windows_directory(&current) {
            return None;
        }
    }
    let root = home.join(PRIVATE_ROOT_NAME);
    match fs::create_dir(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    plain_windows_directory(&root).then_some(root)
}

#[cfg(windows)]
fn plain_windows_directory(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    })
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
#[path = "daemon_edge_runtime_copy_tests.rs"]
mod tests;
