#![forbid(unsafe_code)]
//! Descriptor-relative, private filesystem access for the capture marker and
//! its output. Every step refuses symlinks and requires owner-only modes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

use fs2::FileExt;
use nix::errno::Errno;
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::{mkdirat, Mode};
use nix::unistd::Uid;

use crate::binding_capture_crypto::{
    encode_marker, parse_marker, valid_run_id, CaptureSession, KEY_BYTES, MAX_BYTES,
    MAX_MARKER_BYTES, MAX_RECORDS,
};
use crate::binding_capture_join::valid_existing_records;
use crate::binding_capture_json::{self as json, Json};

pub(crate) const DIRECTORY_NAME: &str = "diagnostics";
pub(crate) const MARKER_NAME: &str = "codex-binding-capture.v2.json";
const OUTPUT_PREFIX: &str = "codex-binding-capture.";
const OUTPUT_SUFFIX: &str = ".jsonl";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const LOCK_DEADLINE: Duration = Duration::from_millis(20);

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn private_directory(file: &File) -> bool {
    file.metadata().is_ok_and(|meta| {
        meta.is_dir()
            && meta.uid() == Uid::current().as_raw()
            && meta.mode() & 0o7777 == PRIVATE_DIRECTORY_MODE
    })
}

fn private_regular(file: &File) -> bool {
    file.metadata().is_ok_and(|meta| {
        meta.is_file()
            && meta.uid() == Uid::current().as_raw()
            && meta.mode() & 0o7777 == PRIVATE_FILE_MODE
            && meta.nlink() == 1
    })
}

/// Open an absolute, `..`-free Guard home one component at a time.
fn open_private_guard_home(guard_home: &Path) -> Option<File> {
    if !guard_home.is_absolute() {
        return None;
    }
    let mut components = guard_home.components();
    let _root = components.next();
    let mut current: OwnedFd = nix::fcntl::open("/", directory_flags(), Mode::empty()).ok()?;
    for component in components {
        let Component::Normal(name) = component else {
            return None;
        };
        current = openat(&current, name, directory_flags(), Mode::empty()).ok()?;
    }
    let directory = File::from(current);
    private_directory(&directory).then_some(directory)
}

fn open_diagnostics(guard_home: &Path) -> Option<File> {
    let home = open_private_guard_home(guard_home)?;
    let directory =
        File::from(openat(&home, DIRECTORY_NAME, directory_flags(), Mode::empty()).ok()?);
    private_directory(&directory).then_some(directory)
}

/// Read exactly the descriptor's current contents when within `maximum`.
fn read_descriptor(file: &mut File, maximum: usize) -> Option<Vec<u8>> {
    let size = usize::try_from(file.metadata().ok()?.len()).ok()?;
    if size > maximum {
        return None;
    }
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// Load and validate the private v2 marker (`_load_capture_config`).
pub(crate) fn load_capture_config(guard_home: &Path, now: f64) -> Option<CaptureSession> {
    let directory = open_diagnostics(guard_home)?;
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let mut marker = File::from(openat(&directory, MARKER_NAME, flags, Mode::empty()).ok()?);
    if !private_regular(&marker) {
        return None;
    }
    let raw = read_descriptor(&mut marker, MAX_MARKER_BYTES)?;
    parse_marker(&json::parse_object(&raw)?, now)
}

fn write_all_bounded(output: &mut File, bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        match output.write(&bytes[offset..]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(written) => offset += written,
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Append one row under an exclusive lock with a bounded wait.
pub(crate) fn append_row(
    session: &CaptureSession,
    guard_home: &Path,
    row: &Json,
    now: f64,
) -> bool {
    if now >= session.expires_at as f64 {
        return false;
    }
    let Some(mut serialized) = json::canonical(row) else {
        return false;
    };
    serialized.push(b'\n');
    if serialized.len() as i64 > session.max_bytes {
        return false;
    }
    let Some(directory) = open_diagnostics(guard_home) else {
        return false;
    };
    let name = format!("{OUTPUT_PREFIX}{}{OUTPUT_SUFFIX}", session.run_id);
    let flags = OFlag::O_RDWR
        | OFlag::O_APPEND
        | OFlag::O_CREAT
        | OFlag::O_NOFOLLOW
        | OFlag::O_NONBLOCK
        | OFlag::O_CLOEXEC;
    let Ok(descriptor) = openat(
        &directory,
        name.as_str(),
        flags,
        Mode::S_IRUSR | Mode::S_IWUSR,
    ) else {
        return false;
    };
    let mut output = File::from(descriptor);
    if !private_regular(&output) {
        return false;
    }
    let deadline = Instant::now() + LOCK_DEADLINE;
    loop {
        match output.try_lock_exclusive() {
            Ok(()) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(_) => return false,
        }
    }
    let appended = append_locked(&mut output, session, &serialized, deadline, now);
    let _ = FileExt::unlock(&output);
    appended
}

fn append_locked(
    output: &mut File,
    session: &CaptureSession,
    serialized: &[u8],
    deadline: Instant,
    now: f64,
) -> bool {
    let max_bytes = session.max_bytes as u64;
    let Ok(metadata) = output.metadata() else {
        return false;
    };
    if metadata.len() > max_bytes {
        return false;
    }
    let Some(existing) = read_descriptor(output, max_bytes as usize) else {
        return false;
    };
    let Some(count) = valid_existing_records(&existing, &session.run_id, Some(session), now) else {
        return false;
    };
    if count as i64 >= session.max_records || (existing.len() + serialized.len()) as u64 > max_bytes
    {
        return false;
    }
    if output.seek(SeekFrom::End(0)).is_err() {
        return false;
    }
    if write_all_bounded(output, serialized, deadline).is_err() {
        let _ = output.set_len(existing.len() as u64);
        return false;
    }
    true
}

fn random_session(
    run_id: &str,
    expires_at: i64,
    max_records: i64,
    max_bytes: i64,
    now: f64,
) -> Option<CaptureSession> {
    if !valid_run_id(run_id) {
        return None;
    }
    let mut key = vec![0u8; KEY_BYTES];
    let mut key_id = [0u8; 16];
    getrandom::fill(&mut key).ok()?;
    getrandom::fill(&mut key_id).ok()?;
    let session = CaptureSession {
        run_id: run_id.to_owned(),
        expires_at,
        max_records,
        max_bytes,
        key_id: hex::encode(key_id),
        key,
    };
    session.usable(now).then_some(session)
}

/// Create one marker and its per-run key in verified private directories.
pub(crate) fn initialize_marker(
    guard_home: &Path,
    run_id: &str,
    expires_at: i64,
    max_records: Option<i64>,
    max_bytes: Option<i64>,
    now: f64,
) -> Option<CaptureSession> {
    let session = random_session(
        run_id,
        expires_at,
        max_records.unwrap_or(MAX_RECORDS),
        max_bytes.unwrap_or(MAX_BYTES),
        now,
    )?;
    let encoded = encode_marker(&session, now)?;
    let home = open_private_guard_home(guard_home)?;
    let directory = match openat(&home, DIRECTORY_NAME, directory_flags(), Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            mkdirat(&home, DIRECTORY_NAME, Mode::S_IRWXU).ok()?;
            openat(&home, DIRECTORY_NAME, directory_flags(), Mode::empty()).ok()?
        }
        Err(_) => return None,
    };
    let directory = File::from(directory);
    if !private_directory(&directory) {
        return None;
    }
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut marker = File::from(
        openat(
            &directory,
            MARKER_NAME,
            flags,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .ok()?,
    );
    marker.write_all(&encoded).ok()?;
    private_regular(&marker).then_some(session)
}
