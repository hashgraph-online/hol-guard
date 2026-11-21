//! Private input snapshot and executable pinning for contained execution.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::common::{file_sha256, MAX_EXECUTABLE_BYTES};
use super::contract::{Backend, Request};

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_INPUT_FILES: usize = 20_000;

fn make_dir(path: &Path) -> Result<(), String> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|error| error.to_string())
}

pub(super) fn snapshot_inputs(request: &Request, temp_root: &Path) -> Result<PathBuf, String> {
    let snapshot = temp_root.join("workspace");
    DirBuilder::new()
        .mode(0o700)
        .create(&snapshot)
        .map_err(|error| error.to_string())?;
    for name in ["home", "tmp"] {
        DirBuilder::new()
            .mode(0o700)
            .create(temp_root.join(name))
            .map_err(|error| error.to_string())?;
    }
    if request.inputs.len() > MAX_INPUT_FILES {
        return Err("containment input file budget exceeded".to_owned());
    }
    let mut total: u64 = 0;
    for item in &request.inputs {
        let mut destination = snapshot.clone();
        destination.extend(item.snapshot_path.split('/'));
        if let Some(parent) = destination.parent() {
            make_dir(parent)?;
        }
        let (copied, digest) = copy_verified_input(Path::new(&item.source_path), &destination)?;
        total += copied;
        if total > MAX_INPUT_BYTES {
            return Err("containment input byte budget exceeded".to_owned());
        }
        if digest != item.content_digest {
            return Err("containment input identity changed before snapshot".to_owned());
        }
    }
    let relative = Path::new(&request.cwd)
        .strip_prefix(&request.policy.workspace)
        .map_err(|_| "cwd must remain inside the workspace".to_owned())?;
    let snapshot_cwd = snapshot.join(relative);
    make_dir(&snapshot_cwd)?;
    Ok(snapshot_cwd)
}

/// Copy one source into `destination` (exclusive create) while hashing it.
fn copy_stream(
    mut source: &File,
    destination: &Path,
    limit: u64,
    message: &str,
) -> Result<(u64, String), String> {
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| error.to_string())?;
    let mut digest = sha2::Sha256::default();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut copied: u64 = 0;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > limit {
            return Err(message.to_owned());
        }
        sha2::Digest::update(&mut digest, &buffer[..count]);
        target
            .write_all(&buffer[..count])
            .map_err(|error| error.to_string())?;
    }
    Ok((copied, hex::encode(sha2::Digest::finalize(digest))))
}

fn open_source(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

fn copy_verified_input(source: &Path, destination: &Path) -> Result<(u64, String), String> {
    let file = open_source(source).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.size() > MAX_INPUT_BYTES {
        return Err("containment input must remain a bounded regular file".to_owned());
    }
    let (copied, digest) = copy_stream(
        &file,
        destination,
        MAX_INPUT_BYTES,
        "containment input byte budget exceeded",
    )?;
    let mode = if metadata.mode() & 0o111 != 0 {
        0o500
    } else {
        0o400
    };
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    Ok((copied, digest))
}

pub(super) fn pin_executable(
    request: &Request,
    temp_root: &Path,
    backend: Backend,
) -> Result<String, String> {
    let source = &request.argv[0];
    if file_sha256(Path::new(source))? != request.executable_digest {
        return Err("executable identity changed before contained execution".to_owned());
    }
    if backend == Backend::MacosSandbox {
        let metadata = fs::symlink_metadata(source).map_err(|error| error.to_string())?;
        let immutable = ["/System/", "/usr/", "/bin/", "/sbin/"]
            .iter()
            .any(|prefix| source.starts_with(prefix))
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0;
        if immutable {
            return Ok(source.clone());
        }
        return Err("macOS containment requires an immutable system executable".to_owned());
    }
    let destination = temp_root.join("guard-exec");
    let file = open_source(Path::new(source)).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.size() > MAX_EXECUTABLE_BYTES {
        return Err("executable must remain a bounded regular file".to_owned());
    }
    let (_, copied_digest) = copy_stream(
        &file,
        &destination,
        MAX_EXECUTABLE_BYTES,
        "executable must remain a bounded regular file",
    )?;
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o500))
        .map_err(|error| error.to_string())?;
    if copied_digest != request.executable_digest
        || file_sha256(&destination)? != request.executable_digest
    {
        return Err("pinned executable copy failed identity verification".to_owned());
    }
    Ok(destination.to_string_lossy().into_owned())
}
