//! Descriptor-rooted discovery without file reads, symlinks or hardlink aliases.
use super::BoundaryResult as Result;
use nix::dir::{Dir, OwningIter};
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fstatat, Mode};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_ENTRIES: usize = 240_000;
const PROTECTED: &[&str] = &[".ssh", ".aws", ".docker", ".kube", ".gnupg", ".hol-guard"];
const MESSAGE: &str = "Linux workspace could not be indexed safely.";
pub(super) type Candidates = BTreeMap<String, BTreeSet<PathBuf>>;
/// An admitted regular file and the device/inode identity it was indexed with.
pub(super) type Grant = (PathBuf, u64, u64);

struct Frame {
    path: PathBuf,
    file: File,
    entries: OwningIter,
}
impl Frame {
    fn new(path: PathBuf, file: File) -> Result<Self> {
        let duplicate = file.try_clone().map_err(|_| MESSAGE)?;
        let directory = Dir::from_fd(duplicate.into()).map_err(|_| MESSAGE)?;
        Ok(Self {
            path,
            file,
            entries: directory.into_iter(),
        })
    }
}

fn protected(path: &Path, root: &Path) -> Result<bool> {
    let text = path.to_str().ok_or(MESSAGE)?;
    Ok(path
        .file_name()
        .and_then(|v| v.to_str())
        .is_some_and(|v| PROTECTED.contains(&v.to_lowercase().as_str()))
        || guard_command::secret_path_probe::is_request_secret_path(text, Some(root), Some(root)))
}

pub(super) fn child(parent: &File, name: &std::ffi::CStr, device: u64, inode: u64) -> Result<File> {
    let descriptor = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| MESSAGE)?;
    let file = File::from(descriptor);
    let opened = file.metadata().map_err(|_| MESSAGE)?;
    if (opened.dev(), opened.ino()) != (device, inode) {
        return Err("Linux workspace changed during discovery.");
    }
    Ok(file)
}

// libc uses signed dev_t on macOS and unsigned dev_t on Linux. Both become
// the same unsigned identity reported by std::fs::Metadata and the wire DTO.
pub(super) fn collect(root: &Path, limit: usize, deadline: Instant) -> Result<Value> {
    let (grants, _) = collect_with_candidates(root, limit, deadline)?;
    Ok(Value::Array(
        grants
            .into_iter()
            .map(|(path, device, inode)| json!({"path":path,"device":device,"inode":inode}))
            .collect(),
    ))
}

#[allow(clippy::unnecessary_cast)]
pub(super) fn collect_with_candidates(
    root: &Path,
    limit: usize,
    deadline: Instant,
) -> Result<(Vec<Grant>, Candidates)> {
    if !root.is_absolute() || limit == 0 || limit > MAX_ENTRIES {
        return Err("Invalid Linux workspace discovery boundary.");
    }
    if root.canonicalize().map_err(|_| MESSAGE)? != root
        || root.components().any(|part| {
            let text = part.as_os_str().to_string_lossy().to_lowercase();
            PROTECTED.contains(&text.as_str()) || text == ".env" || text.starts_with(".env.")
        })
    {
        return Err("Linux workspace is not a canonical nonsensitive directory.");
    }
    let descriptor = open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| MESSAGE)?;
    let mut stack = vec![Frame::new(root.to_path_buf(), File::from(descriptor))?];
    let mut visited = 0;
    let mut grants = Vec::new();
    let mut candidates = Candidates::new();
    while let Some(frame) = stack.last_mut() {
        if Instant::now() >= deadline {
            return Err("Linux workspace discovery exceeds its time budget.");
        }
        let Some(entry) = frame.entries.next() else {
            stack.pop();
            continue;
        };
        let entry = entry.map_err(|_| MESSAGE)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        visited += 1;
        if visited > limit {
            return Err("Linux workspace discovery exceeds its entry budget.");
        }
        let path = frame
            .path
            .join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let metadata =
            fstatat(&frame.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| MESSAGE)?;
        let kind = metadata.st_mode & libc::S_IFMT;
        // Grants and candidate names travel as JSON strings. A non-UTF-8 name
        // cannot be represented or matched by DT_NEEDED, so the entry and any
        // subtree under it stay ungranted instead of aborting discovery.
        let Ok(text) = name.to_str() else {
            continue;
        };
        if protected(&path, root)? {
            continue;
        }
        if kind == libc::S_IFLNK || (kind == libc::S_IFREG && metadata.st_nlink == 1) {
            candidates
                .entry(text.to_owned())
                .or_default()
                .insert(frame.path.clone());
        }
        if kind == libc::S_IFLNK {
            continue;
        }
        if kind == libc::S_IFDIR {
            let file = child(
                &frame.file,
                name,
                metadata.st_dev as u64,
                metadata.st_ino as u64,
            )?;
            stack.push(Frame::new(path, file)?);
        } else if kind == libc::S_IFREG && metadata.st_nlink == 1 {
            grants.push((path, metadata.st_dev as u64, metadata.st_ino as u64));
        }
    }
    Ok((grants, candidates))
}
