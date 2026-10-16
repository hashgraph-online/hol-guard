use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};

use winapi::shared::minwindef::{DWORD, FALSE, FILETIME};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{
    GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_TAG_INFO,
};
use winapi::um::minwinbase::{FileAttributeTagInfo, FileIdInfo};
use winapi::um::winbase::{
    GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_TYPE_DISK,
};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GENERIC_READ,
};

use super::private_files::open_raw_with_flags;

// Symlinks, junctions, and mount points set the name-surrogate bit. Other
// reparse points, such as OneDrive and Cloud Files placeholders, leave the
// object where it is and are not aliases.
const NAME_SURROGATE_TAG_BIT: DWORD = 0x2000_0000;

/// Volume serial number and file ID of one file.
///
/// ReFS, including Windows 11 Dev Drives, uses 128-bit file IDs, and the
/// 64-bit `nFileIndex` is not guaranteed unique there, so the full
/// `FILE_ID_INFO` is used when the file system provides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    volume_serial: u64,
    id: [u8; 16],
}

impl FileId {
    /// Volume serial and file ID as lowercase hex, for identity records.
    pub fn to_hex(self) -> String {
        let id: String = self.id.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("{:016x}-{id}", self.volume_serial)
    }
}

// `winapi` 0.3.9 defines `FileIdInfo` but not its output structure.
#[repr(C)]
struct FileIdInformation {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

struct HandleInfo {
    id: FileId,
    links: DWORD,
    directory: bool,
    reparse_tag: Option<DWORD>,
    last_write_time: u64,
    creation_time: u64,
    size: u64,
}

/// What `os.stat` reports for one path, read from a single handle.
///
/// The times are raw `FILETIME` ticks. `file_index` is the little-endian
/// `FILE_ID_INFO` identifier, or the 64-bit `nFileIndex` on file systems
/// without one, as CPython's `win32_xstat` fills `st_ino`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathStat {
    pub last_write_time: u64,
    pub creation_time: u64,
    pub size: u64,
    pub file_index: u128,
}

/// Read one handle's identity. `require_tag` refuses a handle whose reparse
/// tag cannot be read; a metadata-only stat tolerates file systems that do
/// not answer `FileAttributeTagInfo`, as `os.stat` does.
fn handle_info(file: &std::fs::File, require_tag: bool) -> io::Result<HandleInfo> {
    let raw = file.as_raw_handle() as HANDLE;
    // SAFETY: `raw` is a live handle borrowed for the duration of each query.
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(changed("opened object is not a disk file"));
    }
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    // SAFETY: The output buffer is correctly sized and `raw` remains open.
    if unsafe { GetFileInformationByHandle(raw, &mut information) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // `winapi` 0.3.9 names the FileAttributes field `NextEntryOffset`.
    let mut tag_info = unsafe { zeroed::<FILE_ATTRIBUTE_TAG_INFO>() };
    // SAFETY: The output buffer is correctly sized for the requested class
    // and `raw` remains open.
    if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileAttributeTagInfo,
            &mut tag_info as *mut FILE_ATTRIBUTE_TAG_INFO as *mut _,
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as DWORD,
        )
    } == FALSE
    {
        if require_tag {
            return Err(io::Error::last_os_error());
        }
        // Only the attribute bit from the basic query decides reparse then.
        tag_info = unsafe { zeroed::<FILE_ATTRIBUTE_TAG_INFO>() };
    }
    let reparse = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag_info.NextEntryOffset & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || tag_info.ReparseTag != 0;
    let mut id_info = FileIdInformation {
        volume_serial_number: 0,
        file_id: [0; 16],
    };
    // SAFETY: The output buffer matches FILE_ID_INFO's layout and size, and
    // `raw` remains open.
    let id = if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileIdInfo,
            &mut id_info as *mut FileIdInformation as *mut _,
            size_of::<FileIdInformation>() as DWORD,
        )
    } != FALSE
    {
        FileId {
            volume_serial: id_info.volume_serial_number,
            id: id_info.file_id,
        }
    } else {
        // File systems without FileIdInfo, such as FAT, still report the
        // 64-bit index, which is unique on them. A volume answers the same
        // way for every file, so both forms never meet in one comparison.
        let index =
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
        let mut id = [0; 16];
        id[..8].copy_from_slice(&index.to_le_bytes());
        FileId {
            volume_serial: u64::from(information.dwVolumeSerialNumber),
            id,
        }
    };
    let filetime =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    Ok(HandleInfo {
        id,
        links: information.nNumberOfLinks,
        directory: information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse_tag: reparse.then_some(tag_info.ReparseTag),
        last_write_time: filetime(information.ftLastWriteTime),
        creation_time: filetime(information.ftCreationTime),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
    })
}

/// Reject a handle of the wrong kind or one that names a link to another
/// object.
fn checked_info(file: &std::fs::File, directory: bool) -> io::Result<HandleInfo> {
    let info = handle_info(file, true)?;
    let alias = info
        .reparse_tag
        .is_some_and(|tag| tag == 0 || tag & NAME_SURROGATE_TAG_BIT != 0);
    if info.directory != directory || alias {
        return Err(changed("path component is a link or the wrong object type"));
    }
    Ok(info)
}

fn changed(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Return the identity and directory-entry count of an existing regular
/// file. With `follow_leaf`, a link at the leaf is resolved to its target.
pub fn regular_file_id(path: &Path, follow_leaf: bool) -> io::Result<(FileId, u32)> {
    let flags = if follow_leaf {
        0
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    let file = open_raw_with_flags(
        path,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_READ_ATTRIBUTES,
        flags,
    )?;
    let info = checked_info(&file, false)?;
    Ok((info.id, info.links))
}

/// `os.stat` for `path`: a link at the leaf is followed, and a file or a
/// directory is read through one handle, as CPython's `win32_xstat` slow
/// path opens it.
pub fn path_stat(path: &Path) -> io::Result<PathStat> {
    let file = open_raw_with_flags(
        path,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_READ_ATTRIBUTES,
        FILE_FLAG_BACKUP_SEMANTICS,
    )?;
    let info = handle_info(&file, false)?;
    Ok(PathStat {
        last_write_time: info.last_write_time,
        creation_time: info.creation_time,
        size: info.size,
        file_index: u128::from_le_bytes(info.id.id),
    })
}

/// Identity of one existing directory, without opening its ancestors.
///
/// A symlink, junction, or mount point at this path is rejected. Cloud
/// placeholders stay, because they are not aliases. Ancestor junctions are
/// left alone so a skill under a synced folder can still be named.
pub fn directory_file_id(path: &Path) -> io::Result<FileId> {
    let file = open_skill_directory(path)?;
    Ok(checked_info(&file, true)?.id)
}

/// Hold one directory open. The handle pins that directory only.
pub fn open_skill_directory(path: &Path) -> io::Result<std::fs::File> {
    let file = open_raw_with_flags(
        path,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    checked_info(&file, true)?;
    Ok(file)
}

/// Return the identity of the file behind an open handle.
pub fn handle_file_id(file: &std::fs::File) -> io::Result<FileId> {
    Ok(handle_info(file, true)?.id)
}

/// Open an existing single-link regular file for reading by walking its
/// canonical path.
///
/// Every ancestor directory is held open without delete sharing until the
/// leaf is open, so no component can be renamed or swapped for a link between
/// the caller's canonicalization and this open. Components that are
/// symlinks, junctions, or mount points are rejected. The returned handle
/// shares only reads, so no writer can change the bytes while it is open.
/// Callers compare `handle_file_id` with the file they inspected.
pub fn open_bound_regular_file(canonical_path: &Path) -> io::Result<std::fs::File> {
    open_bound_file(canonical_path, true, FILE_SHARE_READ)
}

/// Like `open_bound_regular_file`, but the handle also shares delete, so a
/// writer can still replace the file with a rename while it is open. The
/// handle keeps reading the bytes it opened, because a rename never changes
/// the contents of an open file, and writers stay excluded.
pub fn open_bound_replaceable_file(canonical_path: &Path) -> io::Result<std::fs::File> {
    open_bound_file(canonical_path, true, FILE_SHARE_READ | FILE_SHARE_DELETE)
}

/// Pin executable bytes without write/delete sharing. System executables may
/// have legitimate WinSxS hardlinks; every link refers to the same locked file.
pub fn open_bound_executable_file(canonical_path: &Path) -> io::Result<std::fs::File> {
    open_bound_file(canonical_path, false, FILE_SHARE_READ)
}

fn open_bound_file(
    canonical_path: &Path,
    single_link: bool,
    leaf_share: DWORD,
) -> io::Result<std::fs::File> {
    let mut components = canonical_path.components().peekable();
    let mut current = PathBuf::new();
    let mut ancestors = Vec::new();
    while let Some(component) = components.next() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                if components.peek().is_none() {
                    let file = open_leaf(&current, single_link, leaf_share);
                    drop(ancestors);
                    return file;
                }
                let directory = open_raw_with_flags(
                    &current,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                )?;
                checked_info(&directory, true)?;
                ancestors.push(directory);
            }
            Component::CurDir | Component::ParentDir => break,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "path must be canonical and name a file",
    ))
}

fn open_leaf(path: &Path, single_link: bool, share: DWORD) -> io::Result<std::fs::File> {
    let entry = open_raw_with_flags(path, share, GENERIC_READ, FILE_FLAG_OPEN_REPARSE_POINT)?;
    let info = checked_info(&entry, false)?;
    if info.links == 0 || (single_link && info.links != 1) {
        return Err(changed("opened file has more than one directory entry"));
    }
    if info.reparse_tag.is_none() {
        return Ok(entry);
    }
    // A cloud placeholder's bytes are served by its filter, so reopen it
    // without FILE_FLAG_OPEN_REPARSE_POINT. The file IDs must match, so a
    // replacement between the two opens is refused.
    let content = open_raw_with_flags(path, share, GENERIC_READ, 0)?;
    if handle_info(&content, true)?.id != info.id {
        return Err(changed("reopened placeholder is a different file"));
    }
    Ok(content)
}
