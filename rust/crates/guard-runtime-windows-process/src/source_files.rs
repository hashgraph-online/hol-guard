use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO};
use winapi::um::minwinbase::FileIdInfo;
use winapi::um::winbase::{GetFileInformationByHandleEx, FILE_FLAG_BACKUP_SEMANTICS};
use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ};
use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::wrappers::GetSecurityInfo;

use super::private_files::validate_handle;

#[path = "source_relative_open.rs"]
mod source_relative_open;
use source_relative_open::open_source_child;

const FILE_FLAG_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;

/// Identity captured from an open source handle, including its security state.
///
/// The legacy index is retained for existing source identity fields; equality
/// also checks the full 128-bit identifier, including on ReFS. The security
/// descriptor stays internal and is never emitted in a hook response.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceFileIdentity {
    pub volume: u64,
    pub index: u64,
    pub size: u64,
    pub modified_100ns: u64,
    pub attributes: u32,
    pub links: u64,
    volume_id: u64,
    file_id: [u8; 16],
    created_100ns: u64,
    security_descriptor: String,
}

impl SourceFileIdentity {
    fn same_directory(&self, actual: &Self) -> bool {
        self.volume_id == actual.volume_id
            && self.file_id == actual.file_id
            && self.attributes == actual.attributes
            && self.created_100ns == actual.created_100ns
            && self.security_descriptor == actual.security_descriptor
    }
}

struct ParentHandle {
    file: File,
    identity: SourceFileIdentity,
}

/// Read-only source capability that retains the complete checked ancestry.
///
/// After the root, every component opens relative to its retained parent,
/// without following reparse points or re-resolving drive aliases. Directory
/// and file handles deny write and delete sharing until this object is dropped.
/// Source files use the caller's ordinary read permissions; this API neither
/// requires a private runtime DACL nor changes an owner or ACL.
pub struct SourceFile {
    file: File,
    parents: Vec<ParentHandle>,
    path: PathBuf,
    root_path: PathBuf,
    canonical_path: PathBuf,
}

impl SourceFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let path = checked_absolute_path(path)?;
        let mut current = PathBuf::new();
        let mut root_path = PathBuf::new();
        let mut parents: Vec<ParentHandle> = Vec::new();
        let component_count = path.components().count();
        for (index, component) in path.components().enumerate() {
            current.push(component.as_os_str());
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let is_leaf = index + 1 == component_count;
            let file = if matches!(component, Component::RootDir) {
                root_path.clone_from(&current);
                open_component(&current, true)?
            } else {
                let parent = parents.last().ok_or_else(invalid_path)?;
                open_source_child(&parent.file, component.as_os_str(), !is_leaf)?
            };
            if is_leaf {
                // Content already comes from checked relative children. The
                // path spelling and the DOS root binding are additionally
                // checked before returning the retained capability.
                let canonical_path = fs::canonicalize(&path)?;
                let source = Self {
                    file,
                    parents,
                    path: path.clone(),
                    root_path,
                    canonical_path,
                };
                source.validate_path()?;
                return Ok(source);
            }
            let identity = query_identity(&file)?;
            parents.push(ParentHandle { file, identity });
        }
        Err(invalid_path())
    }

    pub fn identity(&self) -> io::Result<SourceFileIdentity> {
        validate_handle(&self.file, false)?;
        query_identity(&self.file)
    }

    /// Recheck checked ancestry and the original path while every handle lives.
    pub fn validate_path(&self) -> io::Result<()> {
        for parent in &self.parents {
            validate_handle(&parent.file, true)?;
            if !parent
                .identity
                .same_directory(&query_identity(&parent.file)?)
            {
                return Err(invalid_path());
            }
        }
        self.validate_root()?;
        if fs::canonicalize(&self.path)? != self.canonical_path {
            return Err(invalid_path());
        }
        self.validate_root()
    }

    fn validate_root(&self) -> io::Result<()> {
        // A retained filesystem handle does not freeze a DOS drive mapping.
        // Reopening only the root detects remapping without using a newly
        // resolved pathname to read source content.
        let original = self.parents.first().ok_or_else(invalid_path)?;
        let actual = open_component(&self.root_path, true)?;
        if !original.identity.same_directory(&query_identity(&actual)?) {
            return Err(invalid_path());
        }
        Ok(())
    }
}

impl Read for SourceFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

fn open_component(path: &Path, directory: bool) -> io::Result<File> {
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let file = OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(flags)
        .open(path)?;
    validate_handle(&file, directory)?;
    Ok(file)
}

fn checked_absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut components = absolute.components();
    match components.next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => return Err(invalid_path()),
    }
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(invalid_path());
    }
    let mut has_leaf = false;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid_path());
        };
        let name = name.to_string_lossy();
        if name.contains([':', '\0', '*', '?'])
            || name.ends_with(['.', ' '])
            || reserved_device_name(&name)
        {
            return Err(invalid_path());
        }
        has_leaf = true;
    }
    if !has_leaf {
        return Err(invalid_path());
    }
    Ok(absolute)
}

fn reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or_default().to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(*prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

fn query_identity(file: &File) -> io::Result<SourceFileIdentity> {
    let raw = file.as_raw_handle() as HANDLE;
    // SAFETY: Both structs contain only plain output fields, and the borrowed
    // file handle stays open throughout the synchronous metadata queries.
    let mut information = unsafe { zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(raw, &mut information) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: FILE_ID_INFO is the correctly sized output for FileIdInfo.
    let mut file_id = unsafe { zeroed::<FILE_ID_INFO>() };
    if unsafe {
        GetFileInformationByHandleEx(
            raw,
            FileIdInfo,
            &mut file_id as *mut FILE_ID_INFO as *mut _,
            size_of::<FILE_ID_INFO>() as DWORD,
        )
    } == FALSE
    {
        return Err(io::Error::last_os_error());
    }
    let security = GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| io::Error::other("source security descriptor unavailable"))?;
    if security.owner().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source owner is unavailable",
        ));
    }
    let security_descriptor = security
        .as_sddl()
        .map_err(|_| io::Error::other("source security descriptor unavailable"))?
        .to_string_lossy()
        .into_owned();
    Ok(SourceFileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        modified_100ns: (u64::from(information.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(information.ftLastWriteTime.dwLowDateTime),
        attributes: information.dwFileAttributes,
        links: u64::from(information.nNumberOfLinks),
        volume_id: file_id.VolumeSerialNumber,
        file_id: file_id.FileId.Identifier,
        created_100ns: (u64::from(information.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(information.ftCreationTime.dwLowDateTime),
        security_descriptor,
    })
}

fn invalid_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "source path binding is invalid")
}

#[cfg(test)]
#[path = "source_files_tests.rs"]
mod tests;
