use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix, PrefixComponent};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::fileapi::{CreateDirectoryW, GetLongPathNameW};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_permissions::SecurityDescriptor;

use super::file_identity::file_information;
use super::private_files::{
    create_private_file as create_path_private_file, mark_handle_for_delete, open_directory_bound,
    open_inspect_private_file, open_raw, open_raw_directory_bound, open_rename_directory,
    rename_into_directory, validate_handle, verify_private_file,
};
use super::MAX_PATH;

const ERROR_ALREADY_EXISTS: i32 = 183;

/// Directory handles held from every component of a checked path.
///
/// The handles are deliberately retained rather than replaced by a
/// canonicalized pathname. A caller can therefore create/open children and
/// commit a replacement while the checked ancestry remains open and denies
/// delete/rename sharing.
pub struct PrivateDirectoryBinding {
    path: PathBuf,
    handles: Vec<std::fs::File>,
    created_final: bool,
}

impl PrivateDirectoryBinding {
    /// Return the normalized path represented by this binding.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the final directory handle while the binding is alive.
    pub fn handle(&self) -> &std::fs::File {
        self.handles
            .last()
            .expect("a directory binding always contains its final component")
    }

    /// Report whether the requested final directory was created by this
    /// binding operation.
    pub fn created_final(&self) -> bool {
        self.created_final
    }

    /// Create a private child file while this directory ancestry is held.
    pub fn create_private_file(
        &self,
        name: &OsStr,
        security_descriptor: &SecurityDescriptor,
    ) -> io::Result<std::fs::File> {
        create_path_private_file(&self.child_path(name)?, security_descriptor)
    }

    /// Open a regular child file while this directory ancestry is held.
    pub fn open_private_file(&self, name: &OsStr) -> io::Result<std::fs::File> {
        let file = open_raw(
            &self.child_path(name)?,
            false,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )?;
        validate_handle(&file, false)?;
        verify_private_file(&file)?;
        Ok(file)
    }

    /// Atomically replace a child with an already-written private file.
    ///
    /// Windows cannot rename a child while this directory remains open without
    /// delete sharing. The exclusive final handle is closed only for the
    /// rename syscall, then the barrier is re-opened on the same path.
    pub fn replace_private_file(
        &mut self,
        source: &std::fs::File,
        destination: &OsStr,
    ) -> io::Result<()> {
        let destination_path = self.child_path(destination)?;
        validate_handle(source, false)?;
        verify_private_file(source)?;
        match open_inspect_private_file(&destination_path) {
            Ok(existing) => drop(existing),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        drop(
            self.handles
                .pop()
                .expect("a directory binding always contains its final component"),
        );
        let renamed = open_rename_directory(&self.path).and_then(|rename_parent| {
            let renamed = rename_into_directory(&rename_parent, source, destination);
            drop(rename_parent);
            renamed
        });
        self.handles
            .push(open_directory_bound(&self.path, false, true)?);
        renamed?;
        let committed = open_inspect_private_file(&destination_path)?;
        if file_information(source.as_raw_handle() as winapi::shared::ntdef::HANDLE)?
            != file_information(committed.as_raw_handle() as winapi::shared::ntdef::HANDLE)?
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "committed private file identity changed",
            ));
        }
        verify_private_file(&committed)
    }

    fn child_path(&self, name: &OsStr) -> io::Result<PathBuf> {
        let child = Path::new(name);
        if child.is_absolute()
            || child
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private child name must be one normal path component",
            ));
        }
        Ok(self.path.join(child))
    }
}

/// Bind an existing or newly-created directory tree.
///
/// `trusted_base` identifies the prefix whose components are trusted only for
/// directory type and reparse-point checks. `private_root` must be at or below
/// that prefix and at or below it every component is passed to `verify` with
/// `is_private` set. The callback therefore owns the platform-specific owner
/// and private-DACL check while this module owns the ancestry and type barrier.
pub fn bind_private_directory<F>(
    path: &Path,
    trusted_base: &Path,
    private_root: &Path,
    security_descriptor: &SecurityDescriptor,
    verify: F,
) -> io::Result<PrivateDirectoryBinding>
where
    F: FnMut(&mut std::fs::File, bool, bool, bool) -> io::Result<()>,
{
    bind_directory_impl(
        path,
        trusted_base,
        private_root,
        Some(security_descriptor),
        verify,
    )
}

/// Bind an existing directory tree without changing its ACL.
pub fn bind_directory<F>(
    path: &Path,
    trusted_base: &Path,
    private_root: &Path,
    verify: F,
) -> io::Result<PrivateDirectoryBinding>
where
    F: FnMut(&mut std::fs::File, bool, bool, bool) -> io::Result<()>,
{
    bind_directory_impl(path, trusted_base, private_root, None, verify)
}

fn bind_directory_impl<F>(
    path: &Path,
    trusted_base: &Path,
    private_root: &Path,
    security_descriptor: Option<&SecurityDescriptor>,
    mut verify: F,
) -> io::Result<PrivateDirectoryBinding>
where
    F: FnMut(&mut std::fs::File, bool, bool, bool) -> io::Result<()>,
{
    let path = normalize_absolute_path(path)?;
    let trusted_base = normalize_absolute_path(trusted_base)?;
    let private_root = normalize_absolute_path(private_root)?;
    validate_boundary(&path, &trusted_base, &private_root)?;

    let mut final_component = None;
    for (index, component) in path.components().enumerate() {
        if matches!(component, Component::Normal(_)) {
            final_component = Some(index);
        }
    }
    let final_component = final_component.expect("the path was checked for a normal component");
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    let mut created_indices = Vec::new();
    let mut created_final = false;
    let mut bound_path = path.clone();
    for (index, component) in path.components().enumerate() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => unreachable!("parent components were rejected"),
            Component::Normal(name) => {
                current.push(name);
                let is_target = index == final_component;
                let is_private = path_has_prefix(&current, &private_root);
                let mut reopen_path = current.clone();
                let (mut handle, created) = match open_directory_bound(&current, false, is_target) {
                    Ok(handle) => (handle, false),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        if let Some((handle, opened)) =
                            open_equivalent_directory(&current, is_target)
                        {
                            reopen_path = opened;
                            (handle, false)
                        } else {
                            let Some(descriptor) = security_descriptor else {
                                cleanup_created_components(&handles, &created_indices, None);
                                return Err(io::Error::new(
                                    io::ErrorKind::NotFound,
                                    if is_private {
                                        "private directory ancestry is missing"
                                    } else {
                                        "trusted directory ancestry is missing"
                                    },
                                ));
                            };
                            if !is_private {
                                cleanup_created_components(&handles, &created_indices, None);
                                return Err(io::Error::new(
                                    io::ErrorKind::NotFound,
                                    "trusted directory ancestry is missing",
                                ));
                            }
                            let (handle, created) =
                                match create_private_directory_handle(&current, descriptor) {
                                    Ok(result) => result,
                                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                                        match open_directory_bound(&current, false, is_target) {
                                            Ok(handle) => (handle, false),
                                            Err(error) => {
                                                cleanup_created_components(
                                                    &handles,
                                                    &created_indices,
                                                    None,
                                                );
                                                return Err(error);
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        cleanup_created_components(
                                            &handles,
                                            &created_indices,
                                            None,
                                        );
                                        return Err(error);
                                    }
                                };
                            (handle, created)
                        }
                    }
                    Err(error) => {
                        cleanup_created_components(&handles, &created_indices, None);
                        return Err(error);
                    }
                };
                if is_target {
                    created_final = created;
                }
                if let Err(error) = verify(&mut handle, is_target, created, is_private) {
                    if is_private && !created {
                        drop(handle);
                        match durable_private_directory_handle(
                            &reopen_path,
                            is_target,
                            is_private,
                            &mut verify,
                        ) {
                            Ok(durable) => handle = durable,
                            Err(error) => {
                                cleanup_created_components(&handles, &created_indices, None);
                                return Err(error);
                            }
                        }
                    } else {
                        cleanup_created_components(
                            &handles,
                            &created_indices,
                            created.then_some(&handle),
                        );
                        return Err(error);
                    }
                }
                if created {
                    created_indices.push(handles.len());
                }
                if is_target {
                    bound_path = reopen_path;
                }
                handles.push(handle);
            }
        }
    }
    Ok(PrivateDirectoryBinding {
        path: bound_path,
        handles,
        created_final,
    })
}

fn verified_directory_handle<F>(
    path: &Path,
    allow_acl_repair: bool,
    is_target: bool,
    is_private: bool,
    verify: &mut F,
) -> io::Result<std::fs::File>
where
    F: FnMut(&mut std::fs::File, bool, bool, bool) -> io::Result<()>,
{
    let mut handle = open_directory_bound(path, allow_acl_repair, is_target)?;
    verify(&mut handle, is_target, false, is_private)?;
    Ok(handle)
}

/// Repair may require WRITE_DAC, but a live barrier must not keep that right.
/// Overlapping client/serve binds fail closed when any handle still has it.
fn durable_private_directory_handle<F>(
    path: &Path,
    is_target: bool,
    is_private: bool,
    verify: &mut F,
) -> io::Result<std::fs::File>
where
    F: FnMut(&mut std::fs::File, bool, bool, bool) -> io::Result<()>,
{
    let repaired = verified_directory_handle(path, true, is_target, is_private, verify)?;
    drop(repaired);
    verified_directory_handle(path, false, is_target, is_private, verify)
}

/// Delete only directories created by this binding, in reverse ancestry order.
/// Cleanup is deliberately best effort: the operation that failed remains the
/// authoritative error, while pre-existing directories are never touched.
fn cleanup_created_components(
    handles: &[std::fs::File],
    created_indices: &[usize],
    current: Option<&std::fs::File>,
) {
    if let Some(handle) = current {
        let _ = mark_handle_for_delete(handle);
    }
    for index in created_indices.iter().rev() {
        let _ = mark_handle_for_delete(&handles[*index]);
    }
}

fn normalize_absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path cannot contain parent components",
                ))
            }
            Component::CurDir => {}
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir | Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    // Windows can represent the same path with different prefixes (for
    // example, `C:\\...` versus the `\\\\?\\C:\\...` form returned by
    // `canonicalize`). Resolve the existing portion of every input so the
    // boundary check compares equivalent path representations. The final
    // private directory may not exist yet, so retain any missing tail.
    canonicalize_existing_prefix(&normalized)
}

fn canonicalize_existing_prefix(path: &Path) -> io::Result<PathBuf> {
    let mut existing = path.to_owned();
    let mut missing_tail = Vec::new();

    let canonical_existing = loop {
        match existing.canonicalize() {
            Ok(canonical) => {
                break long_path_if_same_shape(&win32_path(&canonical)).unwrap_or(canonical);
            }
            Err(error) => {
                // `\\?\` disables 8.3 expansion, so canonicalize returns
                // NotFound for an existing short name. GetLongPathNameW on
                // the Win32 form still resolves it when the component count
                // is unchanged. A junction that changes depth still fails.
                if let Some(long) = long_path_if_same_shape(&win32_path(&existing)) {
                    break long;
                }
                let Some(name) = existing.file_name() else {
                    return Err(error);
                };
                missing_tail.push(name.to_owned());
                let Some(parent) = existing.parent() else {
                    return Err(error);
                };
                if parent == existing {
                    return Err(error);
                }
                existing = parent.to_owned();
            }
        }
    };

    let verbatim = canonical_existing
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\");
    let mut canonical = if missing_tail.is_empty() {
        canonical_existing
    } else {
        win32_path(&canonical_existing)
    };
    for component in missing_tail.iter().rev() {
        canonical.push(existing_alias_or_name(&canonical, component));
    }
    if verbatim && !missing_tail.is_empty() {
        // A successful canonicalize restores the verbatim form. If it fails,
        // keep the Win32 spelling: re-adding `\\?\` disables 8.3 expansion
        // and makes an existing short-name tail look missing.
        if let Ok(resolved) = std::fs::canonicalize(&canonical) {
            canonical = resolved;
        }
    }
    if let Some(long) = long_path_if_same_shape(&win32_path(&canonical)) {
        canonical = long;
    }
    Ok(extended_path_if_long(&canonical))
}

fn existing_alias_or_name(parent: &Path, name: &OsStr) -> std::ffi::OsString {
    let candidate = win32_path(parent).join(name);
    let Some(long) = long_path_if_same_shape(&candidate) else {
        return name.to_owned();
    };
    let Some(long_name) = long.file_name() else {
        return name.to_owned();
    };
    let Some(long_parent) = long.parent() else {
        return name.to_owned();
    };
    if path_has_prefix(long_parent, &win32_path(parent))
        && path_has_prefix(&win32_path(parent), long_parent)
    {
        long_name.to_owned()
    } else {
        name.to_owned()
    }
}

fn win32_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_owned()
}

fn long_path_if_same_shape(path: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let mut buffer = vec![0u16; 512];
    let mut length =
        unsafe { GetLongPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if length as usize > buffer.len() {
        buffer.resize(length as usize, 0);
        length =
            unsafe { GetLongPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    }
    if length == 0 || length as usize > buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    let long = PathBuf::from(std::ffi::OsString::from_wide(&buffer));
    if !long.is_absolute() || long.components().count() != path.components().count() {
        return None;
    }
    Some(long)
}

fn extended_path_if_long(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let path = win32_path(path);
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.len() < MAX_PATH {
        return path;
    }
    let mut extended = Vec::with_capacity(wide.len() + 8);
    if wide.starts_with(&[92, 92]) {
        extended.extend_from_slice(&[92, 92, 63, 92, 85, 78, 67, 92]);
        extended.extend_from_slice(&wide[2..]);
    } else {
        extended.extend_from_slice(&[92, 92, 63, 92]);
        extended.extend_from_slice(&wide);
    }
    PathBuf::from(std::ffi::OsString::from_wide(&extended))
}

/// Open the same directory under a spelling CreateFileW can resolve.
///
/// `\\?\` disables 8.3 expansion, so an existing short name returns
/// NotFound. The Win32 form and a same-shape long path are the only
/// retries. A junction that changes depth is rejected by the long-path check.
fn open_equivalent_directory(
    path: &Path,
    allow_add_file: bool,
) -> Option<(std::fs::File, PathBuf)> {
    let win32 = win32_path(path);
    if win32 != path {
        if let Ok(handle) = open_directory_bound(&win32, false, allow_add_file) {
            return Some((handle, win32));
        }
    }
    let long = long_path_if_same_shape(&win32)?;
    if long == path || long == win32 {
        return None;
    }
    open_directory_bound(&long, false, allow_add_file)
        .ok()
        .map(|handle| (handle, long))
}
/// True when `path` is `root` or a descendant. `\\?\` and Win32 spellings name
/// the same directory. A long-path lookup is accepted only when it keeps the
/// same component count, so a junction to another depth still fails.
pub fn path_is_within(path: &Path, root: &Path) -> bool {
    if path_has_prefix(path, root) {
        return true;
    }
    let Some(long_path) = long_path_if_same_shape(&win32_path(path)) else {
        return false;
    };
    path_has_prefix(&long_path, root) || path_has_prefix(&long_path, &win32_path(root))
}

fn validate_boundary(path: &Path, trusted_base: &Path, private_root: &Path) -> io::Result<()> {
    if !path.is_absolute() || !trusted_base.is_absolute() || !private_root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory binding paths must be absolute",
        ));
    }
    if !path_has_prefix(private_root, trusted_base) || !path_has_prefix(path, private_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory binding path is outside its trusted private boundary",
        ));
    }
    if !path
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory path has no directory component",
        ));
    }
    if !private_root
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory boundary has no directory component",
        ));
    }
    Ok(())
}

fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    let path_components = boundary_components(path);
    let prefix_components = boundary_components(prefix);
    if prefix_components.len() > path_components.len() {
        return false;
    }
    path_components
        .iter()
        .zip(prefix_components.iter())
        .all(|(actual, expected)| boundary_component_eq(actual, expected))
}

fn boundary_components(path: &Path) -> Vec<Component<'_>> {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect()
}

/// Win32 canonical forms name the same directory with different prefixes
/// (`C:\` vs `\\?\C:\`, `\\server\share` vs `\\?\UNC\server\share`) and with
/// filesystem case. Guard homes are created by this process; a case variant is
/// the same NTFS directory, not a sibling escape. `..` is rejected earlier.
fn os_eq_ignore_ascii_case(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn boundary_component_eq(actual: &Component<'_>, expected: &Component<'_>) -> bool {
    match (actual, expected) {
        (Component::Prefix(left), Component::Prefix(right)) => windows_prefix_eq(left, right),
        (Component::RootDir, Component::RootDir) => true,
        (Component::Normal(left), Component::Normal(right)) => os_eq_ignore_ascii_case(left, right),
        _ => false,
    }
}

fn windows_prefix_eq(left: &PrefixComponent<'_>, right: &PrefixComponent<'_>) -> bool {
    if windows_prefix_kind_eq(left.kind(), right.kind()) {
        return true;
    }
    os_eq_ignore_ascii_case(left.as_os_str(), right.as_os_str())
}

fn windows_prefix_kind_eq(left: Prefix<'_>, right: Prefix<'_>) -> bool {
    let left_disk = match left {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
        _ => None,
    };
    let right_disk = match right {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
        _ => None,
    };
    if let (Some(left_letter), Some(right_letter)) = (left_disk, right_disk) {
        return left_letter.eq_ignore_ascii_case(&right_letter);
    }
    let left_unc = match left {
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => Some((server, share)),
        _ => None,
    };
    let right_unc = match right {
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => Some((server, share)),
        _ => None,
    };
    if let (Some((left_server, left_share)), Some((right_server, right_share))) =
        (left_unc, right_unc)
    {
        return os_eq_ignore_ascii_case(left_server, right_server)
            && os_eq_ignore_ascii_case(left_share, right_share);
    }
    false
}

/// Create one owner-private directory with its security descriptor applied at
/// creation time. Returns whether this call created the directory.
pub fn create_private_directory(
    path: &Path,
    security_descriptor: &SecurityDescriptor,
) -> io::Result<bool> {
    match create_private_directory_handle(path, security_descriptor) {
        Ok((_directory, created)) => Ok(created),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}

fn create_private_directory_handle(
    path: &Path,
    security_descriptor: &SecurityDescriptor,
) -> io::Result<(std::fs::File, bool)> {
    let path_w = super::wide_path(path)?;
    let mut security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: security_descriptor as *const _ as *mut _,
        bInheritHandle: FALSE,
    };
    // SAFETY: The path is NUL-terminated; SECURITY_ATTRIBUTES and its
    // descriptor remain valid through the synchronous CreateDirectoryW call.
    if unsafe { CreateDirectoryW(path_w.as_ptr(), &mut security) } != FALSE {
        // A failed reopen has no verified handle to bind cleanup to. Retain
        // the owner-private directory for recovery; never issue a path-based
        // delete after creation, even while the parent binding is held.
        let directory = open_raw_directory_bound(path, true, true, true)?;
        if let Err(error) = validate_handle(&directory, true) {
            // Once the handle exists, cleanup is handle-bound and cannot be
            // redirected by a pathname replacement.
            let _ = mark_handle_for_delete(&directory);
            return Err(error);
        }
        return Ok((directory, true));
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, error));
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_disk_prefix_matches_drive_prefix() {
        let path = Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\home\native-runtime");
        let prefix = Path::new(r"C:\Users\runneradmin\AppData\Local\Temp\home");
        assert!(path_has_prefix(path, prefix));
        assert!(path_has_prefix(
            prefix,
            Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\home")
        ));
    }

    #[test]
    fn windows_prefix_compare_is_case_insensitive_and_rejects_siblings() {
        let path = Path::new(r"\\?\C:\Users\RUNNERADMIN\AppData\Local\Temp\Home");
        let prefix = Path::new(r"c:\users\runneradmin\appdata\local\temp\home");
        assert!(path_has_prefix(path, prefix));
        assert!(!path_has_prefix(
            Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\other"),
            Path::new(r"C:\Users\runneradmin\AppData\Local\Temp\home")
        ));
    }

    #[test]
    fn verbatim_unc_prefix_matches_unc_prefix() {
        let path = Path::new(r"\\?\UNC\server\share\home\native-runtime");
        let prefix = Path::new(r"\\server\share\home");
        assert!(path_has_prefix(path, prefix));
        assert!(!path_has_prefix(path, Path::new(r"\\other\share\home")));
    }
    #[test]
    fn win32_child_is_within_verbatim_root() {
        let root = Path::new(r"\\?\C:\Users\runneradmin\AppData\Local\Temp\home");
        let child = Path::new(r"C:\Users\runneradmin\AppData\Local\Temp\home\native-runtime");
        assert!(path_is_within(child, root));
        assert!(!path_is_within(
            Path::new(r"C:\Users\runneradmin\AppData\Local\Temp\other"),
            root
        ));
    }

    #[test]
    fn verbatim_existing_directory_binds() {
        let directory = std::env::temp_dir().join(format!("hg-bind-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let display = directory.display().to_string();
        let verbatim = PathBuf::from(format!(r"\\?\{display}"));
        let binding = bind_directory(&verbatim, &directory, &directory, |_, _, _, _| Ok(()));
        let _ = std::fs::remove_dir_all(&directory);
        binding.expect("verbatim spelling of an existing directory opens");
    }
}
