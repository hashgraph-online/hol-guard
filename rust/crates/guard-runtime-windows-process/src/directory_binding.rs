use std::ffi::OsStr;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};

use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::fileapi::CreateDirectoryW;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::winnt::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows_permissions::SecurityDescriptor;

use super::private_files::{
    create_private_file as create_path_private_file, file_information, mark_handle_for_delete,
    open_directory_bound, open_inspect_private_file, open_raw, open_raw_directory_bound,
    open_rename_directory, rename_into_directory, validate_handle, verify_private_file,
};

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
                let (mut handle, created) = match open_directory_bound(&current, false, is_target) {
                    Ok(handle) => (handle, false),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
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
                                    cleanup_created_components(&handles, &created_indices, None);
                                    return Err(error);
                                }
                            };
                        (handle, created)
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
                            &current,
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
                handles.push(handle);
            }
        }
    }
    Ok(PrivateDirectoryBinding {
        path,
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
            Ok(canonical) => break canonical,
            Err(error) => {
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

    let mut canonical = canonical_existing;
    for component in missing_tail.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
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
    let mut path_components = path.components();
    for expected in prefix.components() {
        let Some(actual) = path_components.next() else {
            return false;
        };
        if actual.as_os_str() != expected.as_os_str() {
            return false;
        }
    }
    true
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
