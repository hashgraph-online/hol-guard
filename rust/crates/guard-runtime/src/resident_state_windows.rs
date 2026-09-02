use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_permissions::constants::{
    AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation,
};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::{
    GetNamedSecurityInfo, GetSecurityInfo, SetNamedSecurityInfo, SetSecurityInfo,
};
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};

fn private_descriptor(directory: bool) -> Result<LocalBox<SecurityDescriptor>, String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let owner_sddl = owner.to_string();
    let inheritance = if directory { "OICI" } else { "" };
    let descriptor_sddl =
        format!("O:{owner_sddl}D:P(A;{inheritance};FA;;;{owner_sddl})(A;{inheritance};FA;;;SY)");
    descriptor_sddl
        .parse::<LocalBox<SecurityDescriptor>>()
        .map_err(|_| "native_resident_windows_acl_build_failed".to_owned())
}

fn trusted_profile() -> Result<PathBuf, String> {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or_else(|| "native_resident_user_profile_missing".to_owned())?
        .canonicalize()
        .map_err(|_| "native_resident_user_profile_invalid".to_owned())
}

fn with_directory_binding<T, F>(
    path: &Path,
    private_root: &Path,
    private: bool,
    action: F,
) -> Result<T, String>
where
    F: FnOnce(&guard_runtime_windows_process::PrivateDirectoryBinding) -> io::Result<T>,
{
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let trusted_base = trusted_profile()?;
    let result = if private {
        let descriptor = private_descriptor(true)?;
        guard_runtime_windows_process::bind_private_directory(
            path,
            &trusted_base,
            private_root,
            &descriptor,
            |handle, _is_target, created, is_private| {
                if !is_private {
                    return Ok(());
                }
                if created {
                    verify_windows_handle(handle, owner.as_ref()).map_err(io::Error::other)
                } else {
                    repair_windows_handle(handle, true, owner.as_ref()).map_err(io::Error::other)
                }
            },
        )
    } else {
        guard_runtime_windows_process::bind_directory(
            path,
            &trusted_base,
            private_root,
            |handle, _is_target, _created, is_private| {
                if is_private {
                    repair_windows_handle(handle, true, owner.as_ref()).map_err(io::Error::other)
                } else {
                    Ok(())
                }
            },
        )
    };
    result
        .and_then(|binding| action(&binding))
        .map_err(|error| error.to_string())
}

pub(super) fn bind_windows_private_directory(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    bind_windows_private_directory_under(path, private_root)
}

pub(super) fn bind_windows_private_directory_under(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let trusted_base = trusted_profile()?;
    let descriptor = private_descriptor(true)?;
    guard_runtime_windows_process::bind_private_directory(
        path,
        &trusted_base,
        private_root,
        &descriptor,
        |handle, _is_target, created, is_private| {
            if !is_private {
                return Ok(());
            }
            if created {
                verify_windows_handle(handle, owner.as_ref()).map_err(io::Error::other)
            } else {
                repair_windows_handle(handle, true, owner.as_ref()).map_err(io::Error::other)
            }
        },
    )
    .map_err(|error| error.to_string())
}

pub(super) fn bind_windows_existing_directory(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    bind_windows_existing_directory_under(path, private_root)
}

pub(super) fn bind_windows_existing_directory_under(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let trusted_base = trusted_profile()?;
    guard_runtime_windows_process::bind_directory(
        path,
        &trusted_base,
        private_root,
        |handle, _is_target, _created, is_private| {
            if is_private {
                repair_windows_handle(handle, true, owner.as_ref()).map_err(io::Error::other)
            } else {
                Ok(())
            }
        },
    )
    .map_err(|error| error.to_string())
}

fn with_existing_directory<T, F>(path: &Path, private_root: &Path, action: F) -> Result<T, String>
where
    F: FnOnce(&guard_runtime_windows_process::PrivateDirectoryBinding) -> io::Result<T>,
{
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let trusted_base = trusted_profile()?;
    guard_runtime_windows_process::bind_directory(
        path,
        &trusted_base,
        private_root,
        |handle, _is_target, _created, is_private| {
            if is_private {
                repair_windows_handle(handle, true, owner.as_ref()).map_err(io::Error::other)
            } else {
                Ok(())
            }
        },
    )
    .and_then(|binding| action(&binding))
    .map_err(|error| error.to_string())
}

pub(super) fn ensure_private_directory_path_under(
    path: &Path,
    private_root: &Path,
    private: bool,
) -> Result<PathBuf, String> {
    with_directory_binding(path, private_root, private, |binding| {
        Ok(binding.path().to_owned())
    })
}

pub(super) fn ensure_private_directory_path(
    path: &Path,
    private_root: &Path,
    private: bool,
) -> Result<PathBuf, String> {
    ensure_private_directory_path_under(path, private_root, private)
}

pub(super) fn create_private_file(path: &Path, private_root: &Path) -> io::Result<File> {
    let descriptor = private_descriptor(false).map_err(io::Error::other)?;
    let owner = current_process_sid()
        .map_err(|_| io::Error::other("native_resident_windows_owner_sid_failed"))?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "private file parent missing")
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file name missing"))?;
    with_existing_directory(parent, private_root, |binding| {
        let file = binding.create_private_file(name, &descriptor)?;
        if let Err(error) = verify_windows_handle(&file, owner.as_ref()) {
            let _ = guard_runtime_windows_process::delete_private_file_handle(&file);
            return Err(io::Error::other(error));
        }
        Ok(file)
    })
    .map_err(io::Error::other)
}

pub(super) fn create_private_directory(path: &Path) -> io::Result<bool> {
    let binding = with_directory_binding(path, path, true, |binding| Ok(binding.created_final()))
        .map_err(io::Error::other)?;
    Ok(binding)
}

pub(super) fn open_private_file(path: &Path, private_root: &Path) -> io::Result<File> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "private file parent missing")
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file name missing"))?;
    with_existing_directory(parent, private_root, |binding| {
        binding.open_private_file(name)
    })
    .map_err(io::Error::other)
}

pub(super) fn open_private_directory(path: &Path, private_root: &Path) -> io::Result<File> {
    with_existing_directory(path, private_root, |binding| {
        let handle = binding.handle();
        handle.try_clone()
    })
    .map_err(io::Error::other)
}

pub(super) fn replace_private_file(
    temporary: &Path,
    path: &Path,
    private_root: &Path,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "native_resident_windows_replace_parent_missing".to_owned())?;
    if temporary.parent() != Some(parent) {
        return Err("native_resident_windows_replace_parent_mismatch".to_owned());
    }
    let temporary_name = temporary
        .file_name()
        .ok_or_else(|| "native_resident_windows_replace_name_missing".to_owned())?;
    let destination_name = path
        .file_name()
        .ok_or_else(|| "native_resident_windows_replace_name_missing".to_owned())?;
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    with_existing_directory(parent, private_root, |binding| {
        let source = binding.open_private_file(temporary_name)?;
        verify_windows_handle(&source, owner.as_ref()).map_err(io::Error::other)?;
        binding.replace_private_file(&source, destination_name)
    })
}

pub(super) fn remove_private_file(path: &Path, private_root: &Path) -> Result<bool, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "native_resident_windows_remove_parent_missing".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "native_resident_windows_remove_name_missing".to_owned())?;
    with_existing_directory(parent, private_root, |binding| {
        let file = match binding.open_private_file(name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        guard_runtime_windows_process::delete_private_file_handle(&file).map(|()| true)
    })
}

pub(super) fn verify_private_file(file: &File) -> Result<(), String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    verify_windows_handle(file, owner.as_ref())
}

pub(super) fn repair_private_file(file: &mut File) -> Result<(), String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    repair_windows_handle(file, false, owner.as_ref())
}

pub(super) fn repair_windows_handle<H: AsRawHandle>(
    handle: &mut H,
    directory: bool,
    owner: &Sid,
) -> Result<(), String> {
    verify_windows_handle_owner(handle, owner)?;
    let descriptor = private_descriptor(directory)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| "native_resident_windows_acl_build_failed".to_owned())?;
    SetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(|_| "native_resident_windows_acl_apply_failed".to_owned())?;
    verify_windows_handle(handle, owner)
}

pub(super) fn protect_windows_path(path: &Path, directory: bool) -> Result<(), String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    verify_windows_path_owner(path, &owner)?;
    let descriptor = private_descriptor(directory)?;
    let dacl = descriptor
        .dacl()
        .ok_or_else(|| "native_resident_windows_acl_build_failed".to_owned())?;
    SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        Some(dacl),
        None,
    )
    .map_err(|_| "native_resident_windows_acl_apply_failed".to_owned())?;

    verify_windows_path(path, &owner)
}

fn verify_windows_path_owner(path: &Path, owner: &Sid) -> Result<(), String> {
    let applied = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
    )
    .map_err(|_| "native_resident_windows_acl_verify_failed".to_owned())?;
    verify_windows_owner(&applied, owner)
}

fn verify_windows_handle_owner<H: AsRawHandle>(handle: &H, owner: &Sid) -> Result<(), String> {
    let applied = GetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
    )
    .map_err(|_| "native_resident_windows_acl_verify_failed".to_owned())?;
    verify_windows_owner(&applied, owner)
}

pub(super) fn verify_windows_path(path: &Path, owner: &Sid) -> Result<(), String> {
    let applied = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner | SecurityInformation::ProtectedDacl,
    )
    .map_err(|_| "native_resident_windows_acl_verify_failed".to_owned())?;
    verify_windows_descriptor(&applied, owner)
}

pub(super) fn verify_windows_handle<H: std::os::windows::io::AsRawHandle>(
    handle: &H,
    owner: &Sid,
) -> Result<(), String> {
    let applied = GetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::Owner | SecurityInformation::ProtectedDacl,
    )
    .map_err(|_| "native_resident_windows_acl_verify_failed".to_owned())?;
    verify_windows_descriptor(&applied, owner)
}

fn windows_owner_is_trusted(
    applied_owner: &Sid,
    owner: &Sid,
    system: &Sid,
    administrators: &Sid,
) -> bool {
    applied_owner == owner || applied_owner == system || applied_owner == administrators
}

fn verify_windows_descriptor(applied: &SecurityDescriptor, owner: &Sid) -> Result<(), String> {
    verify_windows_owner(applied, owner)?;
    let system = "S-1-5-18"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| "native_resident_windows_system_sid_failed".to_owned())?;
    let administrators = "S-1-5-32-544"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| "native_resident_windows_administrators_sid_failed".to_owned())?;
    let applied_owner = applied
        .owner()
        .ok_or_else(|| "native_resident_windows_acl_verify_failed".to_owned())?;
    if !windows_owner_is_trusted(
        applied_owner,
        owner,
        system.as_ref(),
        administrators.as_ref(),
    ) {
        return Err("native_resident_windows_acl_not_private".to_owned());
    }
    let sddl = applied
        .as_sddl()
        .map_err(|_| "native_resident_windows_acl_verify_failed".to_owned())?;
    if !sddl.to_string_lossy().contains("D:P") {
        return Err("native_resident_windows_acl_not_private".to_owned());
    }
    let applied_dacl = applied
        .dacl()
        .ok_or_else(|| "native_resident_windows_acl_verify_failed".to_owned())?;
    let mut owner_allowed = false;
    let mut system_allowed = false;
    for index in 0..applied_dacl.len() {
        let ace = applied_dacl
            .get_ace(index)
            .ok_or_else(|| "native_resident_windows_acl_verify_failed".to_owned())?;
        if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
            || !ace.mask().contains(AccessRights::FileAllAccess)
            || ace.flags().contains(AceFlags::Inherited)
        {
            return Err("native_resident_windows_acl_not_private".to_owned());
        }
        let sid = ace
            .sid()
            .ok_or_else(|| "native_resident_windows_acl_not_private".to_owned())?;
        if sid == owner {
            owner_allowed = true;
        } else if sid == system.as_ref() {
            system_allowed = true;
        } else {
            return Err("native_resident_windows_acl_not_private".to_owned());
        }
    }
    if !owner_allowed || (!system_allowed && owner != system.as_ref()) {
        return Err("native_resident_windows_acl_not_private".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_owner_allowlist_rejects_unrelated_principals() {
        let owner = "S-1-5-21-1-2-3-1001".parse::<LocalBox<Sid>>().unwrap();
        let system = "S-1-5-18".parse::<LocalBox<Sid>>().unwrap();
        let administrators = "S-1-5-32-544".parse::<LocalBox<Sid>>().unwrap();
        let unrelated = "S-1-5-21-4-5-6-1002".parse::<LocalBox<Sid>>().unwrap();

        for applied_owner in [owner.as_ref(), system.as_ref(), administrators.as_ref()] {
            assert!(windows_owner_is_trusted(
                applied_owner,
                owner.as_ref(),
                system.as_ref(),
                administrators.as_ref(),
            ));
        }
        assert!(!windows_owner_is_trusted(
            unrelated.as_ref(),
            owner.as_ref(),
            system.as_ref(),
            administrators.as_ref(),
        ));
    }
fn verify_windows_owner(applied: &SecurityDescriptor, owner: &Sid) -> Result<(), String> {
    let system = "S-1-5-18"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| "native_resident_windows_system_sid_failed".to_owned())?;
    let administrators = "S-1-5-32-544"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| "native_resident_windows_administrators_sid_failed".to_owned())?;
    let applied_owner = applied
        .owner()
        .ok_or_else(|| "native_resident_windows_acl_verify_failed".to_owned())?;
    if !windows_owner_is_trusted(
        applied_owner,
        owner,
        system.as_ref(),
        administrators.as_ref(),
    ) {
        return Err("native_resident_windows_acl_not_private".to_owned());
    }
    Ok(())
}
