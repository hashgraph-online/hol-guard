//! Who owns a file system object.

use std::path::Path;

use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::GetNamedSecurityInfo;
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};

/// Whether `applied` is the current user, LocalSystem or the local
/// Administrators group. Windows Server makes the Administrators group the
/// owner of what an administrator creates; LocalSystem and Administrators can
/// already rewrite anything the user owns.
pub(crate) fn trusted_owner(applied: &Sid, current: &Sid) -> bool {
    applied == current
        || ["S-1-5-18", "S-1-5-32-544"].iter().any(|sid| {
            sid.parse::<LocalBox<Sid>>()
                .is_ok_and(|trusted| applied == trusted.as_ref())
        })
}

/// Whether the object at `path` is owned by the current user, the Windows
/// counterpart of comparing a Unix `st_uid` with `getuid()`. `false` when the
/// owner cannot be read.
pub fn owned_by_current_user(path: &Path) -> bool {
    let Ok(current) = current_process_sid() else {
        return false;
    };
    GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner,
    )
    .ok()
    .is_some_and(|descriptor| {
        descriptor
            .owner()
            .is_some_and(|owner| trusted_owner(owner, current.as_ref()))
    })
}

/// Create `path` owned by the current user with a protected access list
/// that grants only that user, inherited by everything created inside. An
/// elevated token would otherwise make the Administrators group the owner.
/// Returns whether this call created the directory.
pub fn create_owner_only_directory(path: &Path) -> std::io::Result<bool> {
    let user = current_process_sid()?.to_string();
    let descriptor = format!("O:{user}D:P(A;OICI;FA;;;{user})")
        .parse::<LocalBox<SecurityDescriptor>>()
        .map_err(std::io::Error::other)?;
    crate::create_private_directory(path, &descriptor)
}
