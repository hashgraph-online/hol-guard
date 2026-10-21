//! Who owns a file system object.

use std::path::Path;

use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::GetNamedSecurityInfo;
use windows_permissions::{LocalBox, Sid};

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
