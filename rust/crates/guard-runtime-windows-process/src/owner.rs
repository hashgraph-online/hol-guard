//! Who owns a file system object.

use std::path::Path;

use windows_permissions::constants::{AceFlags, AceType, SeObjectType, SecurityInformation};
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

/// Access rights that change an object or what it contains: write, append,
/// extended attributes, delete child, attributes, delete, change access,
/// take ownership, and the generic write and all rights.
const WRITE_RIGHTS: u32 = 0x0002
    | 0x0004
    | 0x0010
    | 0x0040
    | 0x0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// Whether no account other than the current user, LocalSystem or the
/// local Administrators group is allowed to change the object at `path`,
/// the Windows counterpart of a Unix mode with no group or other write
/// bit. Entries that only pass to children are skipped; a missing access
/// list grants everyone everything. `false` when the list cannot be read.
pub fn writable_only_by_trusted(path: &Path) -> bool {
    let Ok(current) = current_process_sid() else {
        return false;
    };
    let Ok(descriptor) = GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
    ) else {
        return false;
    };
    let Some(dacl) = descriptor.dacl() else {
        return false;
    };
    (0..dacl.len()).all(|index| {
        let Some(ace) = dacl.get_ace(index) else {
            return false;
        };
        if matches!(
            ace.ace_type(),
            AceType::ACCESS_DENIED_ACE_TYPE
                | AceType::ACCESS_DENIED_CALLBACK_ACE_TYPE
                | AceType::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
                | AceType::ACCESS_DENIED_OBJECT_ACE_TYPE
        ) || ace.flags().contains(AceFlags::InheritOnly)
            || ace.mask().bits() & WRITE_RIGHTS == 0
        {
            return true;
        }
        ace.sid()
            .is_some_and(|sid| trusted_owner(sid, current.as_ref()))
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
