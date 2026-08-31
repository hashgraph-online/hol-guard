use std::path::Path;
use windows_permissions::constants::{
    AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation,
};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::{GetNamedSecurityInfo, GetSecurityInfo, SetNamedSecurityInfo};
use windows_permissions::{LocalBox, SecurityDescriptor, Sid};

pub(super) fn protect_windows_path(path: &Path, directory: bool) -> Result<(), String> {
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    let owner_sddl = owner.to_string();
    let inheritance = if directory { "OICI" } else { "" };
    let descriptor_sddl =
        format!("D:P(A;{inheritance};FA;;;{owner_sddl})(A;{inheritance};FA;;;SY)");
    let descriptor = descriptor_sddl
        .parse::<LocalBox<SecurityDescriptor>>()
        .map_err(|_| "native_resident_windows_acl_build_failed".to_owned())?;
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

fn verify_windows_descriptor(applied: &SecurityDescriptor, owner: &Sid) -> Result<(), String> {
    let system = "S-1-5-18"
        .parse::<LocalBox<Sid>>()
        .map_err(|_| "native_resident_windows_system_sid_failed".to_owned())?;
    if applied.owner() != Some(owner) {
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
