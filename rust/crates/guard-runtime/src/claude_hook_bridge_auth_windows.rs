//! The Windows half of the bridge's private-file check.
//!
//! Python writes the bridge token and the discovery key with the ACL the
//! Guard home passes down, so a protected owner-only DACL is not required.
//! What is required is what the POSIX owner-only check means: the file and
//! the Guard home belong to the current user (or to SYSTEM or
//! Administrators, which can read every file anyway), and no entry that
//! applies to them grants access to anyone else. Every path component is
//! opened without following a link, the Guard home and its ancestors stay
//! open until the file is, and the bytes are read from the handle that was
//! checked.

use std::fs::File;
use std::io;
use std::path::Path;

use windows_permissions::constants::{AceFlags, AceType, SeObjectType, SecurityInformation};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::GetSecurityInfo;
use windows_permissions::{LocalBox, Sid};

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// Why a handle failed the check, so the caller can word the error the way
/// the POSIX check does.
enum Refusal {
    Unreadable,
    Owner,
    Access,
}

/// The principals trusted to own or reach a private file.
struct Trusted {
    user: LocalBox<Sid>,
    system: LocalBox<Sid>,
    administrators: LocalBox<Sid>,
}

impl Trusted {
    fn current() -> Option<Self> {
        Some(Self {
            user: current_process_sid().ok()?,
            system: SYSTEM_SID.parse().ok()?,
            administrators: ADMINISTRATORS_SID.parse().ok()?,
        })
    }

    fn contains(&self, sid: &Sid) -> bool {
        sid == &*self.user || sid == &*self.system || sid == &*self.administrators
    }
}

/// Open `path` for reading once it and its directory pass the check.
pub(crate) fn open_private_file(path: &Path, label: &str) -> Result<File, String> {
    let unavailable = || format!("{label} is unavailable");
    let parent = path.parent().ok_or_else(unavailable)?;
    // Holding the Guard home's ancestry open without delete sharing keeps
    // every component in place until the file below it is open.
    let home = guard_runtime_windows_process::bind_readonly_directory(parent).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            "Guard home is not a directory".to_owned()
        } else {
            unavailable()
        }
    })?;
    let file =
        guard_runtime_windows_process::open_bound_replaceable_file(path).map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                format!("{label} must be a regular file")
            } else {
                unavailable()
            }
        })?;
    let trusted = Trusted::current().ok_or_else(unavailable)?;
    for handle in [home.handle(), &file] {
        match verify(handle, &trusted) {
            Ok(()) => {}
            Err(Refusal::Unreadable) => return Err(format!("{label} is unreadable")),
            Err(Refusal::Owner) => {
                return Err(format!("{label} ownership does not match the current user"))
            }
            Err(Refusal::Access) => return Err(format!("{label} permissions are not owner-only")),
        }
    }
    Ok(file)
}

fn verify(handle: &File, trusted: &Trusted) -> Result<(), Refusal> {
    let descriptor = GetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|_| Refusal::Unreadable)?;
    let owner = descriptor.owner().ok_or(Refusal::Owner)?;
    if !trusted.contains(owner) {
        return Err(Refusal::Owner);
    }
    // A missing DACL grants everyone full access.
    let dacl = descriptor.dacl().ok_or(Refusal::Access)?;
    for index in 0..dacl.len() {
        let ace = dacl.get_ace(index).ok_or(Refusal::Unreadable)?;
        // An inherit-only entry applies to children, not to this object.
        if ace.flags().contains(AceFlags::InheritOnly) {
            continue;
        }
        match ace.ace_type() {
            AceType::ACCESS_DENIED_ACE_TYPE => {}
            AceType::ACCESS_ALLOWED_ACE_TYPE => {
                let sid = ace.sid().ok_or(Refusal::Access)?;
                if !trusted.contains(sid) {
                    return Err(Refusal::Access);
                }
            }
            // Conditional, object and callback entries are not expected on
            // these files, and none of them can be judged safely here.
            _ => return Err(Refusal::Access),
        }
    }
    Ok(())
}
