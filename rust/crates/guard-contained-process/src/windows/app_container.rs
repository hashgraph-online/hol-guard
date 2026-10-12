use super::*;

pub struct AppContainer {
    name: Vec<u16>,
    pub(super) sid: PSID,
    closed: bool,
}

impl AppContainer {
    /// Every run uses a new SID; no network capabilities or loopback exemption
    /// are requested. Creation and LPAC process attributes are probed by launch.
    pub fn create(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid AppContainer name",
            ));
        }
        let name = wide(OsStr::new(name))?;
        let mut sid = null_mut();
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null_mut(),
                0,
                &mut sid,
            )
        };
        if status < 0 || sid.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("AppContainer creation failed: {status:#x}"),
            ));
        }
        Ok(Self {
            name,
            sid,
            closed: false,
        })
    }

    /// Grants touch only newly-created private staging objects, never the live
    /// workspace, user profile, Guard state, executable installation or host ACLs.
    pub fn grant(&self, path: &Path, writable: bool, directory: bool) -> io::Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .access_mode(0x0002_0000 | 0x0004_0000 | 0x0008_0000)
            .share_mode(1 | 2)
            .custom_flags(0x0020_0000 | if directory { 0x0200_0000 } else { 0 })
            .open(path)?;
        let metadata = file.metadata()?;
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 || metadata.is_dir() != directory {
            return Err(crate::bound_fs::changed());
        }
        let handle = file.as_raw_handle() as HANDLE;
        let mut owner: PSID = null_mut();
        let mut old_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut old_descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        struct Local(*mut std::ffi::c_void);
        impl Drop for Local {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _old = Local(old_descriptor);
        let mut entries: [EXPLICIT_ACCESS_W; 2] = unsafe { zeroed() };
        for (entry, (sid, rights)) in entries.iter_mut().zip([
            (owner, 0x001f_01ff),
            (
                self.sid,
                if writable {
                    FILE_READ_WRITE_EXECUTE
                } else {
                    FILE_READ_EXECUTE
                },
            ),
        ]) {
            entry.grfAccessPermissions = rights;
            entry.grfAccessMode = SET_ACCESS;
            entry.grfInheritance = if directory && writable { 3 } else { 0 };
            entry.Trustee.pMultipleTrustee = null_mut();
            entry.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
            entry.Trustee.ptstrName = sid.cast();
        }
        let mut acl: PACL = null_mut();
        let status = unsafe { SetEntriesInAclW(2, entries.as_mut_ptr(), null_mut(), &mut acl) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _acl = Local(acl.cast());
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // DACL grants alone do not permit a low-integrity AppContainer to write
        // medium-integrity user files. Only captured private objects are lowered.
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text: *const u16,
                revision: u32,
                descriptor: *mut PSECURITY_DESCRIPTOR,
                size: *mut u32,
            ) -> i32;
            fn GetSecurityDescriptorSacl(
                descriptor: PSECURITY_DESCRIPTOR,
                present: *mut i32,
                sacl: *mut PACL,
                defaulted: *mut i32,
            ) -> i32;
        }
        let label = wide(OsStr::new(if directory {
            "S:(ML;OICI;NW;;;LW)"
        } else {
            "S:(ML;;NW;;;LW)"
        }))?;
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                label.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _label = Local(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut sacl = null_mut();
        if unsafe { GetSecurityDescriptorSacl(descriptor, &mut present, &mut sacl, &mut defaulted) }
            == 0
            || present == 0
            || sacl.is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                0x10,
                null_mut(),
                null_mut(),
                null_mut(),
                sacl,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn close(&mut self) -> io::Result<()> {
        if !self.closed {
            let status = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            if status < 0 {
                return Err(io::Error::other(format!(
                    "AppContainer cleanup failed: {status:#x}"
                )));
            }
            self.closed = true;
        }
        Ok(())
    }
}
impl Drop for AppContainer {
    fn drop(&mut self) {
        if !self.closed {
            unsafe {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
        }
        unsafe {
            FreeSid(self.sid);
        }
    }
}
