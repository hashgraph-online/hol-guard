use super::*;

#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[repr(C)]
struct RenameInfo {
    replace: u8,
    root: HANDLE,
    length: u32,
    name: [u16; 1],
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSetInformationFile(
        file: HANDLE,
        status: *mut IoStatus,
        information: *mut std::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
}
pub(crate) fn rename_bound(
    source: &File,
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    replace: bool,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let root = std::fs::OpenOptions::new()
        .access_mode(0x0010_0082)
        .share_mode(1 | 2 | 4)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(parent.path())?;
    if guard_runtime_windows_process::handle_file_id(&root)?
        != guard_runtime_windows_process::handle_file_id(parent.handle())?
    {
        return Err(crate::bound_fs::changed());
    }
    let name = wide(name)?;
    let name = &name[..name.len() - 1];
    let offset = std::mem::offset_of!(RenameInfo, name);
    let length = offset + name.len() * 2;
    let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
    let information = storage.as_mut_ptr().cast::<RenameInfo>();
    unsafe {
        (*information).replace = u8::from(replace);
        (*information).root = root.as_raw_handle() as HANDLE;
        (*information).length = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            information.cast::<u8>().add(offset).cast(),
            name.len(),
        );
    }
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let result = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut status,
            information.cast(),
            length as u32,
            10,
        )
    };
    if result < 0 {
        return Err(io::Error::other(format!(
            "bound output rename failed: {result:#x}"
        )));
    }
    parent.verify()
}

fn transaction_file(path: &Path, write: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    let access = 0x8000_0000 | 0x0001_0000 | if write { 0x4000_0000 } else { 0 };
    // DELETE authority is on this opened object. With no WRITE/DELETE sharing,
    // third-party target mutation/rename cannot change the object we move.
    let file = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    use std::os::windows::fs::MetadataExt;
    if !file.metadata()?.is_file() || file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(crate::bound_fs::changed());
    }
    Ok(file)
}
fn delete_object(file: &File) -> io::Result<()> {
    let mut delete = 1u8;
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let result = unsafe {
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut status,
            (&mut delete as *mut u8).cast(),
            1,
            13,
        )
    };
    if result < 0 {
        return Err(io::Error::other(format!(
            "bound output disposal failed: {result:#x}"
        )));
    }
    Ok(())
}
fn published_object(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: &crate::bound_fs::Identity,
) -> io::Result<bool> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .access_mode(0x80)
        .share_mode(1 | 2 | 4)
        .custom_flags(0x0020_0000)
        .open(parent.path().join(name))?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Ok(false);
    }
    Ok(crate::bound_fs::identity(&file)?.same_object(expected))
}
pub(crate) fn promote_transaction(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    recovery: &crate::bound_fs::Directory,
    expected: Option<(&crate::bound_fs::Identity, &str)>,
    written: &crate::bound_fs::ReadFile,
) -> io::Result<()> {
    let mut new = transaction_file(&recovery.path().join("new"), true)?;
    let bytes = crate::bound_fs::read_file(&mut new, 256 * 1024 * 1024)?;
    if !bytes.identity.same_object(&written.identity) || bytes.digest != written.digest {
        return Err(crate::bound_fs::changed());
    }
    let old = if let Some((expected_id, expected_digest)) = expected {
        let mut old = transaction_file(&parent.path().join(name), false)?;
        let read = crate::bound_fs::read_file(&mut old, 256 * 1024 * 1024)?;
        if &read.identity != expected_id || read.digest != expected_digest {
            return Err(crate::bound_fs::changed());
        }
        parent.verify()?;
        if !published_object(parent, name, expected_id)? {
            return Err(crate::bound_fs::changed());
        }
        rename_bound(&old, recovery, OsStr::new("old"), false)?;
        Some(old)
    } else {
        None
    };
    if let Err(error) = rename_bound(&new, parent, name, false) {
        // A newly created user target wins. Restore only into an absent name;
        // never overwrite that target. The old bytes remain in recovery/old
        // when an intervening writer prevents restoration.
        if let Some(old) = old.as_ref() {
            let _ = rename_bound(old, parent, name, false);
        }
        delete_object(&new)?;
        return Err(error);
    }
    if !published_object(parent, name, &written.identity)? {
        return Err(crate::bound_fs::changed());
    }
    if let Some(old) = old.as_ref() {
        delete_object(old)?;
    }
    parent.verify()
}

pub(crate) fn remove_bound_file(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: (&crate::bound_fs::Identity, &str),
) -> io::Result<()> {
    let mut file = transaction_file(&parent.path().join(name), false)?;
    let read = crate::bound_fs::read_file(&mut file, 256 * 1024 * 1024)?;
    if read.identity != *expected.0
        || read.digest != expected.1
        || !published_object(parent, name, expected.0)?
    {
        return Err(crate::bound_fs::changed());
    }
    parent.verify()?;
    delete_object(&file)?;
    parent.verify()
}
pub(crate) fn remove_bound_directory(
    parent: &crate::bound_fs::Directory,
    name: &OsStr,
    expected: &crate::bound_fs::Identity,
) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let path = parent.path().join(name);
    let file = std::fs::OpenOptions::new()
        .access_mode(0x8000_0000 | 0x0001_0000)
        .share_mode(1)
        .custom_flags(0x0220_0000)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.file_attributes() & 0x400 != 0
        || !crate::bound_fs::identity(&file)?.same_object(expected)
    {
        return Err(crate::bound_fs::changed());
    }
    if std::fs::read_dir(&path)?.next().transpose()?.is_some() {
        return Err(crate::bound_fs::changed());
    }
    parent.verify()?;
    // DELETE disposition belongs to this held, non-reparse object. Windows
    // itself refuses a nonempty directory; no recursive live path cleanup.
    delete_object(&file)?;
    parent.verify()
}
