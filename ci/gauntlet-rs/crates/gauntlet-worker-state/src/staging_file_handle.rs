//! Read an opaque file handle through an already-held kernel descriptor.
//! No pathname, `/proc` symlink or open-by-handle authority is used.

use gauntlet_contracts::{EffectFileHandle, MAX_EFFECT_HANDLE_BYTES};
use std::os::fd::{AsFd, AsRawFd};

#[repr(C)]
struct HandleBuffer {
    length: u32,
    kind: i32,
    bytes: [u8; MAX_EFFECT_HANDLE_BYTES],
}

pub(crate) fn sample_file_handle(file: &impl AsFd) -> Result<EffectFileHandle, String> {
    let mut buffer = HandleBuffer {
        length: MAX_EFFECT_HANDLE_BYTES as u32,
        kind: -1,
        bytes: [0; MAX_EFFECT_HANDLE_BYTES],
    };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: the repr(C) buffer has the Linux file_handle header followed by
    // exactly the advertised writable capacity. The fd stays borrowed for
    // this call. AT_EMPTY_PATH queries that object without path resolution.
    let result = unsafe {
        libc::name_to_handle_at(
            file.as_fd().as_raw_fd(),
            c"".as_ptr(),
            (&mut buffer as *mut HandleBuffer).cast(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if result != 0 || buffer.length as usize > MAX_EFFECT_HANDLE_BYTES {
        return Err(format!(
            "kernel file handle unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Mount IDs differ across the physical and idmapped views. Object
    // comparison uses the opaque handle plus the separately checked st_dev.
    EffectFileHandle::from_kernel(buffer.kind, &buffer.bytes[..buffer.length as usize])
        .ok_or_else(|| "kernel file handle has an unsupported shape".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    #[ignore] // Requires the dedicated Linux VM's handle-capable /home filesystem.
    fn vm_file_handle_survives_rename_and_distinguishes_replacement() {
        let dir = tempfile::tempdir_in("/home").unwrap();
        let path = dir.path().join("original");
        std::fs::write(&path, b"original").unwrap();
        let held = File::open(&path).unwrap();
        let identity = sample_file_handle(&held).unwrap();
        let moved = dir.path().join("renamed");
        std::fs::rename(&path, &moved).unwrap();
        assert_eq!(
            sample_file_handle(&File::open(&moved).unwrap()).unwrap(),
            identity
        );
        std::fs::remove_file(&moved).unwrap();
        assert_eq!(sample_file_handle(&held).unwrap(), identity);
        std::fs::write(&path, b"replacement").unwrap();
        assert_ne!(
            sample_file_handle(&File::open(&path).unwrap()).unwrap(),
            identity
        );
    }
}
