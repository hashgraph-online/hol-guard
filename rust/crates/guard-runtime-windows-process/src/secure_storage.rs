//! Small, owned wrappers for the Windows secure-storage APIs.
//!
//! `hol-guard-runtime` forbids unsafe code. Keep the Win32 pointers and the
//! DPAPI-allocated buffers in this companion crate, and expose only copied
//! Rust-owned bytes to the runtime.

use std::ffi::OsStr;
use std::io;
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null_mut, slice_from_raw_parts};
use std::sync::atomic::{compiler_fence, Ordering};

use winapi::shared::minwindef::{DWORD, FALSE, HLOCAL};
use winapi::shared::winerror::ERROR_NOT_FOUND;
use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
use winapi::um::winbase::LocalFree;
use winapi::um::wincred::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_MAX_CREDENTIAL_BLOB_SIZE,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, PCREDENTIALW,
};
use winapi::um::wincrypt::DATA_BLOB;

fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows target contains an embedded NUL",
        ));
    }
    Ok(OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn blob_from_bytes(bytes: &[u8]) -> io::Result<DATA_BLOB> {
    let cb_data = DWORD::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows secure-storage input exceeds the DWORD limit",
        )
    })?;
    Ok(DATA_BLOB {
        cbData: cb_data,
        pbData: if bytes.is_empty() {
            null_mut()
        } else {
            bytes.as_ptr() as *mut u8
        },
    })
}

/// Wipe sensitive bytes with volatile stores so the optimizer cannot remove
/// the cleanup as a dead write before the allocation is released.
pub fn secure_zero(bytes: &mut [u8]) {
    // SAFETY: `bytes` is a valid mutable slice for its entire length, and the
    // volatile stores stay within that slice.
    unsafe {
        for index in 0..bytes.len() {
            std::ptr::write_volatile(bytes.as_mut_ptr().add(index), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

unsafe fn secure_zero_raw(pointer: *mut u8, length: usize) {
    for index in 0..length {
        // SAFETY: The caller owns a valid allocation containing `length` bytes.
        unsafe { std::ptr::write_volatile(pointer.add(index), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Zero and release a buffer allocated by a Windows API.
fn release_blob(blob: DATA_BLOB) -> io::Result<()> {
    if blob.pbData.is_null() {
        return if blob.cbData == 0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows secure-storage returned a null buffer",
            ))
        };
    }
    // SAFETY: DPAPI returned a valid allocation containing `cbData` bytes;
    // ownership is released exactly once below, after this wipe.
    unsafe { secure_zero_raw(blob.pbData, blob.cbData as usize) };
    // SAFETY: DPAPI allocates DATA_BLOB output with the LocalAlloc family.
    let remaining = unsafe { LocalFree(blob.pbData as HLOCAL) };
    if remaining.is_null() {
        Ok(())
    } else {
        Err(io::Error::other("LocalFree failed for a DPAPI buffer"))
    }
}

fn copy_and_release(blob: DATA_BLOB) -> io::Result<Vec<u8>> {
    let bytes = if blob.cbData == 0 {
        Vec::new()
    } else if blob.pbData.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows secure-storage returned a null buffer",
        ));
    } else {
        // SAFETY: The pointer and length are supplied by the live DATA_BLOB;
        // copy before releasing the API-owned allocation.
        unsafe { (&*slice_from_raw_parts(blob.pbData, blob.cbData as usize)).to_vec() }
    };
    match release_blob(blob) {
        Ok(()) => Ok(bytes),
        Err(error) => {
            let mut bytes = bytes;
            secure_zero(&mut bytes);
            Err(error)
        }
    }
}

/// Protect arbitrary bounded bytes with the current user's DPAPI key.
pub fn dpapi_protect(value: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    let mut input = blob_from_bytes(value)?;
    let mut optional_entropy = blob_from_bytes(entropy)?;
    let entropy_ptr = if entropy.is_empty() {
        null_mut()
    } else {
        &mut optional_entropy
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: All blobs point to live Rust-owned input for this synchronous
    // call; DPAPI owns only the output and it is copied and wiped below.
    let protected = unsafe {
        CryptProtectData(
            &mut input,
            null_mut(),
            entropy_ptr,
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if protected == FALSE {
        let error = io::Error::last_os_error();
        if !output.pbData.is_null() {
            let _ = release_blob(output);
        }
        return Err(error);
    }
    copy_and_release(output)
}

/// Unprotect bytes with the current user's DPAPI key.
pub fn dpapi_unprotect(value: &[u8], entropy: &[u8]) -> io::Result<Vec<u8>> {
    let mut input = blob_from_bytes(value)?;
    let mut optional_entropy = blob_from_bytes(entropy)?;
    let entropy_ptr = if entropy.is_empty() {
        null_mut()
    } else {
        &mut optional_entropy
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: All blobs point to live Rust-owned input for this synchronous
    // call; DPAPI owns only the output and it is copied and wiped below.
    let unprotected = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            entropy_ptr,
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if unprotected == FALSE {
        let error = io::Error::last_os_error();
        if !output.pbData.is_null() {
            let _ = release_blob(output);
        }
        return Err(error);
    }
    copy_and_release(output)
}

/// Read one exact generic credential. Only `ERROR_NOT_FOUND` is absence.
pub fn credential_read(target: &str) -> io::Result<Option<Vec<u8>>> {
    let target = wide(target)?;
    let mut credential: PCREDENTIALW = null_mut();
    // SAFETY: The target is NUL-terminated and the output pointer remains
    // valid until CredFree below.
    let read = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) };
    if read == FALSE {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
            return Ok(None);
        }
        return Err(error);
    }
    if credential.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CredReadW returned a null credential",
        ));
    }
    // SAFETY: CredReadW returned an owned CREDENTIALW allocation. The fields
    // are inspected before the allocation is released exactly once.
    let result = unsafe {
        let credential_ref = &*credential;
        let size = credential_ref.CredentialBlobSize as usize;
        if size > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "credential blob exceeds the Windows bound",
            ))
        } else if size == 0 {
            Ok(Vec::new())
        } else if credential_ref.CredentialBlob.is_null() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "credential blob pointer is null",
            ))
        } else {
            let bytes = std::slice::from_raw_parts(credential_ref.CredentialBlob, size).to_vec();
            // SAFETY: CredReadW returned `size` bytes at CredentialBlob.
            secure_zero_raw(credential_ref.CredentialBlob, size);
            Ok(bytes)
        }
    };
    // SAFETY: CredFree owns the allocation returned by CredReadW.
    unsafe { CredFree(credential as *mut _) };
    result.map(Some)
}

/// Write one durable generic credential without prompting or enumerating.
pub fn credential_write(target: &str, value: &[u8]) -> io::Result<()> {
    if value.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential blob exceeds the Windows bound",
        ));
    }
    let target = wide(target)?;
    let mut credential: CREDENTIALW = unsafe { zeroed() };
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = target.as_ptr() as *mut _;
    credential.CredentialBlobSize = value.len() as DWORD;
    credential.CredentialBlob = if value.is_empty() {
        null_mut()
    } else {
        value.as_ptr() as *mut u8
    };
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    // SAFETY: All pointers reference live Rust-owned storage for this
    // synchronous call; Windows copies the credential before returning.
    let written = unsafe { CredWriteW(&mut credential, 0) };
    if written == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Delete a generic credential. Intended for cleanup of unique test targets.
pub fn credential_delete(target: &str) -> io::Result<bool> {
    let target = wide(target)?;
    // SAFETY: The target is NUL-terminated and remains live for this call.
    let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
    if deleted != FALSE {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}
