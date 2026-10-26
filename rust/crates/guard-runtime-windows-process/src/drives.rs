//! Which drive letters name local volumes.

use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
use winapi::um::winbase::{DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE};

/// The mounted drive letters, uppercase, when every one is a local volume.
///
/// `None` when the drive mask cannot be read or any mounted drive is remote,
/// of unknown type or has no root: probing such a drive can stall on the
/// network, so a caller that needs every drive answered treats it as unproven.
pub fn local_drive_letters() -> Option<Vec<char>> {
    // SAFETY: GetLogicalDrives takes no arguments and only returns a bitmask.
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return None;
    }
    let mut letters = Vec::new();
    for index in 0..26u8 {
        if mask & (1 << index) == 0 {
            continue;
        }
        let letter = b'A' + index;
        let root = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
        // SAFETY: `root` is a NUL-terminated UTF-16 root path that outlives
        // the call, which only reads it.
        let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
        if !matches!(
            kind,
            DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_CDROM | DRIVE_RAMDISK
        ) {
            return None;
        }
        letters.push(char::from(letter));
    }
    Some(letters)
}
