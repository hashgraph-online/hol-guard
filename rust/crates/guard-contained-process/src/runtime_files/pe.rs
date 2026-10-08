use super::{bytes, invalid, string, u16le, u32le, u64le, Import};
use std::io;
use std::path::Path;

pub(super) fn pe(data: &[u8], library: &Path) -> io::Result<Vec<Import>> {
    let pe = u32le(data, 0x3c)? as usize;
    if bytes(data, pe, 4)? != b"PE\0\0" {
        return Err(invalid());
    }
    let count = u16le(data, pe + 6)? as usize;
    let optional = pe + 24;
    let optional_size = u16le(data, pe + 20)? as usize;
    if count > 1024 {
        return Err(invalid());
    }
    let magic = u16le(data, optional)?;
    let directories = optional
        + match magic {
            0x20b => 112,
            0x10b => 96,
            _ => return Err(invalid()),
        };
    let base = if magic == 0x20b {
        u64le(data, optional + 24)?
    } else {
        u64::from(u32le(data, optional + 28)?)
    };
    let sections = optional + optional_size;
    let rva = |address: u32| -> io::Result<usize> {
        for index in 0..count {
            let at = sections + index * 40;
            let virtual_address = u32le(data, at + 12)?;
            let raw_size = u32le(data, at + 16)?;
            let offset = u32le(data, at + 20)?;
            if let Some(delta) = address
                .checked_sub(virtual_address)
                .filter(|delta| *delta < raw_size)
            {
                return usize::try_from(u64::from(offset) + u64::from(delta))
                    .map_err(|_| invalid());
            }
        }
        Err(invalid())
    };
    let mut names = Vec::new();
    for (index, descriptor_size, name_offset) in [(1usize, 20usize, 12usize), (13, 32, 4)] {
        if directories + index * 8 + 8 > optional + optional_size {
            continue;
        }
        let address = u32le(data, directories + index * 8)?;
        let length = u32le(data, directories + index * 8 + 4)? as usize;
        if address == 0 || length == 0 {
            continue;
        }
        // Reject oversized descriptor tables before materializing names or
        // search paths. Include one terminating zero descriptor in the bound.
        if length > 1025 * descriptor_size {
            return Err(invalid());
        }
        let start = rva(address)?;
        let end = start.checked_add(length).ok_or_else(invalid)?;
        bytes(data, start, length)?;
        for at in (start..end).step_by(descriptor_size) {
            let descriptor = bytes(data, at, descriptor_size)?;
            if descriptor.iter().all(|byte| *byte == 0) {
                break;
            }
            let mut name = u32le(data, at + name_offset)?;
            if index == 13 && u32le(data, at)? & 1 == 0 {
                name = u32::try_from(u64::from(name).checked_sub(base).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            }
            if names.len() >= 1024 {
                return Err(invalid());
            }
            let offset = rva(name)?;
            let name = string(data, offset, offset.checked_add(256).ok_or_else(invalid)?)?;
            if name.contains(['/', '\\', ':']) {
                return Err(invalid());
            }
            names.push(name);
        }
    }
    let search = vec![library.parent().ok_or_else(invalid)?.to_path_buf()];
    #[cfg(windows)]
    let search = {
        let mut search = search;
        search.push(crate::windows::system_directory()?);
        search
    };
    let search: std::sync::Arc<[std::path::PathBuf]> = search.into();
    Ok(names
        .into_iter()
        .filter(|name| {
            !name.to_ascii_lowercase().starts_with("api-ms-")
                && !name.to_ascii_lowercase().starts_with("ext-ms-")
        })
        .map(|name| Import {
            name,
            search: search.clone(),
            inherited_rpath: std::sync::Arc::from([]),
            optional: false,
        })
        .collect())
}
