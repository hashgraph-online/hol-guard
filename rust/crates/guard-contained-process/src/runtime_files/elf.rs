use super::{bytes, invalid, string, u16le, u32le, u64le, Import};
use std::io;
use std::path::{Path, PathBuf};

pub(super) fn elf_interpreter(data: &[u8]) -> io::Result<Option<String>> {
    if !data.starts_with(b"\x7fELF") {
        return Ok(None);
    }
    if bytes(data, 4, 2)? != [2, 1] {
        return Err(invalid());
    }
    let offset = usize::try_from(u64le(data, 32)?).map_err(|_| invalid())?;
    let size = u16le(data, 54)? as usize;
    let count = u16le(data, 56)? as usize;
    if size < 56 || count > 1024 {
        return Err(invalid());
    }
    let mut interpreter = None;
    for index in 0..count {
        let at = offset
            .checked_add(index.checked_mul(size).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if u32le(data, at)? != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err(invalid());
        }
        let start = usize::try_from(u64le(data, at + 8)?).map_err(|_| invalid())?;
        let length = usize::try_from(u64le(data, at + 32)?).map_err(|_| invalid())?;
        let end = start.checked_add(length).ok_or_else(invalid)?;
        bytes(data, start, length)?;
        let name = string(data, start, end)?;
        let path = Path::new(&name);
        if !path.is_absolute()
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(invalid());
        }
        interpreter = Some(name);
    }
    Ok(interpreter)
}

pub(super) fn elf(data: &[u8], library: &Path) -> io::Result<Vec<Import>> {
    if bytes(data, 4, 2)? != [2, 1] {
        return Err(invalid());
    }
    let phoff = usize::try_from(u64le(data, 32)?).map_err(|_| invalid())?;
    let size = u16le(data, 54)? as usize;
    let count = u16le(data, 56)? as usize;
    if size < 56 || count > 1024 {
        return Err(invalid());
    }
    let mut segments = Vec::new();
    let mut dynamic = None;
    for index in 0..count {
        let at = phoff + index * size;
        let kind = u32le(data, at)?;
        let offset = u64le(data, at + 8)?;
        let address = u64le(data, at + 16)?;
        let length = u64le(data, at + 32)?;
        if kind == 1 {
            segments.push((address, offset, length));
        } else if kind == 2 {
            dynamic = Some((offset, length));
        }
    }
    let Some((offset, length)) = dynamic else {
        return Ok(Vec::new());
    };
    let offset = usize::try_from(offset).map_err(|_| invalid())?;
    let length = usize::try_from(length).map_err(|_| invalid())?;
    bytes(data, offset, length)?;
    let mut strtab = None;
    let mut strsize = None;
    let mut needed = Vec::new();
    let mut path_offsets = Vec::new();
    for at in (offset..offset + length).step_by(16) {
        let tag = u64le(data, at)?;
        let value = u64le(data, at + 8)?;
        match tag {
            0 => break,
            1 => needed.push(value),
            5 => strtab = Some(value),
            10 => strsize = Some(value),
            15 | 29 => path_offsets.push(value),
            _ => {}
        }
    }
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let address = strtab.ok_or_else(invalid)?;
    let table = segments
        .iter()
        .find_map(|(start, offset, length)| {
            address
                .checked_sub(*start)
                .filter(|delta| *delta < *length)
                .and_then(|delta| offset.checked_add(delta))
        })
        .ok_or_else(invalid)?;
    let table = usize::try_from(table).map_err(|_| invalid())?;
    let table_size = usize::try_from(strsize.ok_or_else(invalid)?).map_err(|_| invalid())?;
    let table_end = table.checked_add(table_size).ok_or_else(invalid)?;
    data.get(table..table_end).ok_or_else(invalid)?;
    let dynamic_string = |offset: u64| {
        let offset = usize::try_from(offset).map_err(|_| invalid())?;
        if offset >= table_size {
            return Err(invalid());
        }
        string(
            data,
            table.checked_add(offset).ok_or_else(invalid)?,
            table_end,
        )
    };
    let parent = library.parent().ok_or_else(invalid)?;
    let mut search = Vec::new();
    for offset in path_offsets {
        let value = dynamic_string(offset)?;
        for path in value.split(':') {
            if path.is_empty() {
                return Err(invalid());
            }
            let path = path
                .replace("${ORIGIN}", &parent.to_string_lossy())
                .replace("$ORIGIN", &parent.to_string_lossy());
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(invalid());
            }
            search.push(path);
        }
    }
    for path in [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/lib/x86_64-linux-gnu",
        "/usr/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
    ] {
        search.push(PathBuf::from(path));
    }
    needed
        .into_iter()
        .map(|offset| {
            let name = dynamic_string(offset)?;
            if name.contains('/') && !Path::new(&name).is_absolute() {
                return Err(invalid());
            }
            Ok(Import {
                name,
                search: search.clone(),
                optional: false,
            })
        })
        .collect()
}
