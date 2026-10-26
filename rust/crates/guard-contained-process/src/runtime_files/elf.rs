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
        let header = bytes(data, at, 56)?;
        if u32le(header, 0)? != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err(invalid());
        }
        let start = usize::try_from(u64le(header, 8)?).map_err(|_| invalid())?;
        let length = usize::try_from(u64le(header, 32)?).map_err(|_| invalid())?;
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

const MAX_IMPORTS: usize = 1024;
const MAX_DYNAMIC_ENTRIES: usize = 16_384;
const MAX_SEARCH_PATHS: usize = 64;
const MAX_SEARCH_BYTES: usize = 65_536;

// Mirror ld.so for the running architecture: the host multiarch directories
// first, then lib64 (x86_64 multilib hosts keep their 32-bit compatibility
// libraries under lib), then lib. Foreign-architecture triplets are never
// searched, so a library installed for another architecture cannot be
// captured in place of the one the native loader selects.
#[cfg(target_arch = "x86_64")]
const DEFAULT_LIBRARY_DIRECTORIES: [&str; 6] = [
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];
#[cfg(target_arch = "aarch64")]
const DEFAULT_LIBRARY_DIRECTORIES: [&str; 6] = [
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const DEFAULT_LIBRARY_DIRECTORIES: [&str; 4] = ["/lib64", "/usr/lib64", "/lib", "/usr/lib"];

#[cfg(test)]
pub(super) fn elf(data: &[u8], library: &Path) -> io::Result<Vec<Import>> {
    elf_with_context(data, library, &[], &|| Ok(()))
}

pub(super) fn elf_with_context(
    data: &[u8],
    library: &Path,
    inherited: &[PathBuf],
    check: &dyn Fn() -> io::Result<()>,
) -> io::Result<Vec<Import>> {
    check()?;
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
        check()?;
        let at = phoff
            .checked_add(index.checked_mul(size).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let header = bytes(data, at, 56)?;
        let kind = u32le(header, 0)?;
        let offset = u64le(header, 8)?;
        let address = u64le(header, 16)?;
        let length = u64le(header, 32)?;
        if kind == 1 {
            segments.push((address, offset, length));
        } else if kind == 2 && dynamic.replace((offset, length)).is_some() {
            return Err(invalid());
        }
    }
    let Some((offset, length)) = dynamic else {
        return Ok(Vec::new());
    };
    let offset = usize::try_from(offset).map_err(|_| invalid())?;
    let length = usize::try_from(length).map_err(|_| invalid())?;
    if length % 16 != 0 || length / 16 > MAX_DYNAMIC_ENTRIES {
        return Err(invalid());
    }
    let table = bytes(data, offset, length)?;
    let mut strtab = None;
    let mut strsize = None;
    let mut needed = Vec::new();
    let mut rpath = None;
    let mut runpath = None;
    let mut terminated = false;
    for entry in table.chunks_exact(16) {
        check()?;
        let tag = u64le(entry, 0)?;
        let value = u64le(entry, 8)?;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 => {
                if needed.len() >= MAX_IMPORTS {
                    return Err(invalid());
                }
                needed.push(value);
            }
            5 => strtab = Some(value),
            10 => strsize = Some(value),
            15 => {
                if rpath.replace(value).is_some() {
                    return Err(invalid());
                }
            }
            29 => {
                if runpath.replace(value).is_some() {
                    return Err(invalid());
                }
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(invalid());
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
    bytes(data, table, table_size)?;
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
    // DT_RUNPATH suppresses this object's DT_RPATH. Only DT_RPATH is
    // inherited by its descendants, nearest loading object first.
    let local = match runpath.or(rpath) {
        Some(offset) => search_paths(&dynamic_string(offset)?, parent, check)?,
        None => Vec::new(),
    };
    let mut inherited_rpath = Vec::new();
    if runpath.is_none() {
        append_paths(&mut inherited_rpath, &local)?;
    }
    append_paths(&mut inherited_rpath, inherited)?;
    let mut search = Vec::new();
    if runpath.is_some() {
        // glibc ignores the loader chain's RPATH for an object with RUNPATH.
        append_paths(&mut search, &local)?;
    } else {
        append_paths(&mut search, &inherited_rpath)?;
    }
    for path in DEFAULT_LIBRARY_DIRECTORIES {
        append_paths(&mut search, &[PathBuf::from(path)])?;
    }
    let search: std::sync::Arc<[PathBuf]> = search.into();
    let inherited_rpath: std::sync::Arc<[PathBuf]> = inherited_rpath.into();
    needed
        .into_iter()
        .map(|offset| {
            check()?;
            let name = dynamic_string(offset)?;
            if name.contains('/') && !Path::new(&name).is_absolute() {
                return Err(invalid());
            }
            Ok(Import {
                name,
                search: search.clone(),
                inherited_rpath: inherited_rpath.clone(),
                optional: false,
            })
        })
        .collect()
}

fn search_paths(
    value: &str,
    parent: &Path,
    check: &dyn Fn() -> io::Result<()>,
) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for path in value.split(':') {
        check()?;
        if path.is_empty() || paths.len() >= MAX_SEARCH_PATHS {
            return Err(invalid());
        }
        let origin = parent.to_string_lossy();
        // Check the expanded length before replace() can amplify repeated ORIGIN.
        let expanded = path
            .len()
            .checked_add(
                path.matches("$ORIGIN")
                    .count()
                    .saturating_add(path.matches("${ORIGIN}").count())
                    .checked_mul(origin.len())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        if expanded > 4096 {
            return Err(invalid());
        }
        let path = PathBuf::from(
            path.replace("${ORIGIN}", &origin)
                .replace("$ORIGIN", &origin),
        );
        if !path.is_absolute() {
            return Err(invalid());
        }
        append_paths(&mut paths, &[path])?;
    }
    Ok(paths)
}

fn append_paths(paths: &mut Vec<PathBuf>, incoming: &[PathBuf]) -> io::Result<()> {
    for path in incoming {
        if paths.contains(path) {
            continue;
        }
        if paths.len() >= MAX_SEARCH_PATHS {
            return Err(invalid());
        }
        let used: usize = paths.iter().map(|path| path.as_os_str().len()).sum();
        if used.saturating_add(path.as_os_str().len()) > MAX_SEARCH_BYTES {
            return Err(invalid());
        }
        paths.push(path.clone());
    }
    Ok(())
}

#[cfg(test)]
mod regressions;
