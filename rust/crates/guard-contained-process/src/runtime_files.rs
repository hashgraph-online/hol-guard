//! Static loader dependency capture. No `ldd`, shell, PATH execution or live
//! package code is used to discover the bytes that a contained tool loads.
use crate::bound_fs::{self, Directory, ReadFile};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

pub struct RuntimeFile {
    pub names: BTreeSet<String>,
    pub bytes: Vec<u8>,
    pub digest: String,
}
pub struct RuntimeBundle {
    pub executable: ReadFile,
    pub files: Vec<RuntimeFile>,
    pub digest: String,
    pub interpreter: Option<String>,
    pub bindings: Vec<crate::runtime_resources::SourceBinding>,
    pub total_bytes: usize,
    pub file_count: usize,
}
struct Import {
    name: String,
    search: Vec<PathBuf>,
    optional: bool,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "runtime dependency identity unavailable",
    )
}
fn bytes(data: &[u8], at: usize, count: usize) -> io::Result<&[u8]> {
    data.get(at..at.checked_add(count).ok_or_else(invalid)?)
        .ok_or_else(invalid)
}
fn u16le(data: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, at, 2)?.try_into().map_err(|_| invalid())?,
    ))
}
fn u32le(data: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, at, 4)?.try_into().map_err(|_| invalid())?,
    ))
}
fn u64le(data: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(data, at, 8)?.try_into().map_err(|_| invalid())?,
    ))
}
fn u32be(data: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        bytes(data, at, 4)?.try_into().map_err(|_| invalid())?,
    ))
}
fn string(data: &[u8], at: usize, end: usize) -> io::Result<String> {
    let slice = data.get(at..end.min(data.len())).ok_or_else(invalid)?;
    let length = slice
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    if length == 0 || length > 4096 {
        return Err(invalid());
    }
    std::str::from_utf8(&slice[..length])
        .map(str::to_owned)
        .map_err(|_| invalid())
}
fn file(path: &Path, max: usize) -> io::Result<ReadFile> {
    let directory = Directory::open(path.parent().ok_or_else(invalid)?)?;
    directory.read_installed(Path::new(path.file_name().ok_or_else(invalid)?), max)
}

pub(crate) fn python_version(path: &Path) -> io::Result<Option<String>> {
    let image = file(path, 256 * 1024 * 1024)?;
    for import in imports(&image.bytes, path, path)? {
        let name = Path::new(&import.name)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some(value) = name
            .strip_prefix("python")
            .and_then(|name| name.strip_suffix(".dll"))
        {
            let digits = value.trim_end_matches("_d");
            if digits.starts_with('3')
                && digits.len() >= 2
                && digits.len() <= 4
                && digits.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Ok(Some(format!("3.{}", &digits[1..])));
            }
        }
        if let Some(value) = name.strip_prefix("libpython3.") {
            let minor: String = value
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .collect();
            if !minor.is_empty() {
                return Ok(Some(format!("3.{minor}")));
            }
        }
    }
    Ok(None)
}

/// Trusted native entry / standalone capture. Contained foreign requests use
/// capture_with_libraries and its mandatory native Guard-home exclusion.
pub fn capture(
    executable: &Path,
    expected: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<RuntimeBundle> {
    capture_impl(executable, expected, &[], None, deadline, cancel)
}
pub fn capture_with_libraries(
    executable: &Path,
    expected: &str,
    libraries: &[(PathBuf, &[u8])],
    guard_home: &Path,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<RuntimeBundle> {
    let root = bound_fs::Directory::open(guard_home)?;
    capture_impl(
        executable,
        expected,
        libraries,
        Some(root.path()),
        deadline,
        cancel,
    )
}
fn capture_impl(
    executable: &Path,
    expected: &str,
    libraries: &[(PathBuf, &[u8])],
    guard_home: Option<&Path>,
    deadline: Instant,
    cancel: &AtomicBool,
) -> io::Result<RuntimeBundle> {
    if Instant::now() >= deadline || cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "runtime dependency deadline",
        ));
    }
    let (executable, mut bindings) = if let Some(home) = guard_home {
        crate::runtime_resources::resolve_without_control(executable, home)?
    } else {
        crate::runtime_resources::resolve(executable)?
    };
    let trusted_self = guard_home.is_none()
        && std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .ok()
            .as_deref()
            == Some(executable.as_path());
    if (!trusted_self && crate::runtime_resources::secret(&executable))
        || guard_home.is_some_and(|root| executable.starts_with(root))
    {
        return Err(invalid());
    }
    let executable = executable.as_path();
    let mut image = bound_fs::open_executable(executable)?;
    let executable_file = bound_fs::read_executable(&mut image, 256 * 1024 * 1024)?;
    if executable_file.digest != expected {
        return Err(bound_fs::changed());
    }
    bindings.push(crate::runtime_resources::SourceBinding::capture(
        executable,
        &executable_file.identity,
    )?);
    let interpreter = elf_interpreter(&executable_file.bytes)?;
    let mut pending = imports(&executable_file.bytes, executable, executable)?;
    for (path, bytes) in libraries {
        pending.extend(imports(bytes, path, executable)?);
    }
    if let Some(name) = &interpreter {
        pending.push(Import {
            name: name.clone(),
            search: Vec::new(),
            optional: false,
        });
    }
    let mut files: BTreeMap<PathBuf, RuntimeFile> = BTreeMap::new();
    let mut aliases: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut total = executable_file.bytes.len();
    while let Some(import) = pending.pop() {
        if Instant::now() >= deadline || cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime dependency deadline",
            ));
        }
        let Some((path, selectors)) = resolve(&import, guard_home)? else {
            if import.optional {
                continue;
            }
            return Err(invalid());
        };
        bindings.extend(selectors);
        if system_shared_cache(&path) {
            continue;
        }
        let name = Path::new(&import.name)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(invalid)?
            .to_owned();
        if name.len() > 255 || name.contains(['/', '\\', ':']) {
            return Err(invalid());
        }
        let key = if cfg!(windows) {
            name.to_lowercase()
        } else {
            name.clone()
        };
        if let Some(previous) = aliases.get(&key) {
            if previous != &path {
                return Err(invalid());
            }
            continue;
        }
        if aliases.len() >= 1024 {
            return Err(invalid());
        }
        aliases.insert(key, path.clone());
        if let Some(file) = files.get_mut(&path) {
            total = total.checked_add(file.bytes.len()).ok_or_else(invalid)?;
            if total > 256 * 1024 * 1024 {
                return Err(invalid());
            }
            file.names.insert(name);
            continue;
        }
        let read = file(&path, (256 * 1024 * 1024usize).saturating_sub(total))?;
        bindings.push(crate::runtime_resources::SourceBinding::capture(
            &path,
            &read.identity,
        )?);
        total = total.checked_add(read.bytes.len()).ok_or_else(invalid)?;
        if total > 256 * 1024 * 1024 {
            return Err(invalid());
        }
        pending.extend(imports(&read.bytes, &path, executable)?);
        files.insert(
            path,
            RuntimeFile {
                names: BTreeSet::from([name]),
                bytes: read.bytes,
                digest: read.digest,
            },
        );
    }
    let mut hash = Sha256::new();
    hash.update(b"guard-runtime-bytes-v1\0");
    hash.update(executable_file.digest.as_bytes());
    if let Some(interpreter) = &interpreter {
        hash.update((interpreter.len() as u64).to_be_bytes());
        hash.update(interpreter.as_bytes());
    }
    for file in files.values() {
        for name in &file.names {
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name.as_bytes());
            hash.update(file.digest.as_bytes());
        }
    }
    for binding in &bindings {
        if Instant::now() >= deadline || cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime dependency deadline",
            ));
        }
        binding.verify()?;
    }
    Ok(RuntimeBundle {
        executable: executable_file,
        files: files.into_values().collect(),
        digest: hex::encode(hash.finalize()),
        interpreter,
        bindings,
        total_bytes: total,
        file_count: aliases.len() + 1,
    })
}
fn elf_interpreter(data: &[u8]) -> io::Result<Option<String>> {
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
fn system_shared_cache(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    return path.starts_with("/usr/lib") || path.starts_with("/System/Library");
    #[cfg(windows)]
    return crate::windows::system_directory().is_ok_and(|root| path.starts_with(root));
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = path;
        false
    }
}
fn resolve(
    import: &Import,
    guard_home: Option<&Path>,
) -> io::Result<Option<(PathBuf, Vec<crate::runtime_resources::SourceBinding>)>> {
    if import.name.contains('\0') {
        return Err(invalid());
    }
    let name = Path::new(&import.name);
    let candidates = if name.is_absolute() {
        vec![name.to_path_buf()]
    } else {
        import.search.iter().map(|root| root.join(name)).collect()
    };
    for candidate in candidates {
        if crate::runtime_resources::secret(&candidate)
            || guard_home.is_some_and(|root| candidate.starts_with(root))
        {
            return Err(invalid());
        }
        if system_shared_cache(&candidate) {
            return Ok(Some((candidate, Vec::new())));
        }
        let resolved = if let Some(home) = guard_home {
            crate::runtime_resources::resolve_without_control(&candidate, home)
        } else {
            crate::runtime_resources::resolve(&candidate)
        };
        match resolved {
            Ok(result) => {
                if crate::runtime_resources::secret(&result.0)
                    || guard_home.is_some_and(|root| result.0.starts_with(root))
                {
                    return Err(invalid());
                }
                return Ok(Some(result));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}
fn imports(data: &[u8], library: &Path, executable: &Path) -> io::Result<Vec<Import>> {
    if data.starts_with(b"\x7fELF") {
        elf(data, library)
    } else if data.starts_with(b"MZ") {
        pe(data, library)
    } else if data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        mach(data, library, executable)
    } else if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || data.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        let count = u32be(data, 4)? as usize;
        if count > 32 {
            return Err(invalid());
        }
        let wide = data[3] == 0xbf;
        let size = if wide { 32 } else { 20 };
        #[cfg(target_arch = "aarch64")]
        let cpu = 0x0100_000c;
        #[cfg(target_arch = "x86_64")]
        let cpu = 0x0100_0007;
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let cpu = 0;
        for index in 0..count {
            let at = 8 + index * size;
            if u32be(data, at)? == cpu {
                let (offset, length) = if wide {
                    let offset = u64::from_be_bytes(
                        bytes(data, at + 8, 8)?.try_into().map_err(|_| invalid())?,
                    );
                    let length = u64::from_be_bytes(
                        bytes(data, at + 16, 8)?.try_into().map_err(|_| invalid())?,
                    );
                    (offset, length)
                } else {
                    (
                        u64::from(u32be(data, at + 8)?),
                        u64::from(u32be(data, at + 12)?),
                    )
                };
                return mach(
                    bytes(
                        data,
                        usize::try_from(offset).map_err(|_| invalid())?,
                        usize::try_from(length).map_err(|_| invalid())?,
                    )?,
                    library,
                    executable,
                );
            }
        }
        Err(invalid())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "contained executable must be a native image",
        ))
    }
}
fn elf(data: &[u8], library: &Path) -> io::Result<Vec<Import>> {
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
    bytes(data, table, table_size)?;
    let parent = library.parent().ok_or_else(invalid)?;
    let mut search = vec![parent.to_path_buf()];
    for offset in path_offsets {
        let value = string(
            data,
            table + usize::try_from(offset).map_err(|_| invalid())?,
            table + table_size,
        )?;
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
            let name = string(
                data,
                table + usize::try_from(offset).map_err(|_| invalid())?,
                table + table_size,
            )?;
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
fn mach(data: &[u8], library: &Path, executable: &Path) -> io::Result<Vec<Import>> {
    if !data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err(invalid());
    }
    let count = u32le(data, 16)? as usize;
    if count > 4096 {
        return Err(invalid());
    }
    let end = 32 + u32le(data, 20)? as usize;
    bytes(data, 32, end.checked_sub(32).ok_or_else(invalid)?)?;
    let mut at = 32;
    let mut names = Vec::new();
    let mut rpaths = Vec::new();
    for _ in 0..count {
        let command = u32le(data, at)?;
        let size = u32le(data, at + 4)? as usize;
        if size < 8 || at + size > end {
            return Err(invalid());
        }
        if [0x0c, 0x8000_0018, 0x8000_001f, 0x8000_0023].contains(&command) {
            let name = string(data, at + u32le(data, at + 8)? as usize, at + size)?;
            names.push((name, command == 0x8000_0018));
        }
        if command == 0x8000_001c {
            rpaths.push(string(data, at + u32le(data, at + 8)? as usize, at + size)?);
        }
        at += size;
    }
    let loader = library.parent().ok_or_else(invalid)?;
    let exe = executable.parent().ok_or_else(invalid)?;
    let expand = |path: &str| {
        path.replace("@loader_path", &loader.to_string_lossy())
            .replace("@executable_path", &exe.to_string_lossy())
    };
    let search: Vec<PathBuf> = rpaths
        .iter()
        .map(|path| PathBuf::from(expand(path)))
        .chain([loader.to_path_buf(), exe.to_path_buf(), exe.join("../lib")])
        .collect();
    names
        .into_iter()
        .map(|(name, optional)| {
            let name = if let Some(name) = name.strip_prefix("@rpath/") {
                name.to_owned()
            } else {
                expand(&name)
            };
            if name.contains('@') {
                return Err(invalid());
            }
            Ok(Import {
                name,
                search: search.clone(),
                optional,
            })
        })
        .collect()
}
fn pe(data: &[u8], library: &Path) -> io::Result<Vec<Import>> {
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
            let name = string(data, rva(name)?, data.len())?;
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
    Ok(names
        .into_iter()
        .filter(|name| {
            !name.to_ascii_lowercase().starts_with("api-ms-")
                && !name.to_ascii_lowercase().starts_with("ext-ms-")
        })
        .map(|name| Import {
            name,
            search: search.clone(),
            optional: false,
        })
        .collect())
}
