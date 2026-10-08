//! Static loader dependency capture. No `ldd`, shell, PATH execution or live
//! package code is used to discover the bytes that a contained tool loads.
use crate::bound_fs::{self, Directory, ReadFile};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

mod elf;
mod mach;
mod pe;
mod system;
use system::{system_library, system_shared_cache};

use elf::{elf, elf_interpreter};
use mach::mach;
use pe::pe;

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
        if system_library(&path) {
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
            Ok(mut result) => {
                if crate::runtime_resources::secret(&result.0)
                    || guard_home.is_some_and(|root| result.0.starts_with(root))
                {
                    return Err(invalid());
                }
                // Windows has no dyld-style diskless cache. A System32
                // candidate must exist as a bound regular image before it can
                // be omitted from the copied bundle.
                #[cfg(windows)]
                if system_library(&result.0) {
                    let held = bound_fs::open_executable(&result.0)?;
                    result
                        .1
                        .push(crate::runtime_resources::SourceBinding::capture(
                            &result.0,
                            &bound_fs::identity(&held)?,
                        )?);
                }
                #[cfg(not(windows))]
                let _ = &mut result;
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

#[cfg(test)]
#[path = "runtime_files_tests.rs"]
mod tests;
