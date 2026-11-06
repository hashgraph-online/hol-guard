//! Resolve only the exact trusted system interpreter of a bounded ELF image.
use super::BoundaryResult as Result;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

fn word(bytes: &[u8], start: usize, width: usize) -> Result<u64> {
    let slice = bytes
        .get(start..start + width)
        .ok_or("Unsupported ELF layout.")?;
    Ok(slice
        .iter()
        .enumerate()
        .fold(0u64, |v, (index, byte)| v | ((*byte as u64) << (index * 8))))
}

fn image(path: &Path) -> Result<(File, std::fs::Metadata, [u8; 64])> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "The exact approved ELF loader could not be verified.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "The exact approved ELF loader could not be verified.")?;
    if !metadata.is_file() {
        return Err("The exact approved ELF loader could not be verified.");
    }
    let mut header = [0u8; 64];
    file.read_exact(&mut header)
        .map_err(|_| "The exact approved ELF loader could not be verified.")?;
    Ok((file, metadata, header))
}

pub(super) fn resolve(executable: &Path) -> Result<Option<PathBuf>> {
    let result = resolve_inner(executable);
    result.map_err(|_| "The exact approved ELF loader could not be verified.")
}

fn resolve_inner(executable: &Path) -> Result<Option<PathBuf>> {
    let (mut file, metadata, header) = image(executable)?;
    let kind = word(&header, 16, 2)?;
    let machine = word(&header, 18, 2)?;
    let offset = word(&header, 32, 8)?;
    let size = word(&header, 54, 2)?;
    let count = word(&header, 56, 2)?;
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(kind, 2 | 3)
        || !matches!(machine, 62 | 183)
        || word(&header, 20, 4)? != 1
        || size != 56
        || count == 0
        || count > 128
        || offset < 64
        || offset
            .checked_add(size * count)
            .is_none_or(|v| v > metadata.len())
    {
        return Err("Unsupported ELF layout.");
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "Unsupported ELF layout.")?;
    let mut load = false;
    let mut interpreter = None;
    for _ in 0..count {
        let mut program = [0u8; 56];
        file.read_exact(&mut program)
            .map_err(|_| "Unsupported ELF layout.")?;
        match word(&program, 0, 4)? {
            1 => load = true,
            3 => {
                if interpreter.is_some() {
                    return Err("Ambiguous ELF interpreter.");
                }
                interpreter = Some((word(&program, 8, 8)?, word(&program, 32, 8)?));
            }
            _ => {}
        }
    }
    if !load {
        return Err("Missing ELF load segment.");
    }
    let Some((start, size)) = interpreter else {
        return Ok(None);
    };
    if size <= 1 || size > 4096 || start.checked_add(size).is_none_or(|v| v > metadata.len()) {
        return Err("Invalid ELF interpreter bounds.");
    }
    file.seek(SeekFrom::Start(start))
        .map_err(|_| "Invalid ELF interpreter bounds.")?;
    let mut raw = vec![0u8; size as usize];
    file.read_exact(&mut raw)
        .map_err(|_| "Invalid ELF interpreter bounds.")?;
    if raw.last() != Some(&0) || raw[..raw.len() - 1].contains(&0) || !raw.is_ascii() {
        return Err("Invalid ELF interpreter encoding.");
    }
    let name = std::str::from_utf8(&raw[..raw.len() - 1])
        .map_err(|_| "Invalid ELF interpreter encoding.")?;
    let names: &[&str] = if machine == 62 {
        &[
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ]
    } else {
        &[
            "/lib/ld-linux-aarch64.so.1",
            "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ]
    };
    if !names.contains(&name) {
        return Err("Unapproved ELF interpreter.");
    }
    let loader = Path::new(name)
        .canonicalize()
        .map_err(|_| "Missing ELF interpreter.")?;
    let roots: Vec<_> = ["/lib", "/lib64"]
        .iter()
        .filter_map(|p| Path::new(p).canonicalize().ok())
        .chain([PathBuf::from("/usr/lib")])
        .collect();
    if !roots.iter().any(|root| loader.starts_with(root)) {
        return Err("External ELF interpreter.");
    }
    let (_file, metadata, header) = image(&loader)?;
    if metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || &header[..7] != b"\x7fELF\x02\x01\x01"
        || word(&header, 16, 2)? != 3
        || word(&header, 18, 2)? != machine
    {
        return Err("Untrusted ELF interpreter.");
    }
    Ok(Some(loader))
}
