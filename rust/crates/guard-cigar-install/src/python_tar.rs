use super::*;
use std::collections::BTreeSet;

/// This shipped layout accepts ordinary USTAR/GNU files/directories and safe
/// internal file aliases. PAX/sparse/device/extension records need a reviewed
/// layout update, rather than ambiguous implicit tar-library extraction.
pub(super) fn read(
    raw: &[u8],
    control: &PreparationControl,
) -> Result<BTreeMap<String, FileContent>, InstallError> {
    let mut offset = 0usize;
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut namespace = BTreeMap::new();
    let mut members = 0usize;
    let mut total = 0u64;
    loop {
        control.checkpoint()?;
        let block = raw
            .get(offset..offset.saturating_add(512))
            .ok_or(InstallError::ArchiveInvalid)?;
        if block.iter().all(|b| *b == 0) {
            if raw.len().saturating_sub(offset) < 1024 || raw[offset..].iter().any(|b| *b != 0) {
                return Err(InstallError::ArchiveInvalid);
            }
            break;
        }
        members += 1;
        if members > MAX_FILES {
            return Err(InstallError::LimitExceeded);
        }
        let mut header = ::tar::Header::new_old();
        header.as_mut_bytes().copy_from_slice(block);
        let sum = block[..148]
            .iter()
            .chain(&block[156..])
            .map(|b| u32::from(*b))
            .sum::<u32>()
            + 8 * 32;
        if header.cksum().map_err(|_| InstallError::ArchiveInvalid)? != sum
            || header.as_gnu().is_none() && header.as_ustar().is_none()
        {
            return Err(InstallError::ArchiveInvalid);
        }
        let size = header
            .entry_size()
            .map_err(|_| InstallError::ArchiveInvalid)?;
        if size > MAX_FILE_BYTES {
            return Err(InstallError::LimitExceeded);
        }
        let end = offset
            .checked_add(512)
            .and_then(|v| v.checked_add(size as usize))
            .ok_or(InstallError::LimitExceeded)?;
        let bytes = raw
            .get(offset + 512..end)
            .ok_or(InstallError::ArchiveInvalid)?;
        let kind = header.entry_type().as_byte();
        if !matches!(kind, b'0' | 0 | b'5' | b'1' | b'2') {
            return Err(InstallError::PythonArchiveUnsupported);
        }
        let path = header.path_bytes();
        let path = std::str::from_utf8(&path).map_err(|_| InstallError::EntryUnsafe)?;
        let mode = header.mode().map_err(|_| InstallError::ArchiveInvalid)?;
        if mode & 0o7000 != 0 {
            return Err(InstallError::EntryUnsafe);
        }
        if path.trim_end_matches('/') == "python" && kind == b'5' {
            if size != 0 {
                return Err(InstallError::ArchiveInvalid);
            }
        } else {
            let name = path
                .strip_prefix("python/")
                .ok_or(InstallError::EntryUnsafe)?;
            let canonical = if kind == b'5' && !name.ends_with('/') {
                format!("{name}/")
            } else {
                name.to_owned()
            };
            let name =
                paths::admit_interpreter_name(canonical.as_bytes(), kind == b'5', &mut namespace)?;
            match kind {
                b'0' | 0 => {
                    total = total.checked_add(size).ok_or(InstallError::LimitExceeded)?;
                    if total > MAX_BYTES {
                        return Err(InstallError::LimitExceeded);
                    }
                    files.insert(
                        name,
                        FileContent {
                            bytes: bytes.to_vec(),
                            executable: mode & 0o111 != 0,
                        },
                    );
                }
                b'5' => {
                    if size != 0 {
                        return Err(InstallError::ArchiveInvalid);
                    }
                }
                _ => {
                    if size != 0 {
                        return Err(InstallError::ArchiveInvalid);
                    }
                    let target = header.link_name_bytes().ok_or(InstallError::EntryUnsafe)?;
                    links.insert(name.clone(), resolve(&name, &target, kind == b'1')?);
                }
            }
        }
        offset = end.checked_add(511).ok_or(InstallError::LimitExceeded)? & !511;
    }
    // Every alias is materialized as its own protected regular file, so no
    // interpreter path can later resolve outside the exact verified tree.
    for (name, link) in &links {
        control.checkpoint()?;
        let mut target = link;
        let mut seen = BTreeSet::from([name]);
        while let Some(next) = links.get(target) {
            if seen.len() >= 8 || !seen.insert(target) {
                return Err(InstallError::EntryUnsafe);
            }
            target = next;
        }
        let source = files.get(target).ok_or(InstallError::EntryUnsafe)?;
        total = total
            .checked_add(source.bytes.len() as u64)
            .ok_or(InstallError::LimitExceeded)?;
        if total > MAX_BYTES || files.len() >= MAX_FILES {
            return Err(InstallError::LimitExceeded);
        }
        let source = source.clone();
        files.insert(name.clone(), source);
    }
    Ok(files)
}

fn resolve(name: &str, raw: &[u8], hard: bool) -> Result<String, InstallError> {
    let text = std::str::from_utf8(raw).map_err(|_| InstallError::EntryUnsafe)?;
    if text.is_empty() || text.starts_with('/') || !text.is_ascii() || text.len() > 1024 {
        return Err(InstallError::EntryUnsafe);
    }
    let mut parts: Vec<&str> = if hard {
        Vec::new()
    } else {
        name.split('/').collect()
    };
    if !hard {
        parts.pop();
    }
    let text = if hard {
        text.strip_prefix("python/")
            .ok_or(InstallError::EntryUnsafe)?
    } else {
        text
    };
    for part in text.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                parts.pop().ok_or(InstallError::EntryUnsafe)?;
            }
            other => parts.push(other),
        }
    }
    paths::admit_interpreter_name(parts.join("/").as_bytes(), false, &mut BTreeMap::new())
}
