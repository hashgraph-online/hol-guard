use crate::{
    paths, FileContent, InstallError, PreparationControl, MAX_BYTES, MAX_FILES, MAX_FILE_BYTES,
};
use guard_cigar_release::WheelLock;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

// Wheels need neither multi-disk ZIP nor ZIP64. Check the bounded central
// directory envelope before the library parses entries/allocates its index.
fn envelope(bytes: &[u8]) -> Result<usize, InstallError> {
    let start = bytes.len().saturating_sub(65535 + 22);
    let position = (start..bytes.len().saturating_sub(21))
        .rev()
        .find(|&p| {
            bytes.get(p..p + 4) == Some(b"PK\x05\x06")
                && bytes.get(p + 20..p + 22).is_some_and(|len| {
                    p + 22 + usize::from(u16::from_le_bytes([len[0], len[1]])) == bytes.len()
                })
        })
        .ok_or(InstallError::ArchiveInvalid)?;
    let e = &bytes[position..position + 22];
    let count = usize::from(u16::from_le_bytes([e[10], e[11]]));
    let same_disk = u16::from_le_bytes([e[8], e[9]]);
    let size = u32::from_le_bytes(
        e[12..16]
            .try_into()
            .map_err(|_| InstallError::ArchiveInvalid)?,
    ) as u64;
    let offset = u32::from_le_bytes(
        e[16..20]
            .try_into()
            .map_err(|_| InstallError::ArchiveInvalid)?,
    ) as u64;
    if e[4..8] != [0, 0, 0, 0]
        || usize::from(same_disk) != count
        || count == 0
        || count > MAX_FILES
        || size > 8 * 1024 * 1024
        || offset + size != position as u64
    {
        return Err(InstallError::LimitExceeded);
    }
    Ok(count)
}

pub(crate) fn read(
    bytes: &[u8],
    lock: &WheelLock,
    files: &mut BTreeMap<String, FileContent>,
    namespace: &mut BTreeMap<String, (String, bool)>,
    total: &mut u64,
    control: &PreparationControl,
) -> Result<(), InstallError> {
    let count = envelope(bytes)?;
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|_| InstallError::ArchiveInvalid)?;
    if archive.len() != count
        || archive
            .has_overlapping_entries()
            .map_err(|_| InstallError::ArchiveInvalid)?
    {
        return Err(InstallError::ArchiveInvalid);
    }
    let mut wheel_names = BTreeSet::new();
    let mut dist_infos = BTreeSet::new();
    let expected = format!(
        "{}-{}.dist-info",
        lock.distribution.replace('-', "_"),
        lock.version
    );
    for index in 0..count {
        control.checkpoint()?;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| InstallError::ArchiveInvalid)?;
        if entry.encrypted()
            || !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            )
        {
            return Err(InstallError::WheelUnsupported);
        }
        let directory = entry.is_dir();
        if entry.is_symlink()
            || entry.unix_mode().is_some_and(|mode| {
                let kind = mode & 0o170000;
                kind != 0 && kind != if directory { 0o040000 } else { 0o100000 }
            })
        {
            return Err(InstallError::EntryUnsafe);
        }
        let name = paths::admit_name(entry.name_raw(), directory, namespace)?;
        if !wheel_names.insert(name.clone()) {
            return Err(InstallError::EntryUnsafe);
        }
        if let Some(top) = name.split('/').next().filter(|s| s.ends_with(".dist-info")) {
            dist_infos.insert(top.to_owned());
        }
        if directory {
            if entry.size() != 0 {
                return Err(InstallError::EntryUnsafe);
            }
            continue;
        }
        if entry.size() > MAX_FILE_BYTES || files.len() >= MAX_FILES {
            return Err(InstallError::LimitExceeded);
        }
        *total = total
            .checked_add(entry.size())
            .ok_or(InstallError::LimitExceeded)?;
        if *total > MAX_BYTES {
            return Err(InstallError::LimitExceeded);
        }
        let executable = entry.unix_mode().is_some_and(|mode| mode & 0o111 != 0);
        let mut content = Vec::with_capacity(entry.size() as usize);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            control.checkpoint()?;
            let n = entry
                .read(&mut chunk)
                .map_err(|_| InstallError::ArchiveInvalid)?;
            if n == 0 {
                break;
            }
            if content.len() as u64 + n as u64 > entry.size() {
                return Err(InstallError::LimitExceeded);
            }
            content.extend_from_slice(&chunk[..n]);
        }
        if content.len() as u64 != entry.size() {
            return Err(InstallError::ArchiveInvalid);
        }
        files.insert(
            name,
            FileContent {
                bytes: content,
                executable,
            },
        );
    }
    if dist_infos != BTreeSet::from([expected.clone()]) {
        return Err(InstallError::WheelUnsupported);
    }
    let metadata = text(files, &format!("{expected}/METADATA"))?;
    if header(metadata, "Name")?
        .replace('_', "-")
        .to_ascii_lowercase()
        != lock.distribution
        || header(metadata, "Version")? != lock.version
    {
        return Err(InstallError::WheelUnsupported);
    }
    check_python_metadata(metadata, lock)?;
    let wheel = text(files, &format!("{expected}/WHEEL"))?;
    if header(wheel, "Wheel-Version")? != "1.0" {
        return Err(InstallError::WheelUnsupported);
    }
    Ok(())
}
fn text<'a>(files: &'a BTreeMap<String, FileContent>, name: &str) -> Result<&'a str, InstallError> {
    let file = files.get(name).ok_or(InstallError::WheelUnsupported)?;
    if file.bytes.len() > 64 * 1024 {
        return Err(InstallError::WheelUnsupported);
    }
    std::str::from_utf8(&file.bytes).map_err(|_| InstallError::WheelUnsupported)
}
fn header<'a>(text: &'a str, key: &str) -> Result<&'a str, InstallError> {
    let mut values = text
        .lines()
        .take_while(|line| !line.trim_end_matches('\r').is_empty())
        .filter_map(|line| {
            let (name, value) = line.trim_end_matches('\r').split_once(": ")?;
            (name == key).then_some(value.trim())
        });
    let value = values.next().ok_or(InstallError::WheelUnsupported)?;
    if values.next().is_some() {
        return Err(InstallError::WheelUnsupported);
    }
    Ok(value)
}

fn check_python_metadata(metadata: &str, lock: &WheelLock) -> Result<(), InstallError> {
    let Some(expected) = &lock.requires_python else {
        return Ok(());
    };
    let mut headers = metadata
        .lines()
        .take_while(|line| !line.trim_end_matches('\r').is_empty())
        .filter_map(|line| line.trim_end_matches('\r').split_once(':'))
        .filter(|(key, _)| key.eq_ignore_ascii_case("Requires-Python"))
        .map(|(_, value)| value.trim());
    if headers.next() != Some(expected.as_str()) || headers.next().is_some() {
        return Err(InstallError::WheelUnsupported);
    }
    Ok(())
}

#[cfg(test)]
mod python_metadata_tests {
    use super::*;
    #[test]
    fn locked_requires_python_must_match_actual_wheel_metadata_once() {
        let catalog = guard_cigar_release::TrustedCatalog::bundled().unwrap();
        let mut lock = catalog.document().builds[0].platforms[0]
            .wheel
            .clone()
            .unwrap();
        lock.requires_python = Some(">=3.14.8,<3.15".into());
        check_python_metadata(
            "Name: hol-cigar\r\nRequires-Python: >=3.14.8,<3.15\r\n\r\n",
            &lock,
        )
        .unwrap();
        for metadata in [
            "Name: hol-cigar\n\n",
            "Requires-Python: >=3.14,<3.15\n\n",
            "Requires-Python: >=3.14.8,<3.15\nrequires-python: >=3.14.8,<3.15\n\n",
            "Name: hol-cigar\n\nRequires-Python: >=3.14.8,<3.15",
        ] {
            assert_eq!(
                check_python_metadata(metadata, &lock),
                Err(InstallError::WheelUnsupported)
            );
        }
        lock.requires_python = None;
        check_python_metadata("Name: old archive\n\n", &lock).unwrap();
    }
}

#[cfg(test)]
#[path = "wheel_safety_tests.rs"]
mod safety_tests;
