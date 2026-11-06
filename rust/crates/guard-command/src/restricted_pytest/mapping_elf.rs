//! Bounded ELF metadata for executable-mapping evidence.
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;

type Result<T> = std::result::Result<T, &'static str>;

fn number(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut buffer = [0; 8];
    buffer[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(buffer)
}

fn at(file: &mut File, offset: u64, width: usize, deadline: std::time::Instant) -> Result<Vec<u8>> {
    if std::time::Instant::now() >= deadline {
        return Err("Linux executable mapping inspection deadline exceeded.");
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|_| "Truncated ELF metadata.")?;
    let mut bytes = vec![0; width];
    file.read_exact(&mut bytes)
        .map_err(|_| "Truncated ELF metadata.")?;
    Ok(bytes)
}

pub(super) fn inspect(
    file: &mut File,
    metadata: &Metadata,
    library: bool,
    system_library: bool,
    deadline: std::time::Instant,
) -> Result<(Option<String>, Vec<String>)> {
    let header = at(file, 0, 64, deadline)?;
    let kind = number(&header, 16, 2);
    let machine = number(&header, 18, 2);
    let offset = number(&header, 32, 8);
    let width = number(&header, 54, 2);
    let count = number(&header, 56, 2);
    if &header[..7] != b"\x7fELF\x02\x01\x01"
        || ![2, 3].contains(&kind)
        || ![62, 183].contains(&machine)
        || number(&header, 20, 4) != 1
        || offset < 64
        || width != 56
        || !(1..=128).contains(&count)
        || offset
            .checked_add(width * count)
            .is_none_or(|end| end > metadata.len())
    {
        return Err("Unsupported ELF mapping layout.");
    }
    let mut programs = Vec::new();
    for index in 0..count {
        let bytes = at(file, offset + width * index, 56, deadline)?;
        programs.push([
            number(&bytes, 0, 4),
            number(&bytes, 4, 4),
            number(&bytes, 8, 8),
            number(&bytes, 16, 8),
            number(&bytes, 24, 8),
            number(&bytes, 32, 8),
            number(&bytes, 40, 8),
            number(&bytes, 48, 8),
        ]);
    }
    let loads: Vec<_> = programs.iter().filter(|v| v[0] == 1).collect();
    if loads.is_empty() {
        return Err("ELF mapping has no load segment.");
    }
    let dynamic: Vec<_> = programs.iter().filter(|v| v[0] == 2).collect();
    let mut entries = Vec::new();
    if !dynamic.is_empty() {
        if dynamic.len() != 1 || dynamic[0][5] > 65536 || dynamic[0][5] % 16 != 0 {
            return Err("Invalid dynamic metadata budget.");
        }
        let segment = dynamic[0];
        if segment[2]
            .checked_add(segment[5])
            .is_none_or(|v| v > metadata.len())
        {
            return Err("Truncated dynamic metadata.");
        }
        for index in 0..segment[5] / 16 {
            let bytes = at(file, segment[2] + index * 16, 16, deadline)?;
            let tag = number(&bytes, 0, 8);
            if tag == 0 {
                break;
            }
            entries.push((tag, number(&bytes, 8, 8)));
        }
    }
    let names: Vec<_> = entries
        .iter()
        .filter(|(tag, _)| [1, 14].contains(tag))
        .collect();
    let mut soname = None;
    let mut dependencies = Vec::new();
    if !names.is_empty() {
        let addresses: Vec<_> = entries
            .iter()
            .filter(|(tag, _)| *tag == 5)
            .map(|(_, v)| *v)
            .collect();
        let sizes: Vec<_> = entries
            .iter()
            .filter(|(tag, _)| *tag == 10)
            .map(|(_, v)| *v)
            .collect();
        if addresses.len() != 1 || sizes.len() != 1 || sizes[0] == 0 || sizes[0] > metadata.len() {
            return Err("Invalid ELF string table.");
        }
        let address = addresses[0];
        let size = sizes[0];
        let locations: Vec<_> = loads
            .iter()
            .filter_map(|p| {
                if p[3] <= address && address.checked_add(size)? <= p[3].checked_add(p[5])? {
                    p[2].checked_add(address - p[3])
                } else {
                    None
                }
            })
            .collect();
        if locations.len() != 1
            || locations[0]
                .checked_add(size)
                .is_none_or(|v| v > metadata.len())
        {
            return Err("Ambiguous ELF string table.");
        }
        for (tag, index) in names {
            if *index >= size {
                return Err("Invalid ELF dependency index.");
            }
            let bytes = at(
                file,
                locations[0] + index,
                (size - index).min(257) as usize,
                deadline,
            )?;
            let Some(end) = bytes.iter().position(|v| *v == 0) else {
                return Err("Unbounded ELF dependency name.");
            };
            let name = &bytes[..end];
            if !name.is_ascii() {
                return Err("Unapproved ELF dependency path.");
            }
            let name = std::str::from_utf8(name).map_err(|_| "Unapproved ELF dependency path.")?;
            if name.is_empty()
                || [".", ".."].contains(&name)
                || name.contains(['/', '\\', '\n', '\r'])
            {
                return Err("Unapproved ELF dependency path.");
            }
            if *tag == 14 {
                if soname.is_some() {
                    return Err("Ambiguous ELF library name.");
                }
                soname = Some(name.to_owned());
            } else {
                dependencies.push(name.to_owned());
            }
        }
    }
    if library {
        let trusted = system_library
            && soname.is_some()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0;
        let interpreter = programs.iter().any(|v| v[0] == 3);
        let pie = entries
            .iter()
            .any(|(tag, v)| *tag == 0x6ffffffb && v & 0x08000000 != 0);
        if kind != 3 || pie || (interpreter && !(trusted && soname.as_deref() == Some("libc.so.6")))
        {
            return Err("Program image is not a shared-library mapping exception.");
        }
    }
    Ok((soname, dependencies))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn inspection_stops_when_the_request_deadline_has_passed() {
        let mut file = File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        let metadata = file.metadata().unwrap();
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let error = inspect(&mut file, &metadata, false, false, deadline).unwrap_err();
        assert_eq!(
            error,
            "Linux executable mapping inspection deadline exceeded."
        );
    }
}
