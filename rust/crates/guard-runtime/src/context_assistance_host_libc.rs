//! Linux C library detection for choosing a managed interpreter build.
//!
//! Guard's Linux runtime is a static musl binary shipped in a manylinux
//! wheel, so its own compile target says nothing about the host. The C
//! library of the host is read from the dynamic loader a system program asks
//! for: `/bin/sh` first, then other base programs in case the shell is static.
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Libc {
    Gnu,
    Musl,
}

const PT_INTERP: u32 = 3;
const HEADER_LIMIT: u64 = 64 * 1024;

const PROGRAMS: [&str; 4] = ["/bin/sh", "/usr/bin/env", "/bin/ls", "/usr/bin/ls"];

pub(super) fn host_libc() -> Option<Libc> {
    PROGRAMS.iter().find_map(|program| program_libc(program))
}

fn program_libc(program: &str) -> Option<Libc> {
    let mut head = Vec::new();
    std::fs::File::open(program)
        .ok()?
        .take(HEADER_LIMIT)
        .read_to_end(&mut head)
        .ok()?;
    elf_interpreter(&head).and_then(|loader| classify(&loader))
}

fn classify(loader: &str) -> Option<Libc> {
    let name = loader.rsplit('/').next().unwrap_or(loader);
    if name.starts_with("ld-musl-") {
        Some(Libc::Musl)
    } else if name.starts_with("ld-linux") {
        Some(Libc::Gnu)
    } else {
        None
    }
}

/// Reads PT_INTERP from a little-endian ELF64 header prefix.
fn elf_interpreter(head: &[u8]) -> Option<String> {
    if head.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let u16_at = |at: usize| Some(u16::from_le_bytes(head.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(head.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| {
        let value = u64::from_le_bytes(head.get(at..at + 8)?.try_into().ok()?);
        usize::try_from(value).ok()
    };
    let table = u64_at(0x20)?;
    let size = usize::from(u16_at(0x36)?);
    if size < 56 {
        return None;
    }
    for index in 0..usize::from(u16_at(0x38)?) {
        let entry = table.checked_add(index.checked_mul(size)?)?;
        if u32_at(entry)? != PT_INTERP {
            continue;
        }
        let offset = u64_at(entry + 8)?;
        let length = u64_at(entry + 32)?;
        let raw = head.get(offset..offset.checked_add(length)?)?;
        let raw = raw.strip_suffix(b"\0").unwrap_or(raw);
        return std::str::from_utf8(raw).ok().map(str::to_owned);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_with_interpreter(loader: &str) -> Vec<u8> {
        let mut image = vec![0u8; 0x200];
        image[..6].copy_from_slice(b"\x7fELF\x02\x01");
        image[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        image[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        image[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        // First header is PT_LOAD, second is PT_INTERP.
        image[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        let interp = 0x40 + 56;
        let bytes = format!("{loader}\0");
        image[interp..interp + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        image[interp + 8..interp + 16].copy_from_slice(&0x100u64.to_le_bytes());
        image[interp + 32..interp + 40].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        image[0x100..0x100 + bytes.len()].copy_from_slice(bytes.as_bytes());
        image
    }

    #[test]
    fn loader_of_the_system_shell_names_the_c_library() {
        let glibc = elf_with_interpreter("/lib64/ld-linux-x86-64.so.2");
        let musl = elf_with_interpreter("/lib/ld-musl-aarch64.so.1");
        let other = elf_with_interpreter("/system/bin/linker64");
        assert_eq!(
            elf_interpreter(&glibc).as_deref().and_then(classify),
            Some(Libc::Gnu)
        );
        assert_eq!(
            elf_interpreter(&musl).as_deref().and_then(classify),
            Some(Libc::Musl)
        );
        assert_eq!(elf_interpreter(&other).as_deref().and_then(classify), None);
    }

    #[test]
    fn truncated_or_foreign_headers_are_not_guessed() {
        let image = elf_with_interpreter("/lib/ld-musl-x86_64.so.1");
        assert_eq!(elf_interpreter(&image[..0x90]), None);
        assert_eq!(elf_interpreter(b"#!/bin/busybox sh\n"), None);
        let mut big_endian = image.clone();
        big_endian[5] = 2;
        assert_eq!(elf_interpreter(&big_endian), None);
        let mut short_entries = image;
        short_entries[0x36..0x38].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(elf_interpreter(&short_entries), None);
    }
}
