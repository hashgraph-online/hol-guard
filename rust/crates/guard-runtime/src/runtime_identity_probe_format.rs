//! Operating system and architecture read from an executable's header bytes.
//!
//! Only the first bytes of the file are inspected. A script or an unrecognized
//! format reports the host operating system and an unknown architecture.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Format {
    pub(crate) os: &'static str,
    pub(crate) arch: &'static str,
}

/// Header bytes needed to classify ELF, Mach-O and PE files.
pub(crate) const HEADER_BYTES: usize = 4096;

pub(crate) fn sniff(header: &[u8]) -> Format {
    let host = host_os();
    if header.starts_with(b"\x7fELF") {
        return Format {
            os: "linux",
            arch: elf_arch(header),
        };
    }
    if let Some(arch) = macho_arch(header) {
        return Format { os: "macos", arch };
    }
    if header.starts_with(b"MZ") {
        return Format {
            os: "windows",
            arch: pe_arch(header),
        };
    }
    Format {
        os: host,
        arch: "unknown",
    }
}

fn host_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        _ => "unknown",
    }
}

fn read_u16(bytes: &[u8], at: usize, little: bool) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_u32(bytes: &[u8], at: usize, little: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn read_u64(bytes: &[u8], at: usize, little: bool) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at + 8)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

fn elf_arch(header: &[u8]) -> &'static str {
    let little = header.get(5) != Some(&2);
    match read_u16(header, 18, little) {
        Some(62) => "x64",
        Some(183) => "arm64",
        Some(3) => "x86",
        Some(40) => "arm",
        _ => "unknown",
    }
}

fn macho_arch(header: &[u8]) -> Option<&'static str> {
    let magic = read_u32(header, 0, false)?;
    let little = match magic {
        0xfeed_face | 0xfeed_facf => false,
        0xcefa_edfe | 0xcffa_edfe => true,
        // A universal binary holds several architectures; the one a launch
        // picks depends on the host, so it is not guessed here.
        0xcafe_babe => return universal_header(header, false).then_some("universal"),
        0xcafe_babf => return universal_header(header, true).then_some("universal"),
        _ => return None,
    };
    Some(match read_u32(header, 4, little) {
        Some(0x0100_0007) => "x64",
        Some(0x0100_000c) => "arm64",
        Some(7) => "x86",
        _ => "unknown",
    })
}

/// `0xcafebabe` is also the Java class magic, where the next word is a
/// minor/major version. A real fat header counts its entries and the first
/// entry must be sane: a known-shaped cpu type, an alignment power, and an
/// offset that lies past the entry table and on that alignment.
fn universal_header(header: &[u8], wide: bool) -> bool {
    let entry: u64 = if wide { 32 } else { 20 };
    let Some(count) = read_u32(header, 4, false) else {
        return false;
    };
    let table_end = 8 + u64::from(count) * entry;
    if count == 0 || table_end > HEADER_BYTES as u64 {
        return false;
    }
    let offset = if wide {
        read_u64(header, 16, false)
    } else {
        read_u32(header, 16, false).map(u64::from)
    };
    let align = read_u32(header, if wide { 32 } else { 24 }, false);
    match (read_u32(header, 8, false), offset, align) {
        (Some(cpu), Some(offset), Some(align)) => {
            cpu != 0 && align < 32 && offset >= table_end && offset % (1_u64 << align) == 0
        }
        _ => false,
    }
}

fn pe_arch(header: &[u8]) -> &'static str {
    let Some(offset) = read_u32(header, 0x3c, true).map(|v| v as usize) else {
        return "unknown";
    };
    if header.get(offset..offset + 4) != Some(b"PE\0\0") {
        return "unknown";
    }
    match read_u16(header, offset + 4, true) {
        Some(0x8664) => "x64",
        Some(0xaa64) => "arm64",
        Some(0x014c) => "x86",
        _ => "unknown",
    }
}
