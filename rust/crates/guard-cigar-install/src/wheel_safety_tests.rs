use super::*;
use crate::tests::control;
use guard_cigar_release::WheelSource;
use std::io::Write;
use zip::{write::SimpleFileOptions, ZipWriter};

fn stored() -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "payload.txt",
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
        )
        .unwrap();
    writer.write_all(b"UNIQUE_PAYLOAD_FOR_CRC").unwrap();
    writer.finish().unwrap().into_inner()
}
fn central(bytes: &[u8]) -> usize {
    bytes.windows(4).position(|b| b == b"PK\x01\x02").unwrap()
}
fn read_failure(bytes: &[u8]) -> InstallError {
    let lock = WheelLock {
        distribution: "hol-cigar".into(),
        version: "0.15.2".into(),
        filename: "hol_cigar-0.15.2-py3-none-any.whl".into(),
        sha256: "0".repeat(64),
        bytes: bytes.len() as u64,
        requires_python: None,
        source: WheelSource::OfflineBundle,
    };
    read(
        bytes,
        &lock,
        &mut BTreeMap::new(),
        &mut BTreeMap::new(),
        &mut 0u64,
        &control(),
    )
    .unwrap_err()
}
#[test]
fn member_count_and_zip64_or_multidisk_envelopes_are_refused_before_indexing() {
    let mut bytes = stored();
    let footer = bytes.len() - 22;
    let too_many = (MAX_FILES as u16 + 1).to_le_bytes();
    bytes[footer + 8..footer + 10].copy_from_slice(&too_many);
    bytes[footer + 10..footer + 12].copy_from_slice(&too_many);
    assert_eq!(read_failure(&bytes), InstallError::LimitExceeded);
    let mut bytes = stored();
    let footer = bytes.len() - 22;
    bytes[footer + 4] = 1;
    assert_eq!(read_failure(&bytes), InstallError::LimitExceeded);
    bytes[footer + 4] = 0;
    bytes[footer + 10..footer + 12].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(read_failure(&bytes), InstallError::LimitExceeded);
}
#[test]
fn symlink_and_device_external_modes_cannot_become_output_files() {
    for kind in [0o120777u32, 0o020600, 0o060600, 0o010600] {
        let mut bytes = stored();
        let central = central(&bytes);
        bytes[central + 5] = 3; // ZIP "made by Unix" system.
        bytes[central + 38..central + 42].copy_from_slice(&(kind << 16).to_le_bytes());
        assert_eq!(read_failure(&bytes), InstallError::EntryUnsafe);
    }
}
#[test]
fn declared_member_expansion_is_bounded_before_reading_content() {
    let mut bytes = stored();
    let central = central(&bytes);
    let size = (MAX_FILE_BYTES as u32 + 1).to_le_bytes();
    bytes[central + 24..central + 28].copy_from_slice(&size);
    bytes[22..26].copy_from_slice(&size);
    assert_eq!(read_failure(&bytes), InstallError::LimitExceeded);
}
#[test]
fn crc_failure_truncation_and_password_encryption_are_refused() {
    let mut bytes = stored();
    let payload = b"UNIQUE_PAYLOAD_FOR_CRC";
    let content = bytes
        .windows(payload.len())
        .position(|b| b == payload)
        .unwrap();
    bytes[content] ^= 1;
    assert_eq!(read_failure(&bytes), InstallError::ArchiveInvalid);
    let bytes = stored();
    assert_eq!(
        read_failure(&bytes[..bytes.len() - 1]),
        InstallError::ArchiveInvalid
    );
    let mut bytes = stored();
    let central = central(&bytes);
    bytes[6] |= 1;
    bytes[central + 8] |= 1;
    assert!(matches!(
        read_failure(&bytes),
        InstallError::ArchiveInvalid | InstallError::WheelUnsupported
    ));
}
