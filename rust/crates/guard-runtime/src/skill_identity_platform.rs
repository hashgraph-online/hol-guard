//! Safe platform bindings for the skill-tree walker and its wire paths.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};

use crate::skill_identity_canon::Failure;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StatKey {
    material: [i128; 8],
    #[cfg(windows)]
    file_id: Option<guard_runtime_windows_process::FileId>,
}

#[cfg(unix)]
pub(crate) fn stat_key(_path: &Path, metadata: &Metadata) -> Result<StatKey, Failure> {
    use std::os::unix::fs::MetadataExt;
    Ok(StatKey {
        material: [
            i128::from(metadata.dev()),
            i128::from(metadata.ino()),
            i128::from(metadata.mode()),
            i128::from(metadata.nlink()),
            i128::from(metadata.len()),
            i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
            i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
            0,
        ],
    })
}

#[cfg(windows)]
fn windows_material(metadata: &Metadata) -> [i128; 8] {
    use std::os::windows::fs::MetadataExt;
    [
        i128::from(metadata.file_attributes()),
        i128::from(metadata.creation_time()),
        i128::from(metadata.last_write_time()),
        i128::from(metadata.file_size()),
        0,
        0,
        0,
        0,
    ]
}

#[cfg(windows)]
pub(crate) fn stat_key(path: &Path, metadata: &Metadata) -> Result<StatKey, Failure> {
    let mut material = windows_material(metadata);
    let file_id = if metadata.file_type().is_symlink() {
        None
    } else if metadata.is_dir() {
        Some(
            guard_runtime_windows_process::directory_file_id(path)
                .map_err(|_| Failure::UnreadableEntry)?,
        )
    } else if metadata.is_file() {
        let (identity, links) = guard_runtime_windows_process::regular_file_id(path, false)
            .map_err(|_| Failure::TreeChangedDuringHash)?;
        material[4] = i128::from(links);
        Some(identity)
    } else {
        None
    };
    Ok(StatKey { material, file_id })
}

pub(crate) fn opened_stat_key(path: &Path, file: &File) -> Result<StatKey, Failure> {
    let metadata = file.metadata().map_err(|_| Failure::UnreadableEntry)?;
    #[cfg(unix)]
    {
        stat_key(path, &metadata)
    }
    #[cfg(windows)]
    {
        let key = stat_key(path, &metadata)?;
        if key.file_id
            != Some(
                guard_runtime_windows_process::handle_file_id(file)
                    .map_err(|_| Failure::TreeChangedDuringHash)?,
            )
        {
            return Err(Failure::TreeChangedDuringHash);
        }
        Ok(key)
    }
}

pub(crate) fn security_mode(metadata: &Metadata) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(format!("{:04o}", metadata.mode() & 0o7777))
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        None
    }
}

pub(crate) fn unsupported_reparse(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 && !metadata.file_type().is_symlink()
    }
    #[cfg(unix)]
    {
        let _ = metadata;
        false
    }
}

pub(crate) fn link_loop(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(1921)
    }
}

#[cfg(unix)]
pub(crate) struct DirectoryGuard;
#[cfg(windows)]
pub(crate) type DirectoryGuard = File;

pub(crate) fn directory_guard(path: &Path) -> Result<DirectoryGuard, Failure> {
    #[cfg(unix)]
    {
        let _ = path;
        Ok(DirectoryGuard)
    }
    #[cfg(windows)]
    {
        // Pin the skill directory itself. Walking every ancestor rejects a
        // junction or synced folder above the skill, which the scan never
        // follows.
        guard_runtime_windows_process::open_skill_directory(path)
            .map_err(|_| Failure::UnreadableEntry)
    }
}

pub(crate) fn open_regular(path: &Path) -> Result<File, Failure> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(open_failure)
    }
    #[cfg(windows)]
    {
        // Skill trees can contain ordinary hardlinks. This existing primitive
        // pins the same bytes without imposing the private-storage one-link rule.
        for attempt in 0..6 {
            match guard_runtime_windows_process::open_bound_executable_file(path) {
                Ok(file) => return Ok(file),
                Err(error) if error.raw_os_error() == Some(32) && attempt < 5 => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(open_failure(error)),
            }
        }
        unreachable!("bounded open always returns")
    }
}

fn open_failure(error: std::io::Error) -> Failure {
    if error.kind() == std::io::ErrorKind::NotFound {
        Failure::TreeChangedDuringHash
    } else {
        Failure::UnreadableEntry
    }
}

pub(crate) fn relative_to(path: &Path, root: &Path) -> Result<PathBuf, Failure> {
    #[cfg(unix)]
    {
        path.strip_prefix(root)
            .map(Path::to_path_buf)
            .map_err(|_| Failure::SymlinkEscape)
    }
    #[cfg(windows)]
    {
        if !guard_runtime_windows_process::path_is_within(path, root) {
            return Err(Failure::SymlinkEscape);
        }
        Ok(path.components().skip(root.components().count()).collect())
    }
}

/// Byte spelling used by Python's fsencode and the existing discovery DTO.
pub(crate) fn path_bytes(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut bytes = Vec::new();
        for scalar in char::decode_utf16(value.encode_wide()) {
            match scalar {
                Ok(character) => {
                    let mut buffer = [0; 4];
                    bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                }
                Err(error) => {
                    let value = u32::from(error.unpaired_surrogate());
                    bytes.extend_from_slice(&[
                        (0xe0 | (value >> 12)) as u8,
                        (0x80 | ((value >> 6) & 0x3f)) as u8,
                        (0x80 | (value & 0x3f)) as u8,
                    ]);
                }
            }
        }
        bytes
    }
}

pub(crate) fn decode_path_hex(value: &str, encoding: &str) -> Result<PathBuf, &'static str> {
    let path = decode_relative_path_hex(value, encoding)?;
    if !path.is_absolute() {
        return Err("native_skill_directory_identity_path_invalid");
    }
    Ok(path)
}

/// `decode_path_hex` for a path the caller may hold relative to its own
/// working directory. The caller sends that directory alongside, so the raw
/// components stay exactly as the caller sees them.
pub(crate) fn decode_relative_path_hex(
    value: &str,
    encoding: &str,
) -> Result<PathBuf, &'static str> {
    let bytes = hex::decode(value).map_err(|_| "native_skill_directory_identity_path_invalid")?;
    #[cfg(unix)]
    let decoded = {
        use std::os::unix::ffi::OsStringExt;
        if encoding != "os_bytes" || bytes.contains(&0) {
            return Err("native_skill_directory_identity_path_invalid");
        }
        OsString::from_vec(bytes)
    };
    #[cfg(windows)]
    let decoded = {
        use std::os::windows::ffi::OsStringExt;
        if encoding != "utf16le" || bytes.len() % 2 != 0 {
            return Err("native_skill_directory_identity_path_invalid");
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if units.contains(&0) {
            return Err("native_skill_directory_identity_path_invalid");
        }
        OsString::from_wide(&units)
    };
    let path = PathBuf::from(decoded);
    if path.as_os_str().is_empty() {
        return Err("native_skill_directory_identity_path_invalid");
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::{
        SkillDirectoryIdentityRequestV1, SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA,
    };
    use serde_json::{json, Value};

    fn encoding(path: &Path) -> (&'static str, String) {
        #[cfg(unix)]
        {
            ("os_bytes", hex::encode(path_bytes(path.as_os_str())))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let bytes: Vec<u8> = path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect();
            ("utf16le", hex::encode(bytes))
        }
    }

    #[test]
    fn encoded_paths_reject_relative_nul_and_wrong_encoding() {
        let (kind, relative) = encoding(Path::new("relative"));
        assert!(decode_path_hex(&relative, kind).is_err());
        assert!(decode_path_hex("00", kind).is_err());
        assert!(decode_path_hex("zz", kind).is_err());
        assert!(decode_path_hex("00", "unknown").is_err());
        let root = std::env::temp_dir();
        let (kind, encoded) = encoding(&root);
        assert_eq!(decode_path_hex(&encoded, kind).unwrap(), root);
    }

    #[test]
    fn native_portable_basic_digest_matches_original() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/skill_directory_portable_vectors.json"
        ))
        .unwrap();
        let case = fixture["inspect"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "basic")
            .unwrap();
        let base = std::env::temp_dir().join(format!(
            "skill-portable-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(base.join("skills/example")).unwrap();
        let document = base.join("skills/example/SKILL.md");
        std::fs::write(&document, case["entries"][0]["content"].as_str().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&document, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let (kind, document_hex) = encoding(&document);
        let (_, scope_hex) = encoding(&base);
        let request: SkillDirectoryIdentityRequestV1 = serde_json::from_value(json!({
            "schema": SKILL_DIRECTORY_IDENTITY_REQUEST_SCHEMA, "request_id": "fixture", "guard_home": base,
            "command": {"kind": "inspect_encoded", "skill_document_hex": document_hex,
                "scope_root_hex": scope_hex, "path_encoding": kind,
                "limits": {"max_depth": 32, "max_entries": 4096, "max_file_bytes": 134217728, "max_total_bytes": 268435456}}
        })).unwrap();
        let reply: Value = serde_json::from_slice(
            &crate::skill_directory_identity_op::evaluate_skill_directory_identity_request(
                &request,
            )
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        let expected = &case["expected"];
        #[cfg(windows)]
        let expected = &case["expected_windows_mode_projection"];
        assert_eq!(reply["payload"], *expected);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
