//! Package manifest, lockfile and bin-target readers shared by the runner
//! evidence builders.
//!
//! Faithful port of `runtime/package_evidence_common.py`.

use std::fmt;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use base64::Engine;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::jsonc::normalize_jsonc;

const MAX_MANIFEST_JSON_BYTES: u64 = 16 * 1024 * 1024;

/// JSON value whose objects reject duplicate keys (`_unique_json_pairs`).
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
                Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
            }

            fn visit_str<E>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(UniqueValue(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut result = Map::new();
                while let Some((key, UniqueValue(value))) =
                    map.next_entry::<String, UniqueValue>()?
                {
                    if result.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate package identity key"));
                    }
                    result.insert(key, value);
                }
                Ok(Value::Object(result))
            }
        }

        deserializer.deserialize_any(UniqueVisitor).map(UniqueValue)
    }
}

fn parse_unique(text: &str, allow_jsonc: bool) -> Option<Value> {
    let normalized;
    let source = if allow_jsonc {
        normalized = normalize_jsonc(text).ok()?;
        normalized.as_str()
    } else {
        text
    };
    serde_json::from_str::<UniqueValue>(source)
        .ok()
        .map(|value| value.0)
}

/// Read a manifest through a verified descriptor; return the object payload
/// (if the document is an object) and its `sha256:` digest.
pub(crate) fn read_json_with_integrity(
    path: &Path,
    allow_jsonc: bool,
) -> (Option<Map<String, Value>>, Option<String>) {
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
    else {
        return (None, None);
    };
    let Ok(before) = file.metadata() else {
        return (None, None);
    };
    if !before.is_file() || before.nlink() != 1 || before.size() > MAX_MANIFEST_JSON_BYTES {
        return (None, None);
    }
    let mut content = Vec::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                content.extend_from_slice(&chunk[..count]);
                if content.len() as u64 > MAX_MANIFEST_JSON_BYTES {
                    return (None, None);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (None, None),
        }
    }
    let Ok(after) = file.metadata() else {
        return (None, None);
    };
    let identity = |meta: &std::fs::Metadata| {
        (
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
        )
    };
    if identity(&before) != identity(&after) {
        return (None, None);
    }
    let Ok(decoded) = std::str::from_utf8(&content) else {
        return (None, None);
    };
    let Some(payload) = parse_unique(decoded, allow_jsonc) else {
        return (None, None);
    };
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
    (payload.as_object().cloned(), Some(digest))
}

/// `version_spec_matches` with `^(?:[~^])?(\d+)\.(\d+)\.(\d+)$`.
pub(crate) fn version_spec_matches(
    specifier: Option<&str>,
    version: Option<&str>,
    caret_pins_zero_major: bool,
) -> bool {
    let (Some(specifier), Some(version)) = (specifier, version) else {
        return false;
    };
    let (Some(spec_parts), Some(version_parts)) = (semver_parts(specifier), semver_parts(version))
    else {
        return false;
    };
    if specifier.starts_with('^') {
        if spec_parts[0] > 0 {
            return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
        }
        if caret_pins_zero_major {
            if spec_parts[1] > 0 {
                return version_parts >= spec_parts && version_parts[..2] == spec_parts[..2];
            }
            return version_parts == spec_parts;
        }
        return version_parts >= spec_parts && version_parts[0] == spec_parts[0];
    }
    if specifier.starts_with('~') {
        return version_parts >= spec_parts && version_parts[..2] == spec_parts[..2];
    }
    version_parts == spec_parts
}

fn semver_parts(value: &str) -> Option<[u128; 3]> {
    let body = value.strip_prefix(['~', '^']).unwrap_or(value);
    let mut parts = body.split('.');
    let mut result = [0u128; 3];
    for slot in &mut result {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(result)
}

/// A syntactically valid 64-byte SRI SHA-512 digest.
pub(crate) fn valid_sha512_integrity(value: Option<&Value>) -> bool {
    let Some(text) = value.and_then(Value::as_str) else {
        return false;
    };
    let Some(encoded) = text.strip_prefix("sha512-") else {
        return false;
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .is_ok_and(|decoded| decoded.len() == 64)
}

/// `Path.resolve(strict=False)` for paths without `..` components.
pub(crate) fn weak_resolve(path: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut existing = path.to_path_buf();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(&existing) {
            let mut result = canonical;
            for part in tail.iter().rev() {
                result.push(part);
            }
            return result;
        }
        match (
            existing.file_name().map(ToOwned::to_owned),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                tail.push(name);
                existing = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Resolve a relative package bin target without allowing root escape.
pub(crate) fn resolved_package_bin_target(
    package_root: &Path,
    target: Option<&str>,
) -> Option<PathBuf> {
    let portable = target?.replace('\\', "/");
    if portable.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = portable
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        return None;
    }
    let mut candidate = package_root.to_path_buf();
    candidate.extend(&parts);
    let resolved = weak_resolve(&candidate);
    resolved
        .components()
        .collect::<Vec<Component>>()
        .starts_with(&package_root.components().collect::<Vec<Component>>())
        .then_some(resolved)
}

/// `object_mapping(value)` for nested values.
pub(crate) fn object_of(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

/// `value.strip()` when a non-blank string, as the evidence helpers return it.
pub(crate) fn stripped(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Package `bin` target for `runner` (`_package_bin_target`).
pub(crate) fn package_bin_target(
    payload: Option<&Map<String, Value>>,
    runner: &str,
) -> Option<String> {
    let value = payload?.get("bin");
    if let Some(text) = stripped(value).filter(|_| value.is_some_and(Value::is_string)) {
        return Some(text);
    }
    stripped(object_of(value)?.get(runner))
}

/// The exact `https://registry.npmjs.org/{package}/-/{tarball}-{version}.tgz`
/// tarball URL. Stricter than the Python URL parse: no spelling variants.
pub(crate) fn canonical_registry_resolution(
    package: &str,
    version: &str,
    resolved: Option<&Value>,
) -> bool {
    let Some(text) = resolved.and_then(Value::as_str) else {
        return false;
    };
    let tarball = package.rsplit('/').next().unwrap_or(package);
    text == format!("https://registry.npmjs.org/{package}/-/{tarball}-{version}.tgz")
}
