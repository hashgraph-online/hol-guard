//! Grant identity for unlisted local CLIs.
//!
//! Local CLI grants match on the `cli_id` and `identity_hash` derived here.
//! The encoding must stay byte-identical to the identities already stored in
//! user grants: canonical JSON with sorted keys and ASCII escapes, SHA-256 of
//! the UTF-8 path for fingerprints, and the historical slug rules.

use guard_contracts::{LocalCliIdentitySourceV1, LocalCliIdentityV1};
use guard_policy_snapshot::digest_bytes;
use serde_json::{Map, Value};

use super::context_digest_json::write_canonical_json;

const SLUG_MAX: usize = 32;
const SLUG_MAX_PARTS: usize = 8;
const REGISTRY_PACKAGE_CLI_PREFIX: &str = "local-cli.npm-";
const PACKAGE_SCRIPT_SURFACE: &str = "package-scripts";
const PACKAGE_SCRIPT_KINDS: [&str; 1] = ["bun-package-script"];
const INLINE_KINDS: [&str; 4] = ["python-c", "python-m", "node-eval", "inline-script"];

pub(super) fn local_cli_identity(
    source: &LocalCliIdentitySourceV1,
) -> Result<Option<LocalCliIdentityV1>, &'static str> {
    match source {
        LocalCliIdentitySourceV1::Script { entrypoint } => script_identity(entrypoint),
        LocalCliIdentitySourceV1::Executable { executable, name } => {
            executable_identity(executable, name)
        }
        LocalCliIdentitySourceV1::RunnerLocalBin {
            name,
            package_name,
            local_bin,
        } => runner_local_bin_identity(name, package_name, local_bin),
        LocalCliIdentitySourceV1::RegistryPackage { name, package_name } => {
            registry_package_identity(name, package_name).map(Some)
        }
        LocalCliIdentitySourceV1::PackageJson {
            manifest_path,
            content_sha256,
            package_name,
        } => package_json_identity(manifest_path, content_sha256, package_name),
    }
}

fn script_identity(entrypoint: &Value) -> Result<Option<LocalCliIdentityV1>, &'static str> {
    let Some(entrypoint) = entrypoint.as_object() else {
        return Ok(None);
    };
    let kind = string_field(entrypoint, "kind");
    if string_field(entrypoint, "status") != "verified" || !is_script_kind(kind) {
        return Ok(None);
    }
    let (Some(digest), Some(path)) = (
        sha256_hex(entrypoint.get("sha256")),
        nonempty_string(entrypoint.get("path")),
    ) else {
        return Ok(None);
    };
    let name = python_path_name(path);
    let fingerprint = path_fingerprint(path);
    let identity_hash = identity_digest(&[
        ("kind", Value::from("script")),
        ("entrypoint_kind", Value::from(kind)),
        ("content_sha256", Value::from(digest)),
        ("path_fingerprint", Value::from(fingerprint.as_str())),
    ])?;
    Ok(Some(LocalCliIdentityV1 {
        cli_id: format!(
            "local-cli.{}-{}",
            slug(&name, SLUG_MAX_PARTS),
            &fingerprint[..8]
        ),
        name,
        kind: "script".to_owned(),
        identity_hash,
    }))
}

fn executable_identity(
    executable: &Value,
    name: &str,
) -> Result<Option<LocalCliIdentityV1>, &'static str> {
    let Some(executable) = executable.as_object() else {
        return Ok(None);
    };
    if string_field(executable, "status") != "verified" {
        return Ok(None);
    }
    let (Some(digest), Some(path)) = (
        sha256_hex(executable.get("sha256")),
        nonempty_string(executable.get("path")),
    ) else {
        return Ok(None);
    };
    let fingerprint = path_fingerprint(path);
    let identity_hash = identity_digest(&[
        ("kind", Value::from("executable")),
        ("content_sha256", Value::from(digest)),
        ("path_fingerprint", Value::from(fingerprint.as_str())),
    ])?;
    Ok(Some(LocalCliIdentityV1 {
        cli_id: format!(
            "local-cli.{}-{}",
            slug(name, SLUG_MAX_PARTS),
            &fingerprint[..8]
        ),
        name: name.to_owned(),
        kind: "executable".to_owned(),
        identity_hash,
    }))
}

fn runner_local_bin_identity(
    name: &str,
    package_name: &str,
    local_bin: &Value,
) -> Result<Option<LocalCliIdentityV1>, &'static str> {
    let Some(local_bin) = local_bin.as_object() else {
        return Ok(None);
    };
    let digest = local_bin
        .get("content_hash")
        .and_then(Value::as_str)
        .map(|hash| Value::from(hash.strip_prefix("sha256:").unwrap_or(hash)));
    let (Some(path), Some(digest)) = (
        nonempty_string(local_bin.get("resolved_path")),
        sha256_hex(digest.as_ref()),
    ) else {
        return Ok(None);
    };
    let fingerprint = path_fingerprint(path);
    let identity_hash = identity_digest(&[
        ("kind", Value::from("executable")),
        ("content_sha256", Value::from(digest)),
        ("path_fingerprint", Value::from(fingerprint.as_str())),
        ("package_name", Value::from(package_name)),
        (
            "installed_version",
            local_bin
                .get("installed_version")
                .cloned()
                .unwrap_or(Value::Null),
        ),
    ])?;
    Ok(Some(LocalCliIdentityV1 {
        cli_id: format!(
            "local-cli.{}-{}",
            slug(name, SLUG_MAX_PARTS),
            &fingerprint[..8]
        ),
        name: name.to_owned(),
        kind: "executable".to_owned(),
        identity_hash,
    }))
}

fn registry_package_identity(
    name: &str,
    package_name: &str,
) -> Result<LocalCliIdentityV1, &'static str> {
    let fingerprint = path_fingerprint(&format!("npm:{package_name}"));
    let identity_hash = identity_digest(&[
        ("kind", Value::from("registry-package")),
        ("package_name", Value::from(package_name)),
    ])?;
    Ok(LocalCliIdentityV1 {
        cli_id: format!(
            "{REGISTRY_PACKAGE_CLI_PREFIX}{}-{}",
            slug(name, SLUG_MAX_PARTS - 1),
            &fingerprint[..8]
        ),
        name: name.to_owned(),
        kind: "executable".to_owned(),
        identity_hash,
    })
}

fn package_json_identity(
    manifest_path: &str,
    content_sha256: &str,
    package_name: &str,
) -> Result<Option<LocalCliIdentityV1>, &'static str> {
    let content = Value::from(content_sha256);
    let Some(digest) = sha256_hex(Some(&content)) else {
        return Ok(None);
    };
    let fingerprint = path_fingerprint(manifest_path);
    let compact: String = package_name
        .to_lowercase()
        .chars()
        .filter(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        .take(16)
        .collect();
    let compact = if compact.is_empty() {
        "app".to_owned()
    } else {
        compact
    };
    let identity_hash = identity_digest(&[
        ("kind", Value::from(PACKAGE_SCRIPT_SURFACE)),
        ("content_sha256", Value::from(digest)),
        ("path_fingerprint", Value::from(fingerprint.as_str())),
    ])?;
    Ok(Some(LocalCliIdentityV1 {
        cli_id: format!("local-cli.pkg-{compact}-{}", &fingerprint[..8]),
        name: package_name.chars().take(120).collect(),
        kind: "script".to_owned(),
        identity_hash,
    }))
}

fn is_script_kind(kind: &str) -> bool {
    if PACKAGE_SCRIPT_KINDS.contains(&kind) || INLINE_KINDS.contains(&kind) {
        return false;
    }
    kind.ends_with("-script") || kind == "direct-script"
}

/// `str(mapping.get(key) or "")` for the string values a launch identity carries.
fn string_field<'a>(mapping: &'a Map<String, Value>, key: &str) -> &'a str {
    mapping.get(key).and_then(Value::as_str).unwrap_or("")
}

fn sha256_hex(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    (text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(text)
}

/// Python `value.strip()` when the stripped string is non-empty.
fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    let stripped = value?.as_str()?.trim_matches(python_whitespace);
    (!stripped.is_empty()).then_some(stripped)
}

/// `str.isspace()` adds the ASCII information separators to Unicode
/// White_Space, which is what `char::is_whitespace` implements.
fn python_whitespace(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// `pathlib.Path(path).name`: the last non-empty, non-`.` component.
fn python_path_name(path: &str) -> String {
    #[cfg(windows)]
    let path = {
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            &path[2..]
        } else {
            path
        }
    };
    path.split(|character| character == '/' || (cfg!(windows) && character == '\\'))
        .filter(|part| !part.is_empty() && *part != ".")
        .next_back()
        .unwrap_or("")
        .to_owned()
}

fn slug(value: &str, max_parts: usize) -> String {
    let lowered = value.to_lowercase();
    let mut compact = String::with_capacity(lowered.len());
    for character in lowered.chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            compact.push(character);
        } else if !compact.ends_with('-') {
            compact.push('-');
        }
    }
    let compact = compact.trim_matches('-');
    if compact.is_empty() {
        return "cli".to_owned();
    }
    let trimmed = compact[..compact.len().min(SLUG_MAX)].trim_matches('-');
    let joined = trimmed
        .split('-')
        .take(max_parts)
        .collect::<Vec<_>>()
        .join("-");
    if joined.is_empty() {
        "cli".to_owned()
    } else {
        joined
    }
}

fn path_fingerprint(path: &str) -> String {
    digest_bytes(path.as_bytes())
}

fn identity_digest(fields: &[(&str, Value)]) -> Result<String, &'static str> {
    let material: Map<String, Value> = fields
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect();
    let mut bytes = Vec::with_capacity(256);
    write_canonical_json(&Value::Object(material), &mut bytes)?;
    Ok(digest_bytes(&bytes))
}

#[cfg(test)]
#[path = "context_digest_local_cli_tests.rs"]
mod tests;
