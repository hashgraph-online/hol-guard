//! `local-skill-index --stdin`: the daemon's explicitly scoped skill metadata
//! index (`guard/runtime/local_skill_index.py` before it moved here).
//!
//! - `index` discovers the primary skill documents below each approved root
//!   and reads each one's bounded frontmatter: name, description,
//!   compatibility, requested tools, a digest of the header and the declared
//!   tool dependencies. A root reached through a link, an unreadable or
//!   malformed document and the index ceiling become static issue codes;
//!   no raw file or parser text is ever returned.
//! - `inspect` re-reads one indexed document, hashes its complete skill
//!   directory and re-reads it again, answering `skill-metadata-changed`
//!   when the header moved under either read.
//!
//! Nothing here loads instructions, runs a script or grants a permission.
//! Paths travel as OS-native hex (`os_bytes` on Unix, `utf16le` on Windows),
//! as the skill directory identity contract carries them.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_command::attestation_timestamp::python_strip;
use guard_command::skill_dependency_manifest::parse_dependencies;
use guard_contracts::SkillDirectoryLimitsV1;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::aibom_symlink::path_has_symlink_component;
use crate::hermes_inspect::{parse_yaml_mapping, stat_key};
use crate::pyjson::PyVal;
use crate::skill_identity_discovery::discover_skill_documents;
use crate::skill_identity_inspect::inspect_skill_directory;
use crate::skill_identity_platform::decode_path_hex;

const SCHEMA: &str = "local-skill-index.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_ROOTS: usize = 64;
const HEADER_BYTES: usize = 16_384;
const INDEX_LIMIT: usize = 1000;
const DISCOVERY_LIMITS: SkillDirectoryLimitsV1 = SkillDirectoryLimitsV1 {
    max_depth: 8,
    max_entries: 1024,
    max_file_bytes: 128 * 1024 * 1024,
    max_total_bytes: 256 * 1024 * 1024,
};
const INSPECTION_LIMITS: SkillDirectoryLimitsV1 = SkillDirectoryLimitsV1 {
    max_depth: 16,
    max_entries: 4096,
    max_file_bytes: 16 * 1024 * 1024,
    max_total_bytes: 16 * 1024 * 1024,
};
const UNREADABLE: &str = "metadata-unreadable";
const CHANGED_DURING_READ: &str = "metadata-changed-during-read";
const INVALID_FRONTMATTER: &str = "metadata-invalid-frontmatter";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    path_encoding: String,
    home_hex: String,
    #[serde(default)]
    roots: Vec<RootRequest>,
    #[serde(default)]
    document_hex: Option<String>,
    #[serde(default)]
    root_hex: Option<String>,
    #[serde(default)]
    metadata_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootRequest {
    root_id: String,
    root_hex: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "local-skill-index"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "local_skill_index_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("local_skill_index_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request)?;
    serde_json::to_vec(&answer).map_err(|_| "local_skill_index_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "local_skill_index_request_invalid".to_owned()
}

fn path(value: &str, encoding: &str) -> Result<PathBuf, String> {
    decode_path_hex(value, encoding).map_err(|_| invalid())
}

fn answer(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let encoding = request.path_encoding.as_str();
    let home = path(&request.home_hex, encoding)?;
    match request.op.as_str() {
        "index"
            if (1..=MAX_ROOTS).contains(&request.roots.len())
                && request.document_hex.is_none()
                && request.root_hex.is_none()
                && request.metadata_digest.is_none() =>
        {
            let mut roots = Vec::with_capacity(request.roots.len());
            for root in &request.roots {
                if root.root_id.is_empty() || root.root_id.len() > 128 {
                    return Err(invalid());
                }
                roots.push((root.root_id.as_str(), path(&root.root_hex, encoding)?));
            }
            Ok(index(&home, &roots))
        }
        "inspect" if request.roots.is_empty() => {
            let document = path(
                request.document_hex.as_deref().ok_or_else(invalid)?,
                encoding,
            )?;
            let root = path(request.root_hex.as_deref().ok_or_else(invalid)?, encoding)?;
            let digest = request.metadata_digest.as_deref().ok_or_else(invalid)?;
            Ok(inspect(&document, &root, &home, digest)
                .unwrap_or_else(|code| json!({ "error": code })))
        }
        _ => Err(invalid()),
    }
}

fn issue(root_id: &str, reason: &str) -> Value {
    json!({ "root_id": root_id, "reason": reason })
}

fn index(home: &Path, roots: &[(&str, PathBuf)]) -> Value {
    let mut records: Vec<Value> = Vec::new();
    let mut issues: Vec<Value> = Vec::new();
    'roots: for (root_id, root) in roots {
        if path_has_symlink_component(root, home) {
            issues.push(issue(root_id, "linked-root-not-indexed"));
            continue;
        }
        let discovery = discover_skill_documents(root, &DISCOVERY_LIMITS);
        issues.extend(
            discovery
                .issues
                .iter()
                .map(|found| issue(root_id, found.failure_reason.as_str())),
        );
        for document_hex in &discovery.documents_hex {
            if records.len() >= INDEX_LIMIT {
                issues.push(issue(root_id, "skill-index-limit"));
                break 'roots;
            }
            let metadata = relative_path(document_hex)
                .ok_or(UNREADABLE)
                .and_then(|relative| read_metadata(&root.join(relative), root));
            match metadata {
                Ok(metadata) => records.push(json!({
                    "root_id": root_id,
                    "document_hex": document_hex,
                    "metadata": metadata,
                })),
                Err(code) => issues.push(issue(root_id, code)),
            }
        }
    }
    json!({ "records": records, "issues": issues })
}

/// The `/`-joined document path discovery reports below its root.
fn relative_path(document_hex: &str) -> Option<PathBuf> {
    let bytes = hex::decode(document_hex).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

fn inspect(document: &Path, root: &Path, home: &Path, digest: &str) -> Result<Value, &'static str> {
    if path_has_symlink_component(document, home) {
        return Err("linked-skill-not-inspected");
    }
    let changed = |metadata: Value| metadata["metadata_digest"].as_str() != Some(digest);
    if changed(read_metadata(document, root)?) {
        return Err("skill-metadata-changed");
    }
    let identity = inspect_skill_directory(document, root, &INSPECTION_LIMITS);
    if changed(read_metadata(document, root)?) {
        return Err("skill-metadata-changed");
    }
    Ok(json!({
        "identity": {
            "status": identity.status,
            "manifest_digest": identity.directory_hash,
            "entry_count": identity.entry_count,
            "total_bytes": identity.total_bytes,
            "reason": identity.failure_reason.map(|reason| reason.as_str()),
        }
    }))
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    // Share read only: no writer or deleter can change the file under the read.
    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Read one primary document's bounded frontmatter, refusing a linked,
/// irregular or concurrently replaced file.
fn read_metadata(document: &Path, root: &Path) -> Result<Value, &'static str> {
    if path_has_symlink_component(document, root) {
        return Err("linked-skill-not-indexed");
    }
    let before = fs::symlink_metadata(document).map_err(|_| UNREADABLE)?;
    if !before.file_type().is_file() {
        return Err("metadata-not-regular-file");
    }
    let file = open_no_follow(document).map_err(|_| UNREADABLE)?;
    let opened = file.metadata().map_err(|_| UNREADABLE)?;
    // Windows reports a handle's stat differently from a path's, so only
    // Unix compares the two directly; both compare like with like below.
    if cfg!(unix) && stat_key(&opened) != stat_key(&before) {
        return Err(CHANGED_DURING_READ);
    }
    let mut raw = Vec::with_capacity(HEADER_BYTES + 1);
    (&file)
        .take(HEADER_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| UNREADABLE)?;
    if stat_key(&file.metadata().map_err(|_| UNREADABLE)?) != stat_key(&opened)
        || stat_key(&fs::symlink_metadata(document).map_err(|_| UNREADABLE)?) != stat_key(&before)
    {
        return Err(CHANGED_DURING_READ);
    }
    drop(file);
    raw.truncate(HEADER_BYTES);
    let header = frontmatter(&raw)?;
    let header = std::str::from_utf8(&header).map_err(|_| "metadata-invalid-utf8")?;
    let parsed = match parse_yaml_mapping(header) {
        Ok(Some(entries)) => entries,
        _ => return Err(INVALID_FRONTMATTER),
    };
    let name = match lookup(&parsed, "name") {
        Some(PyVal::Str(name))
            if is_skill_name(name)
                && document
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|parent| parent.to_str())
                    == Some(name.as_str()) =>
        {
            name
        }
        _ => return Err("metadata-invalid-name-or-description"),
    };
    let description = match lookup(&parsed, "description") {
        Some(PyVal::Str(text)) if (1..=1024).contains(&python_strip(text).chars().count()) => {
            python_strip(text)
        }
        _ => return Err("metadata-invalid-name-or-description"),
    };
    let compatibility =
        optional_text(&parsed, "compatibility", 500).ok_or("metadata-invalid-compatibility")?;
    let requested =
        optional_text(&parsed, "allowed-tools", 2048).ok_or("metadata-invalid-tool-request")?;
    let (present, manifest) = dependency_manifest(&parsed);
    Ok(json!({
        "name": name,
        "description": description,
        "compatibility": compatibility,
        "requested_tools": requested,
        "metadata_digest": hex::encode(Sha256::digest(header.as_bytes())),
        "requirements_complete": false,
        "instruction_content_loaded": false,
        "dependencies": parse_dependencies(present, manifest),
    }))
}

/// `bytes.strip()`: the six ASCII white space bytes.
fn strip_ascii(line: &[u8]) -> &[u8] {
    let space = |byte: &u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
    let start = line
        .iter()
        .position(|byte| !space(byte))
        .unwrap_or(line.len());
    let end = line
        .iter()
        .rposition(|byte| !space(byte))
        .map_or(start, |at| at + 1);
    &line[start..end]
}

/// `bytes.splitlines(keepends=True)`: `\n`, `\r` and `\r\n` end a line.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut at) = (0, 0);
    while at < bytes.len() {
        let end = match bytes[at] {
            b'\n' => at + 1,
            b'\r' if bytes.get(at + 1) == Some(&b'\n') => at + 2,
            b'\r' => at + 1,
            _ => {
                at += 1;
                continue;
            }
        };
        lines.push(&bytes[start..end]);
        (start, at) = (end, end);
    }
    if start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

/// The bytes between the opening `---` line and the next one.
fn frontmatter(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let lines = split_lines(raw);
    if lines.first().is_none_or(|line| strip_ascii(line) != b"---") {
        return Err("metadata-frontmatter-missing");
    }
    let end = lines
        .iter()
        .skip(1)
        .position(|line| strip_ascii(line) == b"---")
        .ok_or("metadata-frontmatter-limit")?
        + 1;
    Ok(lines[1..end].concat())
}

fn lookup<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// `[a-z0-9]+(?:-[a-z0-9]+)*`, at most 64 characters.
fn is_skill_name(name: &str) -> bool {
    name.len() <= 64
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

/// An absent key reads as empty text; any other non-text value is refused.
fn optional_text<'a>(entries: &'a [(String, PyVal)], key: &str, limit: usize) -> Option<&'a str> {
    match lookup(entries, key) {
        None => Some(""),
        Some(PyVal::Str(text)) if text.chars().count() <= limit => Some(text),
        Some(_) => None,
    }
}

/// Whether `metadata["hol-guard.dependencies"]` is declared, and its text
/// when it is text. A declared non-text value has no manifest to read.
fn dependency_manifest(entries: &[(String, PyVal)]) -> (bool, Option<&str>) {
    let Some(PyVal::Dict(metadata)) = lookup(entries, "metadata") else {
        return (false, None);
    };
    match lookup(metadata, "hol-guard.dependencies") {
        None | Some(PyVal::Null) => (false, None),
        Some(PyVal::Str(text)) => (true, Some(text)),
        Some(_) => (true, None),
    }
}

#[cfg(test)]
#[path = "local_skill_index_tests.rs"]
mod tests;
