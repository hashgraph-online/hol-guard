//! Runtime launch/executable identity — verbatim port of
//! `approval_context.py` :298-500, :562-806, :872-1817.
//!
//! Every public function returns a `serde_json::Value` object whose keys are
//! the exact Python dict keys. Digests use the canonical-JSON contract from
//! `guard-contracts` (`json.dumps(v, sort_keys=True, separators=(",",":"),
//! ensure_ascii=True)`); opaque digests are `sha256(material.encode("utf-8"))`
//! or the `guard-context-unbound:<label>:<sha256>` sentinel for strict digests
//! — the native-resident fallback in Python `native_context.py`.
//!
//! All host-OS and filesystem semantics are POSIX-only (`shutil.which`
//! directory search + execute bit, `lstat` chains, shebang extraction).
//! Windows-specific gates are preserved verbatim so POSIX builds fail closed
//! exactly like the Python original.

use std::collections::HashSet;
use std::fs::{self, Metadata};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use guard_contracts::write_canonical_json;
use serde_json::{json, Map, Value};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::command_tokens::executable_name;
use crate::env_wrapper::parse_env_wrapper;
use crate::launch_identity_common::{
    canonical_material_bytes, context_opaque_digest_strict, expand_user, launch_argv_digest,
    normalized_launch_cwd, runtime_launch_argv, sha256_hex, RuntimeLaunchArgv, UNBOUND_PREFIX,
};
use crate::shell_tokens;

// Python constants (approval_context.py :47-51, file_identity.py :23-31,
// native_context.py :377-388).
const MAX_EXECUTABLE_HASH_BYTES: u64 = 256 * 1024 * 1024;
const EXECUTABLE_HASH_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_SHEBANG_BYTES: usize = 4096;

// `content_stat_identity` (file_identity.py :23-31) — the compact stat tuple
// used to detect content/path replacement. Order is
// (dev, ino, size, mtime_ns, ctime_ns, mode); the Python source uses this
// ordering, NOT the (dev, ino, mtime, ctime, size, mode) order suggested by
// prior maps. Verified against file_identity.py verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StatKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    mode: u32,
}

fn stat_key(metadata: &Metadata) -> StatKey {
    StatKey {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mtime_ns: metadata.mtime_nsec(),
        ctime_ns: metadata.ctime_nsec(),
        mode: metadata.mode(),
    }
}

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;

fn is_regular(mode: u32) -> bool {
    mode & S_IFMT == S_IFREG
}

fn token_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    if getrandom::fill(&mut buffer).is_ok() {
        hex::encode(buffer)
    } else {
        "0".repeat(bytes * 2)
    }
}

// `context_sha256_digest(material, unbound_label=<label>, strict=True)` — same
// degrade over structured material.
fn context_sha256_digest_strict(material: &Value, unbound_label: &str) -> String {
    let material_bytes = canonical_material_bytes(material);
    format!(
        "{}{}:{}",
        UNBOUND_PREFIX,
        unbound_label,
        sha256_hex(&material_bytes)
    )
}

// `_opaque_identity_digest` (:883-889) — `context_opaque_digest(material,
// unbound_label="opaque-identity")` (strict).
fn opaque_identity_digest(material: &str) -> String {
    context_opaque_digest_strict(material, "opaque-identity")
}

fn is_sha256_hex(value: &Value) -> bool {
    match value.as_str() {
        Some(s) => {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

// `_unreusable_executable_identity` (:1801-1812).
fn unreusable_executable_identity(command: &Value, status: &str, path: Option<&Path>) -> Value {
    let mut map = Map::new();
    map.insert(
        "command".to_string(),
        command
            .as_str()
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "path".to_string(),
        path.map(|p| Value::String(p.to_string_lossy().into_owned()))
            .unwrap_or(Value::Null),
    );
    map.insert("status".to_string(), Value::String(status.to_string()));
    map.insert("reuse_nonce".to_string(), Value::String(token_hex(16)));
    Value::Object(map)
}

// `with_launch_cwd` inner closure (:352-356).
fn with_launch_cwd(mut identity: Value, effective_cwd: Option<&Path>) -> Value {
    if let (Value::Object(map), Some(cwd)) = (&mut identity, effective_cwd) {
        map.insert(
            "launch_cwd".to_string(),
            Value::String(cwd.to_string_lossy().into_owned()),
        );
    }
    identity
}

// `_runtime_path_with_trusted_home` (:315-330).
fn runtime_path_with_trusted_home(command: &str, home_dir: Option<&Path>) -> Option<PathBuf> {
    if command == "~" {
        return home_dir.map(|p| p.to_path_buf());
    }
    if let Some(stripped) = command.strip_prefix("~/") {
        // POSIX: `os.name == "nt"` gate is false; `~\` is not trusted-home.
        let home = home_dir?;
        let relative_tail = stripped.trim_start_matches(['/', '\\']);
        if relative_tail.is_empty() {
            return None;
        }
        // ntpath.splitdrive POSIX-surrogate: a `C:`/`\\` prefix in the tail
        // would escape the trusted home; reject drive/UNC-like tails.
        if looks_like_windows_drive(relative_tail) {
            return None;
        }
        return Some(home.join(relative_tail));
    }
    if command.starts_with('~') {
        return None;
    }
    Some(PathBuf::from(command))
}

fn looks_like_windows_drive(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
        || text.starts_with("\\\\")
        || text.starts_with("//")
}

// `_executable_path_chain_snapshot` (:441-492). Returns None on any lstat
// failure; Some(vec) of snapshot maps otherwise. Each snapshot dict is
// emitted in Python's `tuple(sorted(items))` order — JSON object key order is
// irrelevant to equality, so we emit a plain object.
fn executable_path_chain_snapshot(path: &Path) -> Option<Vec<Value>> {
    let canonical = path.canonicalize().ok()?;
    let mut snapshots: Vec<Value> = Vec::new();
    let mut seen_paths: HashSet<String> = HashSet::new();
    for endpoint in [path.to_path_buf(), canonical] {
        let parts: Vec<String> = endpoint
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts.is_empty() {
            return None;
        }
        let mut current = PathBuf::from(&parts[0]);
        for (index, part) in parts.iter().enumerate().skip(1) {
            current.push(part);
            let metadata = match fs::symlink_metadata(&current) {
                Ok(m) => m,
                Err(_) => return None,
            };
            let is_endpoint = index == parts.len() - 1;
            if !is_endpoint && !metadata.file_type().is_symlink() {
                continue;
            }
            let current_text = current.to_string_lossy().into_owned();
            if seen_paths.contains(&current_text) {
                continue;
            }
            seen_paths.insert(current_text.clone());
            let mut target: Option<String> = None;
            if metadata.file_type().is_symlink() {
                match fs::read_link(&current) {
                    Ok(t) => target = Some(t.to_string_lossy().into_owned()),
                    Err(_) => return None,
                }
            }
            let mut snapshot = Map::new();
            snapshot.insert("change_time_ns".to_string(), json!(metadata.ctime_nsec()));
            snapshot.insert("device".to_string(), json!(metadata.dev()));
            snapshot.insert("inode".to_string(), json!(metadata.ino()));
            snapshot.insert(
                "mode".to_string(),
                json!(metadata.permissions().mode() & 0o7777),
            );
            snapshot.insert("modified_time_ns".to_string(), json!(metadata.mtime_nsec()));
            snapshot.insert("path".to_string(), Value::String(current_text));
            snapshot.insert(
                "target_sha256".to_string(),
                match &target {
                    Some(t) => Value::String(context_opaque_digest_strict(t, "path-target")),
                    None => Value::Null,
                },
            );
            snapshots.push(Value::Object(snapshot));
        }
    }
    if snapshots.is_empty() {
        None
    } else {
        Some(snapshots)
    }
}

// Match the runtime's opt-in sanitized stderr protocol without exposing any
// executable path, digest, launch environment, or file content.
static EXECUTABLE_DIGEST_DIAGNOSTIC: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("HOL_GUARD_NATIVE_DIAGNOSTIC").is_ok_and(|value| {
        let value = value.trim();
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
});

fn emit_executable_digest_phase(status: &'static str, elapsed: Duration) {
    let mut line = [0u8; 192];
    let mut output = Cursor::new(line.as_mut_slice());
    if writeln!(
        output,
        "native_resident_phase phase=executable_digest status={status} elapsed_ms={}",
        elapsed.as_millis()
    )
    .is_ok()
    {
        let length = output.position() as usize;
        let _ = std::io::stderr().lock().write_all(&line[..length]);
    }
}

// `_cached_executable_hash` (:1743-1782) — ported uncached; the Python
// `lru_cache` is a pure optimization (output identical for same stat key).
// Returns (digest, hash_status, shebang, shebang_status).
fn cached_executable_hash(
    path: &Path,
    expected_stat: StatKey,
) -> (Option<String>, &'static str, Option<String>, &'static str) {
    if !*EXECUTABLE_DIGEST_DIAGNOSTIC {
        return executable_hash_inner(path, expected_stat);
    }
    let started = Instant::now();
    emit_executable_digest_phase("start", Duration::ZERO);
    let result = executable_hash_inner(path, expected_stat);
    emit_executable_digest_phase(
        if result.1 == "verified" {
            "ok"
        } else {
            "error"
        },
        started.elapsed(),
    );
    result
}

fn executable_hash_inner(
    path: &Path,
    expected_stat: StatKey,
) -> (Option<String>, &'static str, Option<String>, &'static str) {
    // Python: os.open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW). Rust File::open
    // would follow a symlink hop; O_NOFOLLOW makes the final-component symlink
    // fail with "open_failed" exactly like the source.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return (None, "open_failed", None, "unverified"),
    };
    let opened_stat = match file.metadata() {
        Ok(m) => m,
        Err(_) => return (None, "read_failed", None, "unverified"),
    };
    let observed_stat = stat_key(&opened_stat);
    if observed_stat != expected_stat || !is_regular(opened_stat.mode()) {
        return (None, "identity_raced", None, "unverified");
    }
    if opened_stat.size() > MAX_EXECUTABLE_HASH_BYTES {
        return (None, "too_large", None, "unverified");
    }
    let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
    let mut prefix: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    let mut reader = file;
    let mut chunk = vec![0u8; EXECUTABLE_HASH_CHUNK_BYTES];
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return (None, "read_failed", None, "unverified"),
        };
        total += n as u64;
        if total > MAX_EXECUTABLE_HASH_BYTES {
            return (None, "too_large", None, "unverified");
        }
        digest.update(&chunk[..n]);
        if prefix.len() <= MAX_SHEBANG_BYTES {
            let take = (MAX_SHEBANG_BYTES + 1 - prefix.len()).min(n);
            prefix.extend_from_slice(&chunk[..take]);
        }
    }
    if total != opened_stat.size() {
        return (None, "size_changed", None, "unverified");
    }
    let final_stat = match reader.metadata() {
        Ok(m) => m,
        Err(_) => return (None, "read_failed", None, "unverified"),
    };
    if stat_key(&final_stat) != observed_stat {
        return (None, "identity_raced", None, "unverified");
    }
    let (shebang, shebang_status) = parse_executable_shebang(&prefix);
    (
        Some(hex::encode(digest.finish().as_ref())),
        "verified",
        shebang,
        shebang_status,
    )
}

// `_parse_executable_shebang` (:1785-1795).
fn parse_executable_shebang(prefix: &[u8]) -> (Option<String>, &'static str) {
    if !prefix.starts_with(b"#!") {
        return (None, "not_script");
    }
    // Python bytes.splitlines() boundaries: \n, \r, \r\n, \v, \f,
    // \x1c, \x1d, \x1e, \x85. first_line is up to the first boundary.
    let first_line: &[u8] = match prefix
        .iter()
        .position(|&b| matches!(b, b'\n' | b'\r' | 0x0b | 0x0c | 0x1c | 0x1d | 0x1e | 0x85))
    {
        Some(i) => &prefix[..i],
        None => prefix,
    };
    if first_line.len() > MAX_SHEBANG_BYTES {
        return (None, "too_long");
    }
    let decoded = match std::str::from_utf8(&first_line[2..]) {
        Ok(s) => python_str_strip(s),
        Err(_) => return (None, "invalid_encoding"),
    };
    if decoded.is_empty() {
        (None, "interpreter_missing")
    } else {
        (Some(decoded.to_string()), "verified")
    }
}

// `shutil.which(command, path=effective_search_path)` — POSIX semantics:
// search each `:`-separated entry (empty entry → `.`), require regular file +
// any execute bit. No PATHEXT, no Windows mode.
fn which(command: &str, search_path: &str) -> Option<PathBuf> {
    // Python: a command containing a path separator is handled by the caller
    // before `which` is reached; `shutil.which` itself also checks the
    // basename form, but the caller contract keeps `command` bare here.
    for entry in search_path.split(':') {
        let dir = if entry.is_empty() {
            Path::new(".")
        } else {
            Path::new(entry)
        };
        let candidate = dir.join(command);
        if let Ok(m) = fs::metadata(&candidate) {
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return Some(candidate);
            }
        }
    }
    None
}

// `build_runtime_executable_identity` (:332-438). `command` is the raw Python
// `object` (None/str/other); callers that already validated a `str` pass a
// `Value::String`.
pub fn build_runtime_executable_identity(
    command: &Value,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    require_executable: bool,
) -> Value {
    let effective_cwd: Option<PathBuf> = cwd.map(|c| normalized_launch_cwd(Some(c)));
    let eff_cwd_ref = effective_cwd.as_deref();

    if command.is_null() || command.as_str() == Some("") {
        return with_launch_cwd(
            json!({"command": Value::Null, "path": Value::Null, "status": "not_applicable"}),
            eff_cwd_ref,
        );
    }
    let command_str = match command.as_str() {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => {
            return with_launch_cwd(
                unreusable_executable_identity(command, "invalid_command", None),
                eff_cwd_ref,
            )
        }
    };

    let candidate = match runtime_path_with_trusted_home(&command_str, home_dir) {
        Some(p) => p,
        None => {
            return with_launch_cwd(
                unreusable_executable_identity(command, "unresolved_home", None),
                eff_cwd_ref,
            )
        }
    };
    // POSIX-only gate (`os.name != "nt"`): `\\`, drive prefix, or `//`
    // verbatim.
    let has_windows_path = command_str.contains('\\')
        || looks_like_windows_drive(&command_str)
        || command_str.starts_with("//");
    if has_windows_path {
        return with_launch_cwd(
            unreusable_executable_identity(command, "foreign_platform_path", Some(&candidate)),
            eff_cwd_ref,
        );
    }
    let has_explicit_path = command_str.contains('/');
    let resolved: PathBuf;
    if candidate.is_absolute() {
        resolved = candidate;
    } else if has_explicit_path {
        resolved = match eff_cwd_ref {
            Some(c) => c.join(&candidate),
            None => candidate,
        };
    } else {
        // `shutil.which` PATH entry normalization (:379-385).
        let mut effective_search_path: Option<String> = search_path.map(|s| s.to_string());
        if let Some(cwd_path) = eff_cwd_ref {
            let inherited = search_path
                .map(|s| s.to_string())
                .or_else(|| std::env::var("PATH").ok());
            if let Some(inherited_path) = inherited {
                let mut normalized_entries: Vec<String> = Vec::new();
                for entry in inherited_path.split(':') {
                    let mut path_entry = if entry.is_empty() {
                        PathBuf::from(".")
                    } else {
                        expand_user(Path::new(entry))
                    };
                    if !path_entry.is_absolute() {
                        path_entry = cwd_path.join(&path_entry);
                    }
                    normalized_entries.push(path_entry.to_string_lossy().into_owned());
                }
                effective_search_path = Some(normalized_entries.join(":"));
            }
        }
        let located = effective_search_path
            .as_deref()
            .and_then(|p| which(&command_str, p));
        match located {
            Some(p) => resolved = p,
            None => {
                return with_launch_cwd(
                    unreusable_executable_identity(command, "unresolved", None),
                    eff_cwd_ref,
                )
            }
        }
    }

    // `os.path.abspath(os.fspath(resolved))` — lexical normalization;
    // `resolved` may still be relative if `which` returned a relative hit.
    let launch_path: PathBuf = if resolved.is_absolute() {
        resolved.clone()
    } else {
        match eff_cwd_ref {
            Some(c) => c.join(&resolved),
            None => std::env::current_dir()
                .map(|c| c.join(&resolved))
                .unwrap_or_else(|_| resolved.clone()),
        }
    };
    let launch_path = normalize_lexical(&launch_path);

    let initial_path_chain = match executable_path_chain_snapshot(&launch_path) {
        Some(c) => c,
        None => {
            return with_launch_cwd(
                unreusable_executable_identity(command, "unreadable", Some(&launch_path)),
                eff_cwd_ref,
            )
        }
    };
    let canonical = match launch_path.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            return with_launch_cwd(
                unreusable_executable_identity(command, "unreadable", Some(&launch_path)),
                eff_cwd_ref,
            )
        }
    };
    let metadata = match fs::metadata(&canonical) {
        Ok(m) => m,
        Err(_) => {
            return with_launch_cwd(
                unreusable_executable_identity(command, "unreadable", Some(&launch_path)),
                eff_cwd_ref,
            )
        }
    };
    if !is_regular(metadata.mode()) {
        return with_launch_cwd(
            unreusable_executable_identity(command, "not_regular", Some(&canonical)),
            eff_cwd_ref,
        );
    }
    if require_executable && metadata.mode() & 0o111 == 0 {
        return with_launch_cwd(
            unreusable_executable_identity(command, "not_executable", Some(&canonical)),
            eff_cwd_ref,
        );
    }
    let key = stat_key(&metadata);
    let (digest, hash_status, shebang, shebang_status) = cached_executable_hash(&canonical, key);
    let final_path_chain = executable_path_chain_snapshot(&launch_path);
    if final_path_chain.as_ref() != Some(&initial_path_chain) {
        return with_launch_cwd(
            unreusable_executable_identity(command, "path_changed", Some(&launch_path)),
            eff_cwd_ref,
        );
    }
    let file_format = match shebang_status {
        "verified" => "script",
        "not_script" => "native",
        _ => "unverified",
    };
    let mut identity = Map::new();
    identity.insert("command".to_string(), command.clone());
    identity.insert(
        "launch_path".to_string(),
        Value::String(launch_path.to_string_lossy().into_owned()),
    );
    identity.insert(
        "file_format".to_string(),
        Value::String(file_format.to_string()),
    );
    identity.insert(
        "path".to_string(),
        Value::String(canonical.to_string_lossy().into_owned()),
    );
    identity.insert("path_chain".to_string(), Value::Array(initial_path_chain));
    identity.insert(
        "shebang_status".to_string(),
        Value::String(shebang_status.to_string()),
    );
    identity.insert("device".to_string(), json!(metadata.dev()));
    identity.insert("inode".to_string(), json!(metadata.ino()));
    identity.insert("modified_time_ns".to_string(), json!(metadata.mtime_nsec()));
    identity.insert("change_time_ns".to_string(), json!(metadata.ctime_nsec()));
    identity.insert("size".to_string(), json!(metadata.size()));
    identity.insert(
        "mode".to_string(),
        json!(metadata.permissions().mode() & 0o7777),
    );
    identity.insert("status".to_string(), Value::String(hash_status.to_string()));
    let mut identity = Value::Object(identity);
    match &digest {
        None => {
            identity["reuse_nonce"] = Value::String(token_hex(16));
        }
        Some(d) => {
            identity["sha256"] = Value::String(d.clone());
        }
    }
    if let Some(s) = &shebang {
        identity["shebang_sha256"] = Value::String(context_opaque_digest_strict(s, "shebang"));
    }
    with_launch_cwd(identity, eff_cwd_ref)
}

// `os.path.abspath` lexical normalization — collapse `.`/`..` without
// resolving symlinks (abspath is `normpath` on POSIX).
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let absolute = path.is_absolute();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if matches!(out.last().map(|s| s.to_string_lossy()), Some(s) if s != "..") {
                    out.pop();
                } else if !absolute {
                    out.push(std::ffi::OsString::from(".."));
                }
            }
            std::path::Component::Normal(s) => out.push(s.to_os_string()),
            std::path::Component::Prefix(_) => {}
        }
    }
    let mut result = if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };
    for part in out {
        result.push(part);
    }
    result
}

// `_identity_shebang_status` (:1217-1224).
fn identity_shebang_status(identity: &Value) -> &'static str {
    if identity.get("sha256").and_then(|v| v.as_str()).is_none() {
        return "unverified";
    }
    let status = identity.get("shebang_status").and_then(|v| v.as_str());
    if identity
        .get("shebang_sha256")
        .and_then(|v| v.as_str())
        .is_some()
        && status == Some("verified")
    {
        return "script";
    }
    if status == Some("not_script") {
        "native"
    } else {
        "unverified"
    }
}

// `_raw_shebang_for_identity` (:1226-1253).
fn raw_shebang_for_identity(identity: &Value) -> (Option<String>, String) {
    let initial_status = identity.get("shebang_status").and_then(|v| v.as_str());
    if initial_status != Some("verified") {
        return (None, initial_status.unwrap_or("unverified").to_string());
    }
    let path = identity.get("path").and_then(|v| v.as_str());
    let expected_digest = identity.get("sha256").and_then(|v| v.as_str());
    let (path, expected_digest) = match (path, expected_digest) {
        (Some(p), Some(d)) => (p, d),
        _ => return (None, "unverified".to_string()),
    };
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return (None, "identity_changed".to_string()),
    };
    let (digest, hash_status, shebang, shebang_status) =
        cached_executable_hash(Path::new(path), stat_key(&metadata));
    if hash_status != "verified"
        || digest.as_deref() != Some(expected_digest)
        || shebang_status != "verified"
        || shebang.is_none()
    {
        return (None, "identity_changed".to_string());
    }
    (shebang, "verified".to_string())
}

// `_runtime_identity_contains_reuse_nonce` (:1710-1717).
fn runtime_identity_contains_reuse_nonce(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key("reuse_nonce")
                || map.values().any(runtime_identity_contains_reuse_nonce)
        }
        Value::Array(items) => items.iter().any(runtime_identity_contains_reuse_nonce),
        _ => false,
    }
}

// `runtime_launch_identity_is_reusable` (:687-690).
pub fn runtime_launch_identity_is_reusable(identity: &Value) -> bool {
    !runtime_identity_contains_reuse_nonce(identity)
}

// `resolved_runtime_launch_executable` (:666-684).
pub fn resolved_runtime_launch_executable(identity: &Value) -> Option<String> {
    let executable = identity.get("executable")?;
    if !executable.is_object() {
        return None;
    }
    let path = executable.get("path").and_then(|v| v.as_str())?;
    let digest = executable.get("sha256")?;
    if executable.get("status").and_then(|v| v.as_str()) != Some("verified")
        || !is_sha256_hex(digest)
    {
        return None;
    }
    if Path::new(path).is_absolute() {
        Some(path.to_string())
    } else {
        None
    }
}

// `resolved_runtime_launch_argv` (:692-752).
pub fn resolved_runtime_launch_argv(identity: &Value, args: &[String]) -> Option<Vec<String>> {
    if !runtime_launch_identity_is_reusable(identity) {
        return None;
    }
    let executable = identity.get("executable")?;
    let entrypoint = identity.get("entrypoint")?;
    if !executable.is_object() || !entrypoint.is_object() {
        return None;
    }
    let executable_path = resolved_runtime_launch_executable(identity)?;
    if entrypoint.get("kind").and_then(|v| v.as_str()) == Some("direct-executable")
        && entrypoint.get("status").and_then(|v| v.as_str()) == Some("bound-by-executable")
    {
        let mut out = vec![executable_path];
        out.extend(args.iter().cloned());
        return Some(out);
    }
    if entrypoint.get("status").and_then(|v| v.as_str()) != Some("verified") {
        return None;
    }
    let kind = entrypoint.get("kind").and_then(|v| v.as_str())?;
    if kind != "direct-script" && kind != "direct-env-script" {
        return None;
    }
    let (shebang, shebang_status) = raw_shebang_for_identity(executable);
    if shebang_status != "verified" {
        return None;
    }
    let shebang = shebang?;
    let shebang_tokens = crate::shell_tokens(&shebang, true).ok()?;
    if shebang_tokens.is_empty() {
        return None;
    }
    let launcher_name = executable_name(shebang_tokens.first().map(|s| s.as_str()))?;
    let shebang_args: Vec<String> = shebang_tokens[1..].to_vec();
    if launch_argv_digest(&shebang_args)
        != entrypoint
            .get("shebang_args_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    {
        return None;
    }
    if launcher_name != "env" && launcher_name != "env.exe" {
        if shebang_args.len() > 1 {
            return None;
        }
        let launcher_path = verified_identity_path(entrypoint.get("launcher")?)?;
        let mut out = vec![launcher_path];
        out.extend(shebang_args);
        out.push(executable_path);
        out.extend(args.iter().cloned());
        return Some(out);
    }
    let env_command = env_shebang_command(&shebang_args)?;
    let (_interpreter, interpreter_args) = env_command;
    if launch_argv_digest(&interpreter_args)
        != entrypoint
            .get("interpreter_args_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    {
        return None;
    }
    let interpreter_path = verified_identity_path(entrypoint.get("interpreter")?)?;
    let mut out = vec![interpreter_path];
    out.extend(interpreter_args);
    out.push(executable_path);
    out.extend(args.iter().cloned());
    Some(out)
}

// `runtime_launch_identity_matches` (:757-806).
#[allow(clippy::too_many_arguments)]
pub fn runtime_launch_identity_matches(
    expected_identity: &Value,
    command: &Value,
    args: &[Value],
    structured_command: bool,
    direct_executable: bool,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    launch_env: Option<&Value>,
) -> bool {
    let current_identity = build_runtime_launch_identity(
        command,
        args,
        structured_command,
        direct_executable,
        search_path,
        cwd,
        None,
        launch_env,
    );
    let expected_digest = runtime_launch_verification_digest(expected_identity);
    let current_digest = runtime_launch_verification_digest(&current_identity);
    match (expected_digest, current_digest) {
        (Some(e), Some(c)) => e == c,
        _ => false,
    }
}

// `_runtime_launch_verification_digest` (:1696-1708).
fn runtime_launch_verification_digest(identity: &Value) -> Option<String> {
    let material = without_runtime_reuse_nonces(identity);
    // `json.dumps(material, ensure_ascii=True, allow_nan=False)` — any encode
    // failure (non-finite floats) returns None verbatim.
    let mut bytes = Vec::new();
    if write_canonical_json(&material, &mut bytes).is_err() {
        return None;
    }
    Some(context_sha256_digest_strict(
        &material,
        "launch-verification",
    ))
}

// `_verified_identity_path` (:1720-1727).
fn verified_identity_path(value: &Value) -> Option<String> {
    if !value.is_object() {
        return None;
    }
    let path = value.get("path").and_then(|v| v.as_str())?;
    let digest = value.get("sha256")?;
    if value.get("status").and_then(|v| v.as_str()) != Some("verified") || !is_sha256_hex(digest) {
        return None;
    }
    if Path::new(path).is_absolute() {
        Some(path.to_string())
    } else {
        None
    }
}

// `_without_runtime_reuse_nonces` (:1730-1740).
fn without_runtime_reuse_nonces(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if k != "reuse_nonce" {
                    out.insert(k.clone(), without_runtime_reuse_nonces(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(without_runtime_reuse_nonces).collect())
        }
        _ => value.clone(),
    }
}

// `_env_shebang_command` (:1208-1214).
fn env_shebang_command(args: &[String]) -> Option<(String, Vec<String>)> {
    // RUST-PARITY: `_env_shebang_command` (:1208-1214) calls
    // `parse_env_wrapper(args)` with defaults — no inherited env, no cwd.
    let parsed = parse_env_wrapper(args, None, None);
    if !parsed.complete || parsed.executable_argv.is_empty() {
        return None;
    }
    Some((
        parsed.executable_argv[0].clone(),
        parsed.executable_argv[1..].to_vec(),
    ))
}

// `build_runtime_launch_identity` (:562-663).
#[allow(clippy::too_many_arguments)]
pub fn build_runtime_launch_identity(
    command: &Value,
    args: &[Value],
    structured_command: bool,
    direct_executable: bool,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    launch_env: Option<&Value>,
) -> Value {
    let effective_cwd = normalized_launch_cwd(cwd);
    let launch_env_map: Option<&Map<String, Value>> = launch_env.and_then(|v| v.as_object());
    let environment: &Map<String, Value> = launch_env_map
        .map(|m| m as &Map<String, Value>)
        .unwrap_or_else(|| {
            // `os.environ` surrogate — build once per call; the caller passes
            // an explicit env in every production path.
            Box::leak(Box::new(
                std::env::vars()
                    .map(|(k, v)| (k, Value::String(v)))
                    .collect(),
            ))
        });
    // Python: `environment = launch_env if launch_env is not None else os.environ`
    // and `effective_search_path = search_path or environment.get("PATH")` —
    // the None-search_path fallback sources PATH from the launch env.
    let effective_search_path: Option<&str> =
        search_path.or_else(|| environment.get("PATH").and_then(|v| v.as_str()));

    if command.is_null() || command.as_str() == Some("") {
        return json!({
            "argv_sha256": launch_argv_digest(&[]),
            "entrypoint": {"kind": "not-applicable", "status": "not_applicable"},
            "executable": build_runtime_executable_identity(
                command, search_path, Some(&effective_cwd), home_dir, true,
            ),
            "launch_cwd": effective_cwd.to_string_lossy(),
        });
    }
    let command_str = match command.as_str() {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => {
            return json!({
                "argv_sha256": launch_argv_digest(&[]),
                "entrypoint": unproven_runtime_entrypoint("unknown-launch", "invalid_launch_command", None),
                "executable": build_runtime_executable_identity(
                    command, search_path, Some(&effective_cwd), home_dir, true,
                ),
                "launch_cwd": effective_cwd.to_string_lossy(),
            })
        }
    };

    let full_argv: Vec<String> = match runtime_launch_argv(command, args, structured_command) {
        RuntimeLaunchArgv::Valid(argv) => argv,
        RuntimeLaunchArgv::Invalid(executable_cmd) => {
            return json!({
                "argv_sha256": launch_argv_digest(&[]),
                "entrypoint": unproven_runtime_entrypoint("unknown-launch", "unparseable_launch_vector", None),
                "executable": build_runtime_executable_identity(
                    &executable_cmd, search_path, Some(&effective_cwd), home_dir, true,
                ),
                "launch_cwd": effective_cwd.to_string_lossy(),
            });
        }
    };
    let executable = full_argv[0].clone();
    let launch_args: &[String] = &full_argv[1..];
    let raw_command = command_str.trim_start();
    let raw_current_user_tilde = raw_command.starts_with("~/");
    let executable_identity: Value =
        if !structured_command && executable.starts_with('~') && !raw_current_user_tilde {
            unreusable_executable_identity(
                &Value::String(executable.clone()),
                "ambiguous_tilde_syntax",
                None,
            )
        } else {
            build_runtime_executable_identity(
                &Value::String(executable.clone()),
                effective_search_path,
                Some(&effective_cwd),
                home_dir,
                true,
            )
        };
    let (executable_shebang, executable_shebang_status) =
        raw_shebang_for_identity(&executable_identity);
    let entrypoint = runtime_entrypoint_identity(
        &executable_identity,
        executable_shebang.as_deref(),
        executable_shebang_status.as_str(),
        direct_executable,
        launch_args,
        &effective_cwd,
        launch_env,
    );
    json!({
        "argv_sha256": launch_argv_digest(&full_argv),
        "entrypoint": entrypoint,
        "executable": executable_identity,
        "launch_cwd": effective_cwd.to_string_lossy(),
    })
}

// `_runtime_entrypoint_identity` (:901-986).
fn runtime_entrypoint_identity(
    executable_identity: &Value,
    executable_shebang: Option<&str>,
    executable_shebang_status: &str,
    direct_executable: bool,
    launch_args: &[String],
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    let command_name = executable_name(executable_identity.get("command").and_then(|v| v.as_str()))
        .unwrap_or_default();
    let resolved_path = executable_identity.get("path");
    let executable_name_str = executable_name(
        resolved_path
            .and_then(|v| v.as_str())
            .or(Some(command_name.as_str())),
    )
    .unwrap_or_default();

    if direct_executable {
        return direct_executable_runtime_entrypoint_identity(
            executable_identity,
            executable_shebang,
            executable_shebang_status,
            launch_args,
            launch_cwd,
            launch_env,
        );
    }
    if executable_name_str.ends_with(".bat") || executable_name_str.ends_with(".cmd") {
        return unproven_runtime_entrypoint(
            "command-script-launcher",
            "command_interpreter_unresolved",
            Some(launch_args),
        );
    }
    if UNRESOLVED_CODE_LAUNCHER_NAMES.contains(&executable_name_str.as_str())
        || UNRESOLVED_CODE_LAUNCHER_NAMES.contains(&command_name.as_str())
    {
        return unproven_runtime_entrypoint(
            "code-launcher",
            "launcher_entrypoint_unresolved",
            Some(launch_args),
        );
    }
    if known_runtime_launcher_name(&executable_name_str)
        && identity_shebang_status(executable_identity) != "native"
    {
        return unproven_runtime_entrypoint(
            "code-launcher",
            "script_backed_launcher_unresolved",
            Some(launch_args),
        );
    }
    if python_launcher_pattern_match(&executable_name_str) {
        return python_runtime_entrypoint_identity(launch_args, launch_cwd, launch_env);
    }
    if NODE_LAUNCHER_NAMES.contains(&executable_name_str.as_str()) {
        return node_runtime_entrypoint_identity(launch_args, launch_cwd, launch_env);
    }
    if SHELL_LAUNCHER_NAMES.contains(&executable_name_str.as_str()) {
        return shell_runtime_entrypoint_identity(
            &executable_name_str,
            launch_args,
            launch_cwd,
            launch_env,
        );
    }
    if SIMPLE_SCRIPT_LAUNCHER_NAMES.contains(&executable_name_str.as_str()) {
        return simple_runtime_entrypoint_identity(&executable_name_str, launch_args, launch_cwd);
    }
    if matches!(
        executable_name_str.as_str(),
        "bun" | "bun.exe" | "deno" | "deno.exe"
    ) {
        return javascript_runtime_entrypoint_identity(
            &executable_name_str,
            launch_args,
            launch_cwd,
        );
    }
    if matches!(executable_name_str.as_str(), "java" | "java.exe") {
        return java_runtime_entrypoint_identity(launch_args, launch_cwd);
    }
    if matches!(executable_name_str.as_str(), "dotnet" | "dotnet.exe") {
        return dotnet_runtime_entrypoint_identity(launch_args, launch_cwd);
    }
    if matches!(
        executable_name_str.as_str(),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
    ) {
        return powershell_runtime_entrypoint_identity(launch_args, launch_cwd);
    }
    direct_executable_runtime_entrypoint_identity(
        executable_identity,
        executable_shebang,
        executable_shebang_status,
        launch_args,
        launch_cwd,
        launch_env,
    )
}

fn known_runtime_launcher_name(executable_name: &str) -> bool {
    python_launcher_pattern_match(executable_name)
        || NODE_LAUNCHER_NAMES.contains(&executable_name)
        || SHELL_LAUNCHER_NAMES.contains(&executable_name)
        || SIMPLE_SCRIPT_LAUNCHER_NAMES.contains(&executable_name)
        || matches!(
            executable_name,
            "bun"
                | "bun.exe"
                | "deno"
                | "deno.exe"
                | "dotnet"
                | "dotnet.exe"
                | "java"
                | "java.exe"
                | "powershell"
                | "powershell.exe"
                | "pwsh"
                | "pwsh.exe"
        )
}

// `_PYTHON_LAUNCHER_PATTERN.fullmatch` (:495-498):
// `(?:python|pypy)(?:\d+(?:\.\d+)*)?(?:\.exe)?` IGNORECASE.
fn python_launcher_pattern_match(name: &str) -> bool {
    let lower = name.to_lowercase();
    let base = lower.strip_suffix(".exe").unwrap_or(&lower);
    let rest = match base
        .strip_prefix("python")
        .or_else(|| base.strip_prefix("pypy"))
    {
        Some(r) => r,
        None => return false,
    };
    if rest.is_empty() {
        return true;
    }
    // Optional version suffix: `\d+(\.\d+)*`.
    let mut chars = rest.chars().peekable();
    if !chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return false;
    }
    while let Some(c) = chars.next() {
        if c == '.' {
            if !chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                return false;
            }
        } else if !c.is_ascii_digit() {
            return false;
        }
    }
    true
}

// `_direct_executable_runtime_entrypoint_identity` (:1012-1110).
fn direct_executable_runtime_entrypoint_identity(
    executable_identity: &Value,
    executable_shebang: Option<&str>,
    executable_shebang_status: &str,
    launch_args: &[String],
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    if executable_identity
        .get("sha256")
        .and_then(|v| v.as_str())
        .is_none()
    {
        return json!({"kind": "direct-executable", "status": "bound-by-executable"});
    }
    if executable_shebang_status == "not_script" {
        return json!({"kind": "direct-executable", "status": "bound-by-executable"});
    }
    let shebang = match executable_shebang {
        None => {
            return unproven_runtime_entrypoint(
                "direct-script",
                &format!("shebang_{executable_shebang_status}"),
                None,
            )
        }
        Some(s) => s,
    };
    let shebang_tokens = shell_tokens(shebang, true).unwrap_or_default();
    if shebang_tokens.is_empty() {
        return unproven_runtime_entrypoint(
            "direct-script",
            "shebang_interpreter_unparseable",
            None,
        );
    }
    let shebang_launcher = shebang_tokens[0].clone();
    let shebang_args: Vec<String> = shebang_tokens[1..].to_vec();
    let launcher_identity = build_runtime_executable_identity(
        &Value::String(shebang_launcher.clone()),
        None,
        Some(launch_cwd),
        None,
        true,
    );
    let launcher_name = executable_name(Some(&shebang_launcher)).unwrap_or_default();
    let mut result = json!({
        "kind": "direct-script",
        "launcher": launcher_identity,
        "script_args_sha256": launch_argv_digest(launch_args),
        "shebang_args_sha256": launch_argv_digest(&shebang_args),
        "shebang_sha256": context_opaque_digest_strict(shebang, "shebang"),
        "status": "verified",
    });

    if launcher_name != "env" && launcher_name != "env.exe" {
        if shebang_args.len() > 1 {
            result.as_object_mut().unwrap().extend(
                unproven_runtime_entrypoint(
                    "direct-script",
                    "nonportable_shebang_arguments",
                    Some(&shebang_args),
                )
                .as_object()
                .unwrap()
                .clone(),
            );
            result["launcher"] = launcher_identity;
            return result;
        }
        if UNRESOLVED_CODE_LAUNCHER_NAMES.contains(&launcher_name.as_str())
            || launcher_identity.get("status").and_then(|v| v.as_str()) != Some("verified")
        {
            result.as_object_mut().unwrap().extend(
                unproven_runtime_entrypoint(
                    "direct-script",
                    "shebang_interpreter_unresolved",
                    None,
                )
                .as_object()
                .unwrap()
                .clone(),
            );
            result["launcher"] = launcher_identity;
            return result;
        }
        if identity_shebang_status(&launcher_identity) != "native" {
            result.as_object_mut().unwrap().extend(
                unproven_runtime_entrypoint(
                    "direct-script",
                    "nested_shebang_interpreter_unresolved",
                    None,
                )
                .as_object()
                .unwrap()
                .clone(),
            );
            result["launcher"] = launcher_identity;
            return result;
        }
        let nested_identity = nested_shebang_interpreter_identity(
            &launcher_name,
            &shebang_args,
            executable_identity
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
            launch_cwd,
            launch_env,
        );
        result["interpreter_launch"] = nested_identity.clone();
        if runtime_identity_contains_reuse_nonce(&nested_identity) {
            result.as_object_mut().unwrap().extend(
                unproven_runtime_entrypoint(
                    "direct-script",
                    "shebang_interpreter_options_unresolved",
                    Some(&shebang_args),
                )
                .as_object()
                .unwrap()
                .clone(),
            );
            result["launcher"] = launcher_identity;
        }
        return result;
    }

    let env_command = env_shebang_command(&shebang_args);
    let search_path = launch_env
        .and_then(|v| v.get("PATH"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    result["search_path_sha256"] =
        Value::String(context_opaque_digest_strict(search_path, "search-path"));
    let (interpreter, interpreter_args) = match env_command {
        None => {
            result.as_object_mut().unwrap().extend(
                unproven_runtime_entrypoint(
                    "direct-env-script",
                    "env_shebang_command_unresolved",
                    Some(&shebang_args),
                )
                .as_object()
                .unwrap()
                .clone(),
            );
            result["launcher"] = launcher_identity;
            return result;
        }
        Some((i, a)) => (i, a),
    };
    // `search_path` comes from the launch env (PATH) so `env` shebangs resolve
    // interpreters against the same path the spawned process will see.
    let search_path_opt = launch_env
        .and_then(|v| v.get("PATH"))
        .and_then(|v| v.as_str());
    let interpreter_identity = build_runtime_executable_identity(
        &Value::String(interpreter.clone()),
        search_path_opt,
        Some(launch_cwd),
        None,
        true,
    );
    let interpreter_name = executable_name(Some(&interpreter)).unwrap_or_default();
    result["interpreter"] = interpreter_identity.clone();
    result["interpreter_args_sha256"] = Value::String(launch_argv_digest(&interpreter_args));
    if UNRESOLVED_CODE_LAUNCHER_NAMES.contains(&interpreter_name.as_str())
        || interpreter_identity.get("status").and_then(|v| v.as_str()) != Some("verified")
        || identity_shebang_status(&interpreter_identity) != "native"
    {
        let env_selector: Vec<String> = std::iter::once(interpreter.clone())
            .chain(interpreter_args.iter().cloned())
            .collect();
        result.as_object_mut().unwrap().extend(
            unproven_runtime_entrypoint(
                "direct-env-script",
                "env_interpreter_unresolved",
                Some(&env_selector),
            )
            .as_object()
            .unwrap()
            .clone(),
        );
        result["interpreter"] = interpreter_identity;
        result["launcher"] = launcher_identity;
        return result;
    }
    let nested_identity = nested_shebang_interpreter_identity(
        &interpreter_name,
        &interpreter_args,
        executable_identity
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        launch_cwd,
        launch_env,
    );
    result["interpreter_launch"] = nested_identity.clone();
    if runtime_identity_contains_reuse_nonce(&nested_identity) {
        result.as_object_mut().unwrap().extend(
            unproven_runtime_entrypoint(
                "direct-env-script",
                "env_interpreter_options_unresolved",
                Some(
                    &std::iter::once(interpreter.clone())
                        .chain(interpreter_args.iter().cloned())
                        .collect::<Vec<_>>(),
                ),
            )
            .as_object()
            .unwrap()
            .clone(),
        );
        result["interpreter"] = interpreter_identity;
        result["launcher"] = launcher_identity;
    }
    result
}

// `_nested_shebang_interpreter_identity` (:1163-1206).
fn nested_shebang_interpreter_identity(
    interpreter_name: &str,
    interpreter_args: &[String],
    script_path: &str,
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    let mut launch_args: Vec<String> = interpreter_args.to_vec();
    launch_args.push(script_path.to_string());
    if python_launcher_pattern_match(interpreter_name) {
        return python_runtime_entrypoint_identity(&launch_args, launch_cwd, launch_env);
    }
    if NODE_LAUNCHER_NAMES.contains(&interpreter_name) {
        return node_runtime_entrypoint_identity(&launch_args, launch_cwd, launch_env);
    }
    if SHELL_LAUNCHER_NAMES.contains(&interpreter_name) {
        return shell_runtime_entrypoint_identity(
            interpreter_name,
            &launch_args,
            launch_cwd,
            launch_env,
        );
    }
    if SIMPLE_SCRIPT_LAUNCHER_NAMES.contains(&interpreter_name) {
        return simple_runtime_entrypoint_identity(interpreter_name, &launch_args, launch_cwd);
    }
    if !interpreter_args.is_empty() {
        return unproven_runtime_entrypoint(
            "shebang-interpreter-options",
            "unsupported_interpreter_options",
            Some(interpreter_args),
        );
    }
    json!({"kind": "shebang-interpreter", "status": "verified"})
}

// `_python_runtime_entrypoint_identity` (:1256-1352).
fn python_runtime_entrypoint_identity(
    args: &[String],
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    let mut index = 0usize;
    let mut ignore_environment = false;
    let mut isolated = false;
    const NO_VALUE_FLAGS: &[&str] = &[
        "-b", "-B", "-d", "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-x",
    ];
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            index += 1;
            break;
        }
        if argument == "-E" {
            ignore_environment = true;
            index += 1;
            continue;
        }
        if argument == "-I" {
            ignore_environment = true;
            isolated = true;
            index += 1;
            continue;
        }
        if argument == "-c" {
            if let Some(i) = python_interactive_environment_identity(launch_env, ignore_environment)
            {
                return i;
            }
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint("python-inline", "missing_inline_code", None);
            }
            return inline_runtime_entrypoint("python-inline", &args[index + 1]);
        }
        if argument.starts_with("-c") && argument != "-c" {
            if let Some(i) = python_interactive_environment_identity(launch_env, ignore_environment)
            {
                return i;
            }
            return inline_runtime_entrypoint("python-inline", &argument[2..]);
        }
        if argument == "-m" {
            if let Some(i) = python_interactive_environment_identity(launch_env, ignore_environment)
            {
                return i;
            }
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint("python-module", "missing_module_name", None);
            }
            return python_module_runtime_entrypoint_identity(
                &args[index + 1],
                launch_cwd,
                launch_env,
                !isolated,
                !ignore_environment,
            );
        }
        if argument.starts_with("-m") && argument != "-m" {
            if let Some(i) = python_interactive_environment_identity(launch_env, ignore_environment)
            {
                return i;
            }
            return python_module_runtime_entrypoint_identity(
                &argument[2..],
                launch_cwd,
                launch_env,
                !isolated,
                !ignore_environment,
            );
        }
        if NO_VALUE_FLAGS.contains(&argument) {
            index += 1;
            continue;
        }
        if argument == "-W"
            || argument == "-X"
            || argument.starts_with("-W")
            || argument.starts_with("-X")
        {
            return unproven_runtime_entrypoint(
                "python-script",
                "code_loading_option_unresolved",
                Some(std::slice::from_ref(&args[index])),
            );
        }
        if argument.starts_with('-') {
            return unproven_runtime_entrypoint(
                "python-script",
                "unsupported_interpreter_option",
                Some(std::slice::from_ref(&args[index])),
            );
        }
        break;
    }
    if let Some(i) = python_interactive_environment_identity(launch_env, ignore_environment) {
        return i;
    }
    if index >= args.len() {
        return unproven_runtime_entrypoint("python-script", "entrypoint_missing", None);
    }
    if args[index] == "-" {
        return unproven_runtime_entrypoint("python-stdin", "stdin_code_unprovable", None);
    }
    file_runtime_entrypoint("python-script", &args[index], launch_cwd)
}

// `_python_module_runtime_entrypoint_identity` (:1355-1410).
fn python_module_runtime_entrypoint_identity(
    module: &str,
    launch_cwd: &Path,
    launch_env: Option<&Value>,
    include_launch_cwd: bool,
    include_python_path: bool,
) -> Value {
    // `[A-Za-z_]\w*(\.[A-Za-z_]\w*)*` fullmatch.
    if !module.split('.').all(|seg| {
        !seg.is_empty()
            && seg
                .chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }) {
        return unproven_runtime_entrypoint(
            "python-module",
            "invalid_module_name",
            Some(std::slice::from_ref(&module.to_string())),
        );
    }
    let mut roots: Vec<PathBuf> = if include_launch_cwd {
        vec![launch_cwd.to_path_buf()]
    } else {
        Vec::new()
    };
    if include_python_path {
        if let Some(raw_python_path) = launch_env
            .and_then(|v| v.get("PYTHONPATH"))
            .and_then(|v| v.as_str())
        {
            for raw_root in raw_python_path.split(':') {
                let root = if raw_root.is_empty() {
                    PathBuf::from(".")
                } else {
                    expand_user(Path::new(raw_root))
                };
                roots.push(if root.is_absolute() {
                    root
                } else {
                    launch_cwd.join(&root)
                });
            }
        }
    }
    let relative_module: PathBuf = module.split('.').collect();
    for root in unique_normalized_paths(&roots) {
        let candidates: [(&str, PathBuf); 4] = [
            (
                "python-module",
                root.join(&relative_module).with_extension("py"),
            ),
            (
                "python-module-bytecode",
                root.join(&relative_module).with_extension("pyc"),
            ),
            (
                "python-package-main",
                root.join(&relative_module).join("__main__.py"),
            ),
            (
                "python-package-main-bytecode",
                root.join(&relative_module).join("__main__.pyc"),
            ),
        ];
        let existing: Vec<(&str, &PathBuf)> = candidates
            .iter()
            .filter(|(_, p)| p.is_file())
            .map(|(k, p)| (*k, p))
            .collect();
        if existing.is_empty() {
            continue;
        }
        if existing.len() != 1 {
            return unproven_runtime_entrypoint(
                "python-module",
                "module_entrypoint_ambiguous",
                Some(std::slice::from_ref(&module.to_string())),
            );
        }
        let (kind, entrypoint_path) = existing[0];
        let mut identity =
            file_runtime_entrypoint(kind, &entrypoint_path.to_string_lossy(), launch_cwd);
        identity["module_sha256"] = Value::String(opaque_identity_digest(module));
        identity["package_initializers"] = Value::Array(python_package_initializer_identities(
            &root,
            &relative_module,
            kind,
            launch_cwd,
        ));
        return identity;
    }
    let reason = if roots.is_empty() {
        "isolated_module_resolution_unproven"
    } else {
        "module_entrypoint_unresolved"
    };
    unproven_runtime_entrypoint(
        "python-module",
        reason,
        Some(std::slice::from_ref(&module.to_string())),
    )
}

// `_python_interactive_environment_identity` (:1412-1423).
fn python_interactive_environment_identity(
    launch_env: Option<&Value>,
    ignore_environment: bool,
) -> Option<Value> {
    if ignore_environment {
        return None;
    }
    let inspect = launch_env
        .and_then(|v| v.get("PYTHONINSPECT"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if !inspect {
        return None;
    }
    Some(unproven_runtime_entrypoint(
        "python-launch",
        "interactive_environment_unresolved",
        None,
    ))
}

// `_unique_normalized_paths` (:1425-1435).
fn unique_normalized_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut unique: Vec<PathBuf> = Vec::new();
    let mut observed: HashSet<String> = HashSet::new();
    for path in paths {
        let normalized = normalized_launch_cwd(Some(path));
        // POSIX normcase is identity.
        let key = normalized.to_string_lossy().into_owned();
        if observed.insert(key) {
            unique.push(normalized);
        }
    }
    unique
}

// `_python_package_initializer_identities` (:1436-1456).
fn python_package_initializer_identities(
    root: &Path,
    relative_module: &Path,
    entrypoint_kind: &str,
    launch_cwd: &Path,
) -> Vec<Value> {
    let parts: Vec<std::ffi::OsString> = relative_module
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let relevant: &[std::ffi::OsString] = if entrypoint_kind.starts_with("python-package-main") {
        &parts
    } else {
        &parts[..parts.len().saturating_sub(1)]
    };
    let mut identities = Vec::new();
    let mut current = root.to_path_buf();
    for part in relevant {
        current.push(part);
        let initializer = current.join("__init__.py");
        if initializer.is_file() {
            identities.push(file_runtime_entrypoint(
                "python-package-initializer",
                &initializer.to_string_lossy(),
                launch_cwd,
            ));
        }
    }
    identities
}

// `_node_runtime_entrypoint_identity` (:1458-1512).
fn node_runtime_entrypoint_identity(
    args: &[String],
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    // NODE_OPTIONS injects a caller-controlled `-r`/`-e` preamble ahead of
    // the script argv, so any visible value makes the entrypoint unproven.
    let node_options_nonempty = launch_env
        .and_then(|v| v.get("NODE_OPTIONS"))
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    if node_options_nonempty {
        return unproven_runtime_entrypoint("node-launch", "environment_options_unresolved", None);
    }
    let mut index = 0usize;
    const HARMLESS_FLAGS: &[&str] = &[
        "--abort-on-uncaught-exception",
        "--enable-source-maps",
        "--no-addons",
        "--no-deprecation",
        "--no-warnings",
        "--trace-deprecation",
        "--trace-uncaught",
        "--trace-warnings",
        "--use-bundled-ca",
        "--use-openssl-ca",
    ];
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            index += 1;
            break;
        }
        if argument == "-e" || argument == "--eval" || argument == "-p" || argument == "--print" {
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint("node-inline", "missing_inline_code", None);
            }
            return inline_runtime_entrypoint("node-inline", &args[index + 1]);
        }
        if argument.starts_with("--eval=") || argument.starts_with("--print=") {
            return inline_runtime_entrypoint(
                "node-inline",
                argument.split_once('=').map(|(_, v)| v).unwrap_or(""),
            );
        }
        if HARMLESS_FLAGS.contains(&argument) {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return unproven_runtime_entrypoint(
                "node-script",
                "unsupported_interpreter_option",
                Some(std::slice::from_ref(&args[index])),
            );
        }
        break;
    }
    if index >= args.len() {
        return unproven_runtime_entrypoint("node-script", "entrypoint_missing", None);
    }
    if args[index] == "-" {
        return unproven_runtime_entrypoint("node-stdin", "stdin_code_unprovable", None);
    }
    file_runtime_entrypoint("node-script", &args[index], launch_cwd)
}

// `_shell_runtime_entrypoint_identity` (:1514-1555).
#[allow(unused_mut)]
fn shell_runtime_entrypoint_identity(
    shell: &str,
    args: &[String],
    launch_cwd: &Path,
    launch_env: Option<&Value>,
) -> Value {
    if shell.starts_with("fish") {
        return unproven_runtime_entrypoint("fish-launch", "shell_startup_unresolved", None);
    }
    let has_startup_env = ["BASH_ENV", "ENV", "ZDOTDIR"].iter().any(|key| {
        launch_env
            .and_then(|v| v.get(*key))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    });
    if has_startup_env {
        return unproven_runtime_entrypoint(
            &format!("{shell}-launch"),
            "shell_startup_environment_unresolved",
            None,
        );
    }
    let mut index = 0usize;
    const HARMLESS_LONG: &[&str] = &[
        "--noprofile",
        "--norc",
        "--posix",
        "--restricted",
        "--verbose",
    ];
    const HARMLESS_SHORT: &str = "abefhkmnptuvxBCEHPT"; // "-i" is already excluded
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == "--" {
            index += 1;
            break;
        }
        let clustered_inline =
            argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains('c');
        if argument == "-c" || argument == "--command" || clustered_inline {
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint(
                    &format!("{shell}-inline"),
                    "missing_inline_code",
                    None,
                );
            }
            return inline_runtime_entrypoint(&format!("{shell}-inline"), &args[index + 1]);
        }
        if HARMLESS_LONG.contains(&argument) {
            index += 1;
            continue;
        }
        // Bare "-" has an empty suffix set, which Python treats as a subset
        // of the harmless options and therefore skips.
        let harmless_short = argument.starts_with('-')
            && !argument.starts_with("--")
            && argument[1..].chars().all(|c| HARMLESS_SHORT.contains(c));
        if harmless_short {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            return unproven_runtime_entrypoint(
                &format!("{shell}-script"),
                "unsupported_interpreter_option",
                Some(std::slice::from_ref(&args[index])),
            );
        }
        break;
    }
    if index >= args.len() {
        return unproven_runtime_entrypoint(
            &format!("{shell}-stdin"),
            "stdin_code_unprovable",
            None,
        );
    }
    file_runtime_entrypoint(&format!("{shell}-script"), &args[index], launch_cwd)
}

// `_simple_runtime_entrypoint_identity` (:1557-1569).
fn simple_runtime_entrypoint_identity(launcher: &str, args: &[String], launch_cwd: &Path) -> Value {
    if args.is_empty() || args[0].starts_with('-') {
        return unproven_runtime_entrypoint(
            &format!("{launcher}-script"),
            "entrypoint_unresolved",
            Some(&args[..args.len().min(1)]),
        );
    }
    file_runtime_entrypoint(&format!("{launcher}-script"), &args[0], launch_cwd)
}

// `_javascript_runtime_entrypoint_identity` (:1578-1604).
fn javascript_runtime_entrypoint_identity(
    launcher: &str,
    args: &[String],
    launch_cwd: &Path,
) -> Value {
    let mut args = args;
    if launcher.starts_with("deno") {
        if args.is_empty() || args[0] != "run" {
            return unproven_runtime_entrypoint(
                "deno-launch",
                "launcher_entrypoint_unresolved",
                Some(args),
            );
        }
        args = &args[1..];
    } else if !args.is_empty() && args[0] == "run" {
        return unproven_runtime_entrypoint(
            "bun-package-script",
            "package_script_entrypoint_unresolved",
            Some(args),
        );
    }
    if args.is_empty() || args[0].starts_with('-') {
        return unproven_runtime_entrypoint(
            &format!("{launcher}-script"),
            "entrypoint_unresolved",
            Some(&args[..args.len().min(1)]),
        );
    }
    file_runtime_entrypoint(&format!("{launcher}-script"), &args[0], launch_cwd)
}

// `_java_runtime_entrypoint_identity` (:1606-1619).
fn java_runtime_entrypoint_identity(args: &[String], launch_cwd: &Path) -> Value {
    let jar_index = match args.iter().position(|a| a == "-jar") {
        Some(i) => i,
        None => {
            return unproven_runtime_entrypoint(
                "java-class",
                "class_entrypoint_unresolved",
                Some(args),
            )
        }
    };
    if jar_index + 1 >= args.len() {
        return unproven_runtime_entrypoint("java-jar", "jar_entrypoint_missing", None);
    }
    file_runtime_entrypoint("java-jar", &args[jar_index + 1], launch_cwd)
}

// `_dotnet_runtime_entrypoint_identity` (:1621-1628).
fn dotnet_runtime_entrypoint_identity(args: &[String], launch_cwd: &Path) -> Value {
    if args.is_empty()
        || args[0].starts_with('-')
        || !(args[0].to_lowercase().ends_with(".dll") || args[0].to_lowercase().ends_with(".exe"))
    {
        return unproven_runtime_entrypoint(
            "dotnet-launch",
            "managed_entrypoint_unresolved",
            Some(&args[..args.len().min(1)]),
        );
    }
    file_runtime_entrypoint("dotnet-assembly", &args[0], launch_cwd)
}

// `_powershell_runtime_entrypoint_identity` (:1630-1654).
fn powershell_runtime_entrypoint_identity(args: &[String], launch_cwd: &Path) -> Value {
    let lowered: Vec<String> = args.iter().map(|a| a.to_lowercase()).collect();
    for option in ["-command", "-c", "-encodedcommand", "-e"] {
        if let Some(index) = lowered.iter().position(|a| a == option) {
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint(
                    "powershell-inline",
                    "missing_inline_code",
                    None,
                );
            }
            return inline_runtime_entrypoint("powershell-inline", &args[index + 1]);
        }
    }
    for option in ["-file", "-f"] {
        if let Some(index) = lowered.iter().position(|a| a == option) {
            if index + 1 >= args.len() {
                return unproven_runtime_entrypoint(
                    "powershell-script",
                    "entrypoint_missing",
                    None,
                );
            }
            return file_runtime_entrypoint("powershell-script", &args[index + 1], launch_cwd);
        }
    }
    unproven_runtime_entrypoint("powershell-launch", "entrypoint_unresolved", Some(args))
}

// `_file_runtime_entrypoint` (:1656-1667).
fn file_runtime_entrypoint(kind: &str, argument: &str, launch_cwd: &Path) -> Value {
    let mut candidate = expand_user(Path::new(argument));
    if !candidate.is_absolute() {
        candidate = launch_cwd.join(&candidate);
    }
    let mut identity = build_runtime_executable_identity(
        &Value::String(candidate.to_string_lossy().into_owned()),
        None,
        Some(launch_cwd),
        None,
        false,
    );
    identity["argument_sha256"] = Value::String(opaque_identity_digest(argument));
    identity["kind"] = Value::String(kind.to_string());
    identity
}

// `_inline_runtime_entrypoint` (:1670-1675).
fn inline_runtime_entrypoint(kind: &str, source: &str) -> Value {
    json!({
        "kind": kind,
        "sha256": opaque_identity_digest(source),
        "status": "verified",
    })
}

// `_unproven_runtime_entrypoint` (:1677-1694).
fn unproven_runtime_entrypoint(kind: &str, reason: &str, selector: Option<&[String]>) -> Value {
    let mut map = Map::new();
    map.insert("kind".to_string(), Value::String(kind.to_string()));
    map.insert("reason".to_string(), Value::String(reason.to_string()));
    map.insert(
        "selector_sha256".to_string(),
        Value::String(launch_argv_digest(selector.unwrap_or(&[]))),
    );
    map.insert("status".to_string(), Value::String("unproven".to_string()));
    map.insert("reuse_nonce".to_string(), Value::String(token_hex(16)));
    Value::Object(map)
}

const NODE_LAUNCHER_NAMES: &[&str] = &["node", "node.exe", "nodejs", "nodejs.exe"];
const SHELL_LAUNCHER_NAMES: &[&str] = &[
    "bash", "bash.exe", "dash", "dash.exe", "fish", "fish.exe", "ksh", "ksh.exe", "sh", "sh.exe",
    "zsh", "zsh.exe",
];
const SIMPLE_SCRIPT_LAUNCHER_NAMES: &[&str] = &[
    "lua",
    "lua.exe",
    "perl",
    "perl.exe",
    "php",
    "php.exe",
    "rscript",
    "rscript.exe",
    "ruby",
    "ruby.exe",
    "ts-node",
    "ts-node.cmd",
    "tsx",
    "tsx.cmd",
];
const UNRESOLVED_CODE_LAUNCHER_NAMES: &[&str] = &[
    "bunx",
    "bunx.exe",
    "docker",
    "docker.exe",
    "go",
    "go.exe",
    "npm",
    "npm.cmd",
    "npx",
    "npx.cmd",
    "pipx",
    "pipx.exe",
    "pnpm",
    "pnpm.cmd",
    "podman",
    "podman.exe",
    "uv",
    "uv.exe",
    "uvx",
    "uvx.exe",
    "yarn",
    "yarn.cmd",
];

// ---------------------------------------------------------------------------
// Package-supply-chain launch/advisory material
// (`local_supply_chain.py` RTM-019).
// ---------------------------------------------------------------------------

// `_package_launch_approval_identity` (local_supply_chain.py :3109-3124) —
// ticket name `_package_request_launch_identity_material` (surface-map alias;
// same argv_sha256 + wrapper_resolution material compose). Pure projection:
// `None` -> `{"available": False}`; otherwise binds `argv_sha256` verbatim and
// passes through a Mapping `wrapper_resolution`, degrading any other/missing
// value to `{"status": "direct"}`.
pub fn package_request_launch_identity_material(
    launch_identity: Option<&Map<String, Value>>,
) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(launch_identity) = launch_identity else {
        out.insert("available".into(), json!(false));
        return out;
    };
    let wrapper_resolution = launch_identity
        .get("wrapper_resolution")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| {
            let mut direct = Map::new();
            direct.insert("status".into(), json!("direct"));
            Value::Object(direct)
        });
    out.insert(
        "argv_sha256".into(),
        launch_identity
            .get("argv_sha256")
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert("wrapper_resolution".into(), wrapper_resolution);
    out
}

// Python `str.strip()` whitespace set (:811 body relies on it via `add_id`).
// `char::is_whitespace` omits the C0 information separators \x1c-\x1f that
// `str.isspace()` strips, so spell the set out for byte-exact parity.
fn python_str_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_str_strip(value: &str) -> &str {
    value.trim_matches(python_str_is_space)
}

// `_package_advisory_ids` (local_supply_chain.py :811-836). First-seen,
// case-sensitive dedup across the four list keys, the two scalar keys, then
// per-reason ids — NOT `sorted(set(...))`. Non-strings, empty-after-strip,
// and repeats are dropped.
pub fn package_advisory_ids(package: &Map<String, Value>) -> Vec<String> {
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add_id = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = python_str_strip(text);
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                advisory_ids.push(trimmed.to_string());
            }
        }
    };
    for key in [
        "advisoryIds",
        "advisory_ids",
        "relatedAdvisoryIds",
        "related_advisory_ids",
    ] {
        if let Some(raw) = package.get(key).and_then(Value::as_array) {
            for entry in raw {
                add_id(Some(entry));
            }
        }
    }
    add_id(package.get("advisoryId"));
    add_id(package.get("advisory_id"));
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            add_id(reason.get("advisoryId"));
            add_id(reason.get("advisory_id"));
        }
    }
    advisory_ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "hg-rtm008-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_script(body: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new();
        let path = dir.path().join("run.sh");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        drop(f);
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        (dir, path)
    }

    #[test]
    fn executable_identity_verified_for_real_script() {
        let (_dir, path) = temp_script("#!/bin/sh\necho hi\n");
        let identity = build_runtime_executable_identity(
            &Value::String(path.to_string_lossy().into_owned()),
            None,
            None,
            None,
            true,
        );
        assert_eq!(identity["status"], "verified");
        let sha = identity["sha256"].as_str().unwrap();
        assert_eq!(sha.len(), 64);
        assert!(sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(identity["file_format"], "script");
        assert_eq!(identity["shebang_status"], "verified");
    }

    #[test]
    fn executable_identity_unresolved_for_missing() {
        let identity = build_runtime_executable_identity(
            &Value::String("definitely-missing-cmd-rtm008".to_string()),
            Some("/nonexistent"),
            None,
            None,
            true,
        );
        assert_eq!(identity["status"], "unresolved");
        assert!(identity["reuse_nonce"].is_string());
    }

    #[test]
    fn reusable_detects_nested_reuse_nonce() {
        let nested = json!({"a": {"b": {"reuse_nonce": "x"}}});
        assert!(!runtime_launch_identity_is_reusable(&nested));
        let clean = json!({"a": {"b": {"status": "verified"}}});
        assert!(runtime_launch_identity_is_reusable(&clean));
    }

    #[test]
    fn launch_argv_digest_matches_python_oracle() {
        // Oracle:
        //   python3 -c "import json,hashlib;
        //   print(hashlib.sha256(json.dumps({'label':'launch-argv','material':
        //   json.dumps(['git','status'],separators=(',',':'),ensure_ascii=True)},
        //   separators=(',',':'),sort_keys=True,ensure_ascii=True).encode()).hexdigest())"
        //
        // The Python digest is
        //   context_opaque_digest(json.dumps(['git','status']), unbound_label='launch-argv')
        // whose strict degrade is
        //   'guard-context-unbound:launch-argv:' +
        //   sha256(json.dumps({'label':'launch-argv','material':'["git","status"]'},
        //                    separators=(',',':'),sort_keys=True,ensure_ascii=True))
        let expected = concat!(
            "guard-context-unbound:launch-argv:",
            "PLACEHOLDER" // replaced by oracle below
        );
        let _ = expected;
        // Compute oracle inline to keep the test self-contained.
        // Python oracle (verified): canonical_material_bytes('["git","status"]')
        // = b'"[\\"git\\",\\"status\\"]"' — the argv JSON is itself a
        // JSON string, so the outer canonical encoding escapes it.
        let inner = "[\"git\",\"status\"]";
        let mut canonical = Vec::new();
        write_canonical_json(&Value::String(inner.to_string()), &mut canonical).unwrap();
        let oracle = format!(
            "guard-context-unbound:launch-argv:{}",
            hex::encode(Sha256::digest(&canonical))
        );
        assert_eq!(
            launch_argv_digest(&["git".to_string(), "status".to_string()]),
            oracle
        );
    }

    #[test]
    fn deterministic_digests_match_python_oracles() {
        // Oracle 1 (python3, verified): _launch_argv_digest(("git","status"))
        // strict degrade = guard-context-unbound:launch-argv:<sha256>.
        assert_eq!(
            launch_argv_digest(&["git".to_string(), "status".to_string()]),
            "guard-context-unbound:launch-argv:8731c2300a49f227285b1c5d205ce9232d4438adafb38cfbb1676b6ca8043c5d"
        );
        // Oracle 2: opaque_identity_digest("/bin/sh").
        assert_eq!(
            opaque_identity_digest("/bin/sh"),
            "guard-context-unbound:opaque-identity:ea0135d2021a123a116e4bc76993e130aa037cc0ada7a86924ed9e6037f462ab"
        );
        // Oracle 3: context_sha256_digest({"kind":"x","status":"verified"},
        // unbound_label="launch-verification") strict degrade.
        assert_eq!(
            context_sha256_digest_strict(
                &json!({"kind": "x", "status": "verified"}),
                "launch-verification"
            ),
            "guard-context-unbound:launch-verification:33f54a528b020a160461134ec8cf256d36536c821bd5a3e2538b160f9212a030"
        );
    }

    // --- Package launch/advisory material (local_supply_chain.py) ------------

    fn canon(value: &Value) -> String {
        let mut out = Vec::new();
        write_canonical_json(value, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn launch_identity_material_none_oracle() {
        // Oracle: _package_launch_approval_identity(None)
        //   -> {"available": False}
        let out = package_request_launch_identity_material(None);
        assert_eq!(out.len(), 1);
        assert_eq!(out["available"], json!(false));
        assert_eq!(
            canon(&Value::Object(out)),
            concat!("{\"available\":", "false}"),
        );
    }

    #[test]
    fn launch_identity_material_empty_map_oracle() {
        // Oracle: _package_launch_approval_identity({})
        //   -> {"argv_sha256": null, "wrapper_resolution": {"status": "direct"}}
        let input = Map::new();
        let out = package_request_launch_identity_material(Some(&input));
        assert_eq!(
            canon(&Value::Object(out)),
            concat!(
                "{\"argv_sha256\":null,\"wrapper_resolution\":{\"status\":\"",
                "direct\"}}",
            ),
        );
    }

    #[test]
    fn launch_identity_material_wrapper_mapping_oracle() {
        // Oracle: _package_launch_approval_identity(
        //   {"argv_sha256": "a"*64,
        //    "wrapper_resolution": {"status": "wrapper", "wrapper": "env",
        //                           "attempts": 1}})
        let input: Map<String, Value> = serde_json::from_value(json!({
            "argv_sha256": "a".repeat(64),
            "wrapper_resolution": {
                "status": "wrapper",
                "wrapper": "env",
                "attempts": 1,
            },
        }))
        .unwrap();
        let out = package_request_launch_identity_material(Some(&input));
        assert_eq!(out["argv_sha256"], json!("a".repeat(64)));
        assert_eq!(
            canon(&Value::Object(out)),
            concat!(
                "{\"argv_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"",
                "wrapper_resolution\":{\"attempts\":1,\"status\":\"wrapper\",\"wrapper\":\"env\"}}",
            ),
        );
    }

    #[test]
    fn launch_identity_material_non_mapping_wrapper_degrades_to_direct() {
        // Oracle: wrapper_resolution="env-wrapped" or None -> {"status": "direct"};
        // unrelated keys do not leak through.
        for wrapper in [json!("env-wrapped"), Value::Null, json!(7), json!(["x"])] {
            let input: Map<String, Value> = serde_json::from_value(json!({
                "argv_sha256": "c".repeat(64),
                "wrapper_resolution": wrapper,
                "other": 1,
            }))
            .unwrap();
            let out = package_request_launch_identity_material(Some(&input));
            assert_eq!(
                canon(&Value::Object(out)),
                concat!(
                    "{\"argv_sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"",
                    "wrapper_resolution\":{\"status\":\"direct\"}}",
                ),
            );
        }
    }

    #[test]
    fn advisory_ids_empty_package_oracle() {
        // Oracle: _package_advisory_ids({}) -> []
        assert!(package_advisory_ids(&Map::new()).is_empty());
    }

    #[test]
    fn advisory_ids_full_oracle_parity() {
        // Oracle: _package_advisory_ids(<fixture>) ==
        //   ["GHSA-1111","CVE-2024-2","RUSTSEC-2024-3","GHSA-zzzz",
        //    "ghsa-zzzz","GHSA-HEAD","GHSA-R1","ghsa-r2"]
        // First-seen insertion order across the four list keys, the two
        // scalar keys, then reasons — dedup is case-sensitive, so
        // "GHSA-zzzz"/"ghsa-zzzz" both survive (NOT sorted(set(...))).
        let package: Map<String, Value> = serde_json::from_value(json!({
            "advisoryIds": ["GHSA-1111", " CVE-2024-2 ", "GHSA-1111", "", 7, null],
            "advisory_ids": ["CVE-2024-2", "RUSTSEC-2024-3"],
            "relatedAdvisoryIds": ["GHSA-zzzz"],
            "related_advisory_ids": ["ghsa-zzzz", "GHSA-1111"],
            "advisoryId": " GHSA-HEAD ",
            "advisory_id": "GHSA-HEAD",
            "reasons": [
                {"advisoryId": "GHSA-R1", "advisory_id": "ghsa-r2"},
                {"advisoryId": "GHSA-1111"},
                "not-a-dict",
                {"other": "x"},
            ],
        }))
        .unwrap();
        assert_eq!(
            package_advisory_ids(&package),
            vec![
                "GHSA-1111",
                "CVE-2024-2",
                "RUSTSEC-2024-3",
                "GHSA-zzzz",
                "ghsa-zzzz",
                "GHSA-HEAD",
                "GHSA-R1",
                "ghsa-r2",
            ],
        );
    }

    #[test]
    fn advisory_ids_malformed_inputs_oracle() {
        // Oracle: _package_advisory_ids({"advisoryIds": "not-a-list",
        //   "reasons": "nope", "advisoryId": 42}) -> []
        //  and  {"reasons": [{"advisoryId": "  "}, {"advisory_id": null}]} -> []
        let package: Map<String, Value> = serde_json::from_value(json!({
            "advisoryIds": "not-a-list",
            "reasons": "nope",
            "advisoryId": 42,
        }))
        .unwrap();
        assert!(package_advisory_ids(&package).is_empty());
        let package2: Map<String, Value> = serde_json::from_value(json!({
            "reasons": [{"advisoryId": "  "}, {"advisory_id": null}],
        }))
        .unwrap();
        assert!(package_advisory_ids(&package2).is_empty());
    }

    #[test]
    fn advisory_ids_python_strip_whitespace_oracle() {
        // Python str.strip() removes \x1c-\x1f; char::is_whitespace does not.
        // A \x1c-padded id must trim to the same string and dedup.
        // Oracle: _package_advisory_ids(
        //   {"advisoryIds": ["\x1cGHSA-X\x1d", "GHSA-X"]}) -> ["GHSA-X"]
        let package: Map<String, Value> = serde_json::from_value(json!({
            "advisoryIds": ["\u{1c}GHSA-X\u{1d}", "GHSA-X"],
        }))
        .unwrap();
        assert_eq!(package_advisory_ids(&package), vec!["GHSA-X"]);
    }

    /// `env -S` option clusters must terminate after an operand-consuming flag
    /// (`short_index = len(token)` in `env_wrapper.parse_env_wrapper`). The port
    /// omitted that advance, so the cluster loop re-read the same flag until
    /// `ENV_SPLIT_MAX_EXPANSIONS` tripped and every `#!/usr/bin/env -S ...`
    /// shebang resolved as `env_shebang_command_unresolved`.
    #[test]
    fn env_split_string_cluster_consumes_operand_once() {
        for (args, expected) in [
            (
                vec!["-S", "python", "-m", "bootstrap"],
                vec!["python", "-m", "bootstrap"],
            ),
            (
                vec!["-S python -m bootstrap"],
                vec!["python", "-m", "bootstrap"],
            ),
            (vec!["-Spython"], vec!["python"]),
            (vec!["-u", "FOO", "cmd"], vec!["cmd"]),
            (vec!["-C", "/tmp", "cmd"], vec!["cmd"]),
            (vec!["cmd"], vec!["cmd"]),
        ] {
            let tokens: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let parsed = crate::env_wrapper::parse_env_wrapper(&tokens, None, None);
            assert_eq!(parsed.error, None, "{args:?}");
            assert!(parsed.complete, "{args:?}");
            assert_eq!(parsed.executable_argv, expected, "{args:?}");
        }
    }

    /// Descriptor-race parity for the ported executable hasher. The Python
    /// `test_windows_executable_hash_keeps_descriptor_race_checks` matrix was
    /// retired with the approval_context helper cluster; this keeps the same
    /// decision contract on the Rust side: any stat field that moves between
    /// the pre-open probe and the opened descriptor yields `identity_raced`
    /// with no digest, while an unmoved stat verifies.
    #[test]
    fn executable_hash_reports_identity_races() {
        let (_dir, path) = temp_script("#!/bin/sh\necho hi\n");
        let expected = stat_key(&fs::metadata(&path).unwrap());
        let (digest, status, _shebang, _shebang_status) = cached_executable_hash(&path, expected);
        assert_eq!(status, "verified");
        assert!(digest.is_some());

        fn assert_identity_raced(path: &Path, expected: StatKey) {
            let (digest, status, _shebang, _shebang_status) =
                cached_executable_hash(path, expected);
            assert_eq!(status, "identity_raced");
            assert!(digest.is_none());
        }

        let mut raced = expected;
        raced.ino += 1;
        assert_identity_raced(&path, raced);

        let mut raced = expected;
        raced.mode &= !0o111;
        assert_identity_raced(&path, raced);

        let mut raced = expected;
        raced.mtime_ns += 1;
        assert_identity_raced(&path, raced);

        let mut raced = expected;
        raced.ctime_ns += 1;
        assert_identity_raced(&path, raced);

        let mut raced = expected;
        raced.size += 1;
        assert_identity_raced(&path, raced);
    }

    /// `O_NOFOLLOW` must reject a final-component symlink exactly like the
    /// Python `os.open(..., O_NOFOLLOW)` it replaced: nothing is hashed.
    #[cfg(unix)]
    #[test]
    fn executable_hash_refuses_final_symlink() {
        let (dir, path) = temp_script("#!/bin/sh\necho hi\n");
        let link = dir.path().join("link.sh");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let expected = stat_key(&fs::metadata(&link).unwrap());
        assert_eq!(cached_executable_hash(&link, expected).1, "open_failed");
    }
}
