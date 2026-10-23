//! Optional task-scoped MCP mutation limit, claimed before forwarding a call.
//!
//! A trusted operator installs the policy in the private Guard home. The
//! resident owns classification, the cross-proxy counter, and the one-use
//! claim. An unavailable or corrupt configured policy blocks the call.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use fs2::FileExt;
use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) const FEATURE: &str = "mcp-task-write-budget-v1";
const REQUEST_SCHEMA: &str = "guard-mcp-write-budget-claim-request.v1";
const RESULT_SCHEMA: &str = "guard-mcp-write-budget-claim-result.v1";
const POLICY_SCHEMA: &str = "guard-mcp-task-write-budget.v1";
const STATE_SCHEMA: &str = "guard-mcp-task-write-budget-state.v3";
const POLICY_NAME: &str = "mcp-task-write-budget.json";
const LOCK_NAME: &str = "mcp-task-write-budget.lock";
const STATE_NAME: &str = "mcp-task-write-budget-state.json";
const STATE_MAX_BYTES: u64 = 65_536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRequest {
    schema: String,
    request_id: String,
    pub(crate) guard_home: String,
    tool_name: String,
    // The trusted proxy extracts these fields from the call it will forward.
    // Large tool bodies never cross the resident protocol for this decision.
    arguments: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    max_writes: u32,
    read_only_tools: Vec<String>,
    #[serde(default)]
    reserved_record_ids: Vec<String>,
    #[serde(default)]
    required_source_ids: Vec<String>,
    #[serde(default)]
    tool_write_limits: BTreeMap<String, u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    policy_sha256: String,
    claimed_writes: u32,
    cited_source_ids: Vec<String>,
    claimed_by_tool: BTreeMap<String, u32>,
}

enum ClaimOutcome {
    Claimed(u32),
    Exhausted,
    MissingSources(Vec<String>),
    ToolExhausted,
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn private_home(path: &Path) -> Option<File> {
    if !path.is_absolute() {
        return None;
    }
    let mut current = open("/", directory_flags(), Mode::empty()).ok()?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return None;
        };
        current = openat(&current, name, directory_flags(), Mode::empty()).ok()?;
    }
    let home = File::from(current);
    home.metadata()
        .ok()
        .filter(|info| {
            info.is_dir() && info.uid() == Uid::current().as_raw() && info.mode() & 0o7777 == 0o700
        })
        .map(|_| home)
}

fn regular_private(file: &File, max_bytes: u64) -> bool {
    file.metadata().is_ok_and(|info| {
        info.is_file()
            && info.uid() == Uid::current().as_raw()
            && info.mode() & 0o7777 == 0o600
            && info.nlink() == 1
            && info.len() <= max_bytes
    })
}

fn read_bounded(file: &mut File, max_bytes: u64) -> Option<Vec<u8>> {
    if !regular_private(file, max_bytes) {
        return None;
    }
    let mut raw = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut raw).ok()?;
    (raw.len() as u64 <= max_bytes).then_some(raw)
}

fn policy(home: &File) -> Result<Option<(Policy, String)>, ()> {
    let fd = match openat(
        home,
        POLICY_NAME,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(()),
    };
    let raw = read_bounded(&mut File::from(fd), 8192).ok_or(())?;
    let parsed: Policy = serde_json::from_slice(&raw).map_err(|_| ())?;
    if parsed.schema != POLICY_SCHEMA
        || !(1..=1000).contains(&parsed.max_writes)
        || !valid_names(&parsed.read_only_tools)
        || !valid_names(&parsed.reserved_record_ids)
        || !valid_names(&parsed.required_source_ids)
        || parsed.tool_write_limits.len() > 128
        || parsed.tool_write_limits.iter().any(|(name, limit)| {
            !valid_names(std::slice::from_ref(name)) || *limit == 0 || *limit > parsed.max_writes
        })
    {
        return Err(());
    }
    if !unique(&parsed.read_only_tools)
        || !unique(&parsed.reserved_record_ids)
        || !unique(&parsed.required_source_ids)
    {
        return Err(());
    }
    Ok(Some((parsed, hex::encode(Sha256::digest(raw)))))
}

fn valid_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'/' | b':')
}

fn valid_names(names: &[String]) -> bool {
    names.len() <= 128
        && names
            .iter()
            .all(|name| !name.is_empty() && name.len() <= 256 && name.bytes().all(valid_name_byte))
}

fn unique(names: &[String]) -> bool {
    names.iter().collect::<BTreeSet<_>>().len() == names.len()
}

fn cited_sources(tool_name: &str, arguments: &serde_json::Value) -> Vec<String> {
    let Some(data) = arguments.get("data") else {
        return Vec::new();
    };
    let artifact = if tool_name.ends_with(".update") {
        data.get("notes")
            .or_else(|| data.get("internal_notes"))
            .and_then(serde_json::Value::as_array)
            .and_then(|notes| notes.last())
            .unwrap_or(data)
    } else {
        data
    };
    let (Some(ids), Some(versions)) = (
        artifact
            .get("source_ids")
            .and_then(serde_json::Value::as_array),
        artifact
            .get("source_versions")
            .and_then(serde_json::Value::as_object),
    ) else {
        return Vec::new();
    };
    if ids.len() > 128 || ids.len() != versions.len() {
        return Vec::new();
    }
    let mut cited = Vec::new();
    for item in ids {
        let Some(id) = item.as_str() else {
            return Vec::new();
        };
        if id.is_empty()
            || id.len() > 256
            || !id.bytes().all(valid_name_byte)
            || versions
                .get(id)
                .and_then(serde_json::Value::as_u64)
                .is_none_or(|v| v == 0)
        {
            return Vec::new();
        }
        cited.push(id.to_owned());
    }
    if !unique(&cited) {
        return Vec::new();
    }
    cited
}

fn state_file(home: &File) -> Option<(File, bool)> {
    let flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let (fd, new) = match openat(
        home,
        STATE_NAME,
        flags | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::from_bits_truncate(0o600),
    ) {
        Ok(fd) => (fd, true),
        Err(Errno::EEXIST) => (openat(home, STATE_NAME, flags, Mode::empty()).ok()?, false),
        Err(_) => return None,
    };
    let file = File::from(fd);
    regular_private(&file, STATE_MAX_BYTES).then_some((file, new))
}

fn claim(
    home: &File,
    digest: &str,
    maximum: u32,
    tool_name: &str,
    tool_limit: Option<u32>,
    cited: &[String],
    required: &[String],
) -> Option<ClaimOutcome> {
    let lock = File::from(
        openat(
            home,
            LOCK_NAME,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .ok()?,
    );
    if !regular_private(&lock, 0) || lock.lock_exclusive().is_err() {
        return None;
    }
    let (mut file, new) = state_file(home)?;
    let mut state = if new {
        State {
            schema: STATE_SCHEMA.into(),
            policy_sha256: digest.into(),
            claimed_writes: 0,
            cited_source_ids: Vec::new(),
            claimed_by_tool: BTreeMap::new(),
        }
    } else {
        let raw = read_bounded(&mut file, STATE_MAX_BYTES)?;
        serde_json::from_slice::<State>(&raw).ok()?
    };
    if state.schema != STATE_SCHEMA
        || state.policy_sha256 != digest
        || state.claimed_writes > maximum
        || !valid_names(&state.cited_source_ids)
        || !unique(&state.cited_source_ids)
        || state.claimed_by_tool.len() > 128
        || state.claimed_by_tool.iter().any(|(name, count)| {
            !valid_names(std::slice::from_ref(name)) || *count == 0 || *count > maximum
        })
        || state
            .claimed_by_tool
            .values()
            .map(|value| u64::from(*value))
            .sum::<u64>()
            != u64::from(state.claimed_writes)
    {
        return None;
    }
    if state.claimed_writes == maximum {
        return Some(ClaimOutcome::Exhausted);
    }
    if tool_limit
        .is_some_and(|limit| state.claimed_by_tool.get(tool_name).copied().unwrap_or(0) >= limit)
    {
        return Some(ClaimOutcome::ToolExhausted);
    }
    let mut sources: BTreeSet<String> = state.cited_source_ids.into_iter().collect();
    sources.extend(cited.iter().cloned());
    if state.claimed_writes + 1 == maximum {
        let missing: Vec<String> = required
            .iter()
            .filter(|id| !sources.contains(*id))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Some(ClaimOutcome::MissingSources(missing));
        }
    }
    state.claimed_writes += 1;
    *state
        .claimed_by_tool
        .entry(tool_name.to_owned())
        .or_insert(0) += 1;
    state.cited_source_ids = sources.into_iter().collect();
    let raw = serde_json::to_vec(&state).ok()?;
    file.seek(SeekFrom::Start(0)).ok()?;
    file.set_len(0).ok()?;
    file.write_all(&raw).ok()?;
    file.sync_all().ok()?;
    Some(ClaimOutcome::Claimed(maximum - state.claimed_writes))
}

pub(crate) fn evaluate(request: &ClaimRequest) -> Result<Vec<u8>, String> {
    let (decision, reason, remaining, missing_source_ids) = if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.tool_name.is_empty()
        || request.tool_name.len() > 256
        || request.tool_name.bytes().any(|c| !valid_name_byte(c))
    {
        ("block", "invalid_request", None, Vec::new())
    } else if let Some(home) = private_home(Path::new(&request.guard_home)) {
        match policy(&home) {
            Ok(None) => ("inactive", "no_policy", None, Vec::new()),
            Ok(Some((policy, _))) if policy.read_only_tools.contains(&request.tool_name) => {
                ("allow", "read_only", None, Vec::new())
            }
            Ok(Some((_policy, _))) if !request.arguments.is_object() => {
                ("block", "invalid_arguments", None, Vec::new())
            }
            Ok(Some((policy, digest)))
                if request.tool_name.ends_with(".create")
                    || request.tool_name.ends_with(".create_draft")
                    || request.tool_name.ends_with(".post") =>
            {
                let reserved = request
                    .arguments
                    .get("record_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|id| policy.reserved_record_ids.iter().any(|held| held == id));
                if reserved {
                    ("block", "record_id_reserved", None, Vec::new())
                } else {
                    claim_decision(&home, &policy, &digest, request)
                }
            }
            Ok(Some((policy, digest))) => claim_decision(&home, &policy, &digest, request),
            Err(()) => ("block", "policy_invalid", None, Vec::new()),
        }
    } else {
        ("block", "guard_home_invalid", None, Vec::new())
    };
    crate::encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "request_id": request.request_id,
        "status": "ok",
        "decision": decision,
        "reason": reason,
        "remaining": remaining,
        "missing_source_ids": missing_source_ids,
    }))
}

fn claim_decision(
    home: &File,
    policy: &Policy,
    digest: &str,
    request: &ClaimRequest,
) -> (&'static str, &'static str, Option<u32>, Vec<String>) {
    let tool_limit = if policy.tool_write_limits.is_empty() {
        None
    } else if let Some(limit) = policy.tool_write_limits.get(&request.tool_name) {
        Some(*limit)
    } else {
        return ("block", "tool_not_authorized", None, Vec::new());
    };
    let cited = cited_sources(&request.tool_name, &request.arguments);
    match claim(
        home,
        digest,
        policy.max_writes,
        &request.tool_name,
        tool_limit,
        &cited,
        &policy.required_source_ids,
    ) {
        Some(ClaimOutcome::Claimed(remaining)) => ("allow", "claimed", Some(remaining), Vec::new()),
        Some(ClaimOutcome::Exhausted) => ("block", "write_budget_exhausted", Some(0), Vec::new()),
        Some(ClaimOutcome::MissingSources(missing)) => {
            ("block", "required_source_references_missing", None, missing)
        }
        Some(ClaimOutcome::ToolExhausted) => {
            ("block", "tool_write_limit_exhausted", None, Vec::new())
        }
        None => ("block", "budget_state_invalid", None, Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, ClaimRequest) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().canonicalize().unwrap();
        let file = path.join(POLICY_NAME);
        std::fs::write(
            &file,
            serde_json::to_vec(&json!({
                "schema": POLICY_SCHEMA,
                "max_writes": 2,
                "read_only_tools": ["crm.read"],
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        (
            root,
            ClaimRequest {
                schema: REQUEST_SCHEMA.into(),
                request_id: "test-claim".into(),
                guard_home: path.to_str().unwrap().into(),
                tool_name: "crm.update".into(),
                arguments: json!({"record_id": "contact-a", "data": {}}),
            },
        )
    }

    fn decision(request: &ClaimRequest) -> serde_json::Value {
        serde_json::from_slice(&evaluate(request).unwrap()).unwrap()
    }

    #[test]
    fn read_calls_do_not_consume_mutation_budget() {
        let (_root, mut request) = setup();
        request.tool_name = "crm.read".into();
        assert_eq!(decision(&request)["reason"], "read_only");
        request.tool_name = "crm.update".into();
        assert_eq!(decision(&request)["remaining"], 1);
        assert_eq!(decision(&request)["remaining"], 0);
        assert_eq!(decision(&request)["reason"], "write_budget_exhausted");
    }

    #[test]
    fn changed_policy_and_corrupt_state_fail_closed() {
        let (_root, request) = setup();
        assert_eq!(decision(&request)["decision"], "allow");
        let home = Path::new(&request.guard_home);
        let policy = home.join(POLICY_NAME);
        let mut raw = std::fs::read(&policy).unwrap();
        raw.push(b' ');
        std::fs::write(&policy, raw).unwrap();
        assert_eq!(decision(&request)["reason"], "budget_state_invalid");
        std::fs::write(home.join(STATE_NAME), b"broken").unwrap();
        assert_eq!(decision(&request)["decision"], "block");
    }

    #[test]
    fn absent_policy_does_not_claim_state() {
        let (_root, request) = setup();
        let home = Path::new(&request.guard_home);
        std::fs::remove_file(home.join(POLICY_NAME)).unwrap();
        assert_eq!(decision(&request)["decision"], "inactive");
        assert!(!home.join(STATE_NAME).exists());
    }

    #[test]
    fn concurrent_proxies_cannot_exceed_the_claim_limit() {
        let (_root, request) = setup();
        let request = std::sync::Arc::new(request);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let request = request.clone();
                std::thread::spawn(move || decision(&request)["decision"] == "allow")
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .filter(|allowed| *allowed)
                .count(),
            2
        );
    }

    #[test]
    fn reserved_create_id_is_blocked_without_spending_a_write() {
        let (_root, mut request) = setup();
        let path = Path::new(&request.guard_home).join(POLICY_NAME);
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": POLICY_SCHEMA, "max_writes": 2,
                "read_only_tools": ["crm.read"],
                "reserved_record_ids": ["lead-a"],
            }))
            .unwrap(),
        )
        .unwrap();
        request.tool_name = "mail.create_draft".into();
        request.arguments = json!({"record_id": "lead-a", "data": {}});
        assert_eq!(decision(&request)["reason"], "record_id_reserved");
        request.arguments["record_id"] = json!("draft-a");
        assert_eq!(decision(&request)["remaining"], 1);
    }

    #[test]
    fn final_write_requires_trusted_provenance_coverage() {
        let (_root, mut request) = setup();
        let path = Path::new(&request.guard_home).join(POLICY_NAME);
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": POLICY_SCHEMA, "max_writes": 2,
                "read_only_tools": ["crm.read"],
                "required_source_ids": ["contact-c"],
            }))
            .unwrap(),
        )
        .unwrap();
        request.arguments = json!({"record_id": "contact-a", "data": {"notes": [{
            "source_ids": ["contact-a"], "source_versions": {"contact-a": 1}
        }]}});
        assert_eq!(decision(&request)["remaining"], 1);
        request.tool_name = "mail.create_draft".into();
        request.arguments = json!({"record_id": "draft-a", "data": {
            "source_ids": ["contact-b"], "source_versions": {"contact-b": 1}
        }});
        let blocked = decision(&request);
        assert_eq!(blocked["reason"], "required_source_references_missing");
        assert_eq!(blocked["missing_source_ids"], json!(["contact-c"]));
        request.arguments["data"] = json!({
            "source_ids": ["contact-b", "contact-c"],
            "source_versions": {"contact-b": 1, "contact-c": 1}
        });
        assert_eq!(decision(&request)["remaining"], 0);
        assert_eq!(decision(&request)["reason"], "write_budget_exhausted");
    }

    #[test]
    fn tool_limits_reserve_draft_slots_from_extra_crm_updates() {
        let (_root, mut request) = setup();
        let path = Path::new(&request.guard_home).join(POLICY_NAME);
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": POLICY_SCHEMA, "max_writes": 4,
                "read_only_tools": ["crm.read"],
                "tool_write_limits": {"crm.update": 2, "mail.create_draft": 2},
            }))
            .unwrap(),
        )
        .unwrap();
        request.tool_name = "mail.send".into();
        assert_eq!(decision(&request)["reason"], "tool_not_authorized");
        request.tool_name = "crm.update".into();
        assert_eq!(decision(&request)["remaining"], 3);
        assert_eq!(decision(&request)["remaining"], 2);
        assert_eq!(decision(&request)["reason"], "tool_write_limit_exhausted");
        request.tool_name = "mail.create_draft".into();
        request.arguments = json!({"record_id": "draft-a", "data": {}});
        assert_eq!(decision(&request)["remaining"], 1);
        assert_eq!(decision(&request)["remaining"], 0);
        assert_eq!(decision(&request)["reason"], "write_budget_exhausted");
    }
}
