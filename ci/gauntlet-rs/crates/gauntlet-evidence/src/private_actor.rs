//! Pure Python parity for a private-cell actor's reported /proc privilege floor.
//! This does not authenticate the source of its process and status fields.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const ACTOR: &str = "actual private actor/process privilege boundary differs";
const FILTERS: &str = "private process lacks both syscall filters";

fn field<'a>(row: &'a Value, name: &str) -> Result<&'a str> {
    row.get(name)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid(ACTOR))
}

fn zero_hex(value: &str) -> bool {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        && digits.bytes().all(|byte| byte == b'0')
}

/// Check the exact actor label/namespaces, three-FD floor, saved UID/GID,
/// capabilities, no-new-privileges and optional two-filter seccomp rule.
pub fn verify_private_actor(
    identity: &Value,
    label: &str,
    namespaces: &Value,
    filtered: bool,
) -> Result<Value> {
    let status = identity
        .get("status")
        .ok_or(EvidenceError::Invalid(ACTOR))?;
    let pid = identity.get("pid").and_then(Value::as_u64);
    let start = field(identity, "start_time")?;
    let fds = identity
        .get("fds")
        .and_then(Value::as_object)
        .ok_or(EvidenceError::Invalid(ACTOR))?;
    let fd_set: BTreeSet<&str> = fds.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = ["0", "1", "2"].into_iter().collect();
    let expected_ids = ["10004", "10004", "10004", "10004"];
    if pid.is_none_or(|pid| pid == 0)
        || start.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || identity.get("lsm_label") != Some(&json!(label))
        || identity.get("namespaces") != Some(namespaces)
        || fd_set != expected
        || field(status, "Uid")?.split_whitespace().collect::<Vec<_>>() != expected_ids
        || field(status, "Gid")?.split_whitespace().collect::<Vec<_>>() != expected_ids
        || !field(status, "Groups")?.trim().is_empty()
        || field(status, "NoNewPrivs")?.trim() != "1"
        || ["CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"]
            .iter()
            .any(|name| {
                status
                    .get(*name)
                    .and_then(Value::as_str)
                    .is_none_or(|value| !zero_hex(value))
            })
    {
        return Err(EvidenceError::Invalid(ACTOR));
    }
    if filtered {
        let filters = status
            .get("Seccomp_filters")
            .and_then(Value::as_str)
            .and_then(|value| value.trim().parse::<i64>().ok());
        if field(status, "Seccomp")?.trim() != "2" || filters.is_none_or(|count| count < 2) {
            return Err(EvidenceError::Invalid(FILTERS));
        }
    }
    Ok(json!({"actor_consistent": true, "execution_eligible": false}))
}
