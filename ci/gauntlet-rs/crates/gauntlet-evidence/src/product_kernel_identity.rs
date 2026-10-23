//! Python parity for a controller-reported product process identity.
//! Real kernel collection and producer authentication are separate checks.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};

const MISSING: &str = "missing controller-observed product kernel identity";
const PRIVILEGE: &str = "actual product UID/capability isolation mismatch";
const MCP: &str = "v2 MCP saved identities/groups/capability floor differs";
const PROCESS: &str = "product process kernel identity is incomplete";
const CONTROLLER: &str = "product shares controller namespace";
const AGENT: &str = "product shares agent namespace";

/// Recompute Python `product_custody._kernel` over supplied identity rows.
/// A matching row is a data relation, not proof that a real process existed.
pub fn verify_product_kernel_identity(
    identity: &Value,
    controller: &Value,
    agent: Option<&Value>,
    product_uid: u64,
) -> Result<Value> {
    if !identity.is_object() {
        return Err(EvidenceError::Invalid(MISSING));
    }
    if !matches!(product_uid, 10004 | 10005)
        || identity.get("effective_uid").and_then(Value::as_u64) != Some(product_uid)
        || identity.get("effective_gid").and_then(Value::as_u64) != Some(product_uid)
        || identity.get("effective_capabilities") != Some(&json!("0000000000000000"))
        || identity.get("no_new_privileges").and_then(Value::as_u64) != Some(1)
    {
        return Err(EvidenceError::Invalid(PRIVILEGE));
    }
    if product_uid == 10005 {
        let slots = json!([10005, 10005, 10005, 10005]);
        let groups = identity.get("supplementary_groups");
        let caps = json!({
            "CapEff": "0000000000000000",
            "CapPrm": "0000000000000000",
            "CapInh": "0000000000000000",
            "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000",
        });
        if identity.get("uid_slots") != Some(&slots)
            || identity.get("gid_slots") != Some(&slots)
            || (groups != Some(&json!([])) && groups != Some(&json!([10005])))
            || identity.get("capability_sets") != Some(&caps)
        {
            return Err(EvidenceError::Invalid(MCP));
        }
    }
    let boot = identity.get("boot_id").and_then(Value::as_str);
    let start = identity.get("start_time").and_then(Value::as_str);
    if boot.is_none()
        || identity.get("boot_id") != controller.get("boot_id")
        || !start.is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(EvidenceError::Invalid(PROCESS));
    }
    for field in ["mount_namespace", "pid_namespace", "network_namespace"] {
        let actual = identity.get(field).and_then(Value::as_str);
        let controller_ns = controller.get(field).and_then(Value::as_str);
        if actual.is_none_or(str::is_empty) || controller_ns.is_none() || actual == controller_ns {
            return Err(EvidenceError::Invalid(CONTROLLER));
        }
        if let Some(agent) = agent {
            let agent_ns = agent.get(field).and_then(Value::as_str);
            if agent_ns.is_none() || actual == agent_ns {
                return Err(EvidenceError::Invalid(AGENT));
            }
        }
    }
    Ok(json!({"identity_consistent": true, "execution_eligible": false}))
}
