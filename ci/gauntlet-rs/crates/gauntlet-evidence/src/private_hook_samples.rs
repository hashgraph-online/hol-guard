//! Data-only Python parity for private-cell Native hook process samples.
//! The kernel provenance of supplied samples remains a separate requirement.

use crate::{verify_product_kernel_identity, EvidenceError, Result};
use serde_json::{json, Value};

const USER_NS: &str = "hook sample lacks a kernel user namespace";
const CAPS: &str = "hook sample capability mask invalid";
const DESCENDANT: &str = "hook descendant escaped host privilege/namespace boundary";
const PRIMARY: &str = "native hook CLI changed user namespace or gained capabilities";
const ABSENT: &str = "native hook CLI was not independently sampled";

fn user_namespace(value: &str) -> bool {
    let Some(numbers) = value
        .strip_prefix("user:[")
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    !numbers.is_empty() && numbers.bytes().all(|byte| byte.is_ascii_digit())
}

fn capability_mask(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nested_child(
    identity: &Value,
    controller: &Value,
    agent: Option<&Value>,
    product_user_namespace: &str,
    sample_user_namespace: &str,
    caps: &str,
) -> bool {
    if sample_user_namespace == product_user_namespace
        || identity.get("effective_uid").and_then(Value::as_u64) != Some(10004)
        || identity.get("effective_gid").and_then(Value::as_u64) != Some(10004)
        || identity.get("uid_slots") != Some(&json!([10004, 10004, 10004, 10004]))
        || identity.get("gid_slots") != Some(&json!([10004, 10004, 10004, 10004]))
        || !matches!(identity.get("supplementary_groups"), Some(value) if value == &json!([]) || value == &json!([10004]))
        || identity.get("no_new_privileges").and_then(Value::as_u64) != Some(1)
        || identity.get("boot_id") != controller.get("boot_id")
        || !identity
            .get("start_time")
            .and_then(Value::as_str)
            .is_some_and(|value| {
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
            })
    {
        return false;
    }
    let expected_caps = json!({
        "CapEff": caps, "CapPrm": caps,
        "CapBnd": "0000000000000000", "CapInh": "0000000000000000",
        "CapAmb": "0000000000000000",
    });
    if identity.get("capability_sets") != Some(&expected_caps) {
        return false;
    }
    for field in ["mount_namespace", "pid_namespace", "network_namespace"] {
        let actual = identity.get(field).and_then(Value::as_str);
        let controller_ns = controller.get(field).and_then(Value::as_str);
        let agent_ns = agent.and_then(|agent| agent.get(field).and_then(Value::as_str));
        if actual.is_none_or(str::is_empty)
            || controller_ns.is_none()
            || actual == controller_ns
            || (agent.is_some() && (agent_ns.is_none() || actual == agent_ns))
        {
            return false;
        }
    }
    true
}

/// Require a zero-capability primary CLI sample at the outside command hash.
/// Nested sandbox children may carry user-namespace-local capabilities only
/// when they retain the declared privilege and namespace separation floor.
pub fn verify_private_hook_samples(
    samples: &Value,
    controller: &Value,
    agent: Option<&Value>,
    product_user_namespace: &str,
    command_hash: &str,
) -> Result<Value> {
    let rows = samples
        .as_array()
        .filter(|rows| rows.len() <= 4096)
        .ok_or(EvidenceError::Invalid(ABSENT))?;
    let mut primary_count = 0;
    let mut nested_count = 0;
    for row in rows {
        let user_ns = row
            .get("user_namespace")
            .and_then(Value::as_str)
            .filter(|value| user_namespace(value))
            .ok_or(EvidenceError::Invalid(USER_NS))?;
        let identity = row
            .get("identity")
            .ok_or(EvidenceError::Invalid(DESCENDANT))?;
        let caps = identity
            .get("effective_capabilities")
            .and_then(Value::as_str)
            .filter(|value| capability_mask(value))
            .ok_or(EvidenceError::Invalid(CAPS))?;
        let local_caps = u64::from_str_radix(caps, 16).map_err(|_| EvidenceError::Invalid(CAPS))?;
        if local_caps == 0 {
            verify_product_kernel_identity(identity, controller, agent, 10004)?;
        } else {
            if !nested_child(
                identity,
                controller,
                agent,
                product_user_namespace,
                user_ns,
                caps,
            ) {
                return Err(EvidenceError::Invalid(DESCENDANT));
            }
            nested_count += 1;
        }
        if row.get("command_sha256") == Some(&json!(command_hash)) {
            if local_caps != 0 || user_ns != product_user_namespace {
                return Err(EvidenceError::Invalid(PRIMARY));
            }
            primary_count += 1;
        }
    }
    if primary_count == 0 {
        return Err(EvidenceError::Invalid(ABSENT));
    }
    Ok(json!({
        "primary_sample_count": primary_count,
        "nested_sample_count": nested_count,
        "execution_eligible": false,
    }))
}
