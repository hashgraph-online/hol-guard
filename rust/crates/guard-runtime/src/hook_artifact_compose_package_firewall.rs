//! What a resolved package-firewall entitlement permits on this machine.
//!
//! The entitlement itself says only whether Cloud access is proven and, when
//! it is not, why. Turning that into per-action availability, the offered
//! actions, the block copy and a single operation's verdict is composition,
//! and it is the same composition for the control plane, the CLI and the
//! proxy. Local protection that is already installed stays repairable and
//! removable whichever way the entitlement failed: that recovers a machine
//! whose Cloud access lapsed without authorizing a new install, test, audit
//! or policy sync.

use guard_contracts::PackageFirewallAccessQueryV1;
use serde_json::{json, Value};

const CONNECT_REQUIRED: &str = "guard_cloud_connect_required";
const RECONNECT_REQUIRED: &str = "guard_cloud_reconnect_required";
const PAID_REQUIRED: &str = "paid_guard_cloud_required";
/// The entitlement a caller reports when the runtime could not resolve one.
/// It is not an unpaid account and not a connect that has to happen, so its
/// block says the runtime could not answer rather than asking for money.
const RUNTIME_UNAVAILABLE: &str = "guard_runtime_unavailable";

/// Operations that say what access there is rather than using it.
const ALWAYS_OFFERED: [&str; 3] = ["status", "connect", "open-shell"];

fn allowed(entitlement: &Value) -> bool {
    entitlement
        .get("allowed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn reason(entitlement: &Value) -> String {
    entitlement
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase()
}

/// The state every Cloud-backed action is in when the entitlement is not
/// proven. An unrecognized reason is read as the paid requirement, which is
/// the narrowest thing an unproven entitlement can mean.
fn blocked_state(entitlement: &Value) -> &'static str {
    if allowed(entitlement) {
        return "available";
    }
    match reason(entitlement).as_str() {
        CONNECT_REQUIRED => "connect_required",
        RECONNECT_REQUIRED => "reconnect_required",
        _ => "paid_required",
    }
}

fn action_states(entitlement: &Value, has_installed_managers: bool) -> Value {
    let blocked = blocked_state(entitlement);
    let local_recovery = if has_installed_managers {
        "available"
    } else {
        "disabled"
    };
    let repair = if allowed(entitlement) || has_installed_managers {
        "available"
    } else {
        blocked
    };
    json!({
        "audit": blocked,
        "install": blocked,
        "remove": local_recovery,
        "repair": repair,
        "sync": blocked,
        "test": blocked,
    })
}

fn available_actions(entitlement: &Value, has_installed_managers: bool) -> Value {
    let mut actions = vec!["status"];
    let reason = reason(entitlement);
    if reason == CONNECT_REQUIRED || reason == RECONNECT_REQUIRED {
        actions.push("connect");
    }
    if has_installed_managers {
        actions.push("repair");
        actions.push("remove");
    }
    actions.push("education");
    actions.push("cli_fallback");
    json!(actions)
}

/// Why a blocked request was blocked, as the status, code and copy the
/// caller answers with.
fn block(entitlement: &Value) -> Value {
    match reason(entitlement).as_str() {
        RUNTIME_UNAVAILABLE => json!({
            "code": RUNTIME_UNAVAILABLE,
            "message": "The HOL Guard runtime could not report package firewall access on this machine.",
            "status": 503,
        }),
        CONNECT_REQUIRED => json!({
            "code": CONNECT_REQUIRED,
            "message": "Connect HOL Guard Cloud on this machine before running package firewall actions.",
            "status": 403,
        }),
        RECONNECT_REQUIRED => json!({
            "code": RECONNECT_REQUIRED,
            "message": "Reconnect HOL Guard Cloud to refresh package firewall access.",
            "status": 403,
        }),
        _ => json!({
            "code": PAID_REQUIRED,
            "message": "HOL Guard Cloud paid access is required to run package firewall actions.",
            "status": 402,
        }),
    }
}

fn operation_allowed(entitlement: &Value, operation: &str, has_installed_managers: bool) -> bool {
    let operation = operation.trim().to_lowercase();
    if ALWAYS_OFFERED.contains(&operation.as_str()) {
        return true;
    }
    if operation == "repair" {
        return allowed(entitlement) || has_installed_managers;
    }
    if operation == "remove" {
        return has_installed_managers;
    }
    // A reconnect is a lapsed proof rather than a missing one, so an
    // entitlement that still reports `allowed` while asking for a reconnect
    // does not carry a Cloud-backed operation.
    if reason(entitlement) == RECONNECT_REQUIRED {
        return false;
    }
    allowed(entitlement)
}

pub(crate) fn package_firewall_access(
    query: &PackageFirewallAccessQueryV1,
) -> Result<Value, String> {
    if !query.entitlement.is_object() {
        return Err("entitlement must be an object".to_owned());
    }
    let installed = query.has_installed_managers;
    Ok(json!({
        "action_states": action_states(&query.entitlement, installed),
        "available_actions": available_actions(&query.entitlement, installed),
        "block": block(&query.entitlement),
        "operation_allowed": query
            .operation
            .as_ref()
            .map(|operation| operation_allowed(&query.entitlement, operation, installed)),
    }))
}
