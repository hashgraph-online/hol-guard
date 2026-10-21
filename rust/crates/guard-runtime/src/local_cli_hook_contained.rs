//! How a local CLI grant refines the hook action.
//!
//! `warn` and the generic review due to non-recognition follow the grant:
//! allowed to `allow`, blocked to `block`. Any other review or
//! `require-reapproval` carries a risk signal of its own, so a block still
//! applies but an allow leaves it standing. A command the workspace
//! sandbox bounds (`sandbox-required`), or a review left only because the
//! program lives outside the sandbox's executable roots, never leaves the
//! sandbox on a grant: an allowed CLI widens the sandbox by the grant's
//! capabilities (`allow-contained-with-grant`), a blocked one is blocked, and
//! one this device never decided keeps its action, the outside-roots review
//! naming the connector to set up. A grant answer that cannot be trusted
//! keeps the action, so nothing here can turn a sandbox requirement into
//! `allow`.

use guard_contracts::LocalCliHookRequestV1;
use serde_json::{json, Value};

use crate::local_cli_hook_op::Launch;

/// The internal action that runs a command in `workspace-contained-grant-v1`.
pub(crate) const ALLOW_CONTAINED_WITH_GRANT: &str = "allow-contained-with-grant";
/// The review `workspace_contained` leaves when the sandbox cannot run the
/// program; `guard_command::pretool::workspace_contained::OUTSIDE_ROOTS_REASON`.
pub(crate) const OUTSIDE_ROOTS_REASON: &str =
    "native_workspace_containment_executable_outside_roots";
/// The reason code a sandbox-bound command the grant widens is routed to;
/// `guard_command::pretool::workspace_contained::WORKSPACE_REASON`.
pub(crate) const WORKSPACE_REASON: &str = "native_workspace_containment_required";
/// The sentence that names the grant as the only widening of the sandbox.
pub(crate) const GRANT_REASON: &str = concat!(
    "HOL Guard runs this command in a protected workspace sandbox, widened only by the ",
    "local CLI access you approved on this device."
);

/// Every capability a grant may turn on, in their canonical order.
pub(crate) const GRANT_CAPABILITIES: [&str; 3] =
    ["loopback-network", "state-dir-read", "state-dir-write"];
const REFINABLE_ACTIONS: [&str; 4] = ["allow", "review", "require-reapproval", "warn"];

/// The grant step's answer: its state, the CLI it read, and the capability
/// field of the decision. `Err` is an answer that cannot be trusted.
pub(crate) type Answer = Result<(Option<&'static str>, Option<Launch>, Value), ()>;

/// A refined action, the connector a review waits on, and the grant a
/// contained run is widened by.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Refined {
    pub(crate) action: String,
    pub(crate) connector: Option<Value>,
    pub(crate) contained_grant: Option<Value>,
}

impl Refined {
    fn keep(request: &LocalCliHookRequestV1) -> Self {
        Self {
            action: request.current_action.clone(),
            ..Self::default()
        }
    }
}

/// Whether the action stays inside the workspace sandbox whatever the grant.
pub(crate) fn sandbox_bound(request: &LocalCliHookRequestV1) -> bool {
    match request.current_action.as_str() {
        "sandbox-required" => true,
        "review" => request.current_reason_code.as_deref() == Some(OUTSIDE_ROOTS_REASON),
        _ => false,
    }
}

/// Whether an allowed grant lifts this unbounded action to `allow`: `allow`
/// and `warn` already run, and a review must be due to non-recognition alone.
fn lifts(request: &LocalCliHookRequestV1) -> bool {
    match request.current_action.as_str() {
        "allow" | "warn" => true,
        _ => crate::connector_setup::grant_lifts(request.current_reason_code.as_deref()),
    }
}

/// Whether a grant may refine the action at all.
pub(crate) fn refinable(request: &LocalCliHookRequestV1) -> bool {
    request.grant_allowed
        && (sandbox_bound(request) || REFINABLE_ACTIONS.contains(&request.current_action.as_str()))
}

/// The action a trusted or untrusted grant answer leaves; `unverified` is the
/// action an untrusted answer holds a generic action at.
pub(crate) fn refine(
    request: &LocalCliHookRequestV1,
    answer: Answer,
    unverified: impl FnOnce() -> String,
) -> Refined {
    let current = request.current_action.as_str();
    let bound = sandbox_bound(request);
    match answer {
        Ok((Some("blocked"), _, _)) => Refined {
            action: "block".to_owned(),
            ..Refined::default()
        },
        Ok((Some("allowed"), _, _)) if !bound && lifts(request) => Refined {
            action: "allow".to_owned(),
            ..Refined::default()
        },
        // A review with its own risk signal outlives the grant.
        Ok((Some("allowed"), _, _)) if !bound => Refined::keep(request),
        Ok((Some("allowed"), Some(launch), capabilities)) => {
            match grant_capabilities(&capabilities) {
                Ok(capabilities) => Refined {
                    action: ALLOW_CONTAINED_WITH_GRANT.to_owned(),
                    connector: None,
                    contained_grant: Some(json!({
                        "cli_id": launch.cli_id,
                        "identity_hash": launch.identity_hash,
                        "name": launch.name,
                        "capabilities": capabilities,
                    })),
                },
                Err(()) => Refined::keep(request),
            }
        }
        // Allowed and blocked answers took the arms above.
        Ok((_, Some(launch), _)) if current == "review" => Refined {
            connector: crate::connector_setup::for_launch(request, &launch),
            ..Refined::keep(request)
        },
        Err(()) if !bound => Refined {
            action: unverified(),
            ..Refined::default()
        },
        _ => Refined::keep(request),
    }
}

/// The review fields a granted outside-roots command is routed to.
///
/// The caller owns no part of this verdict: it narrows the review it holds to
/// the surfaces this operation reads, and copies the answer back. A caller
/// that cannot reach the resident keeps its review.
pub(crate) fn contained_route() -> Value {
    json!({
        "decision": "deny",
        "minimum_action": "sandbox-required",
        "policy_action": "sandbox-required",
        "reason_code": WORKSPACE_REASON,
        "reason": GRANT_REASON,
    })
}

/// The decision's capability names: absent is none; anything but a sorted,
/// distinct list of known names is untrusted.
pub(crate) fn grant_capabilities(value: &Value) -> Result<Vec<String>, ()> {
    let items = match value {
        Value::Null => return Ok(Vec::new()),
        Value::Array(items) => items,
        _ => return Err(()),
    };
    let names: Vec<String> = items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|name| GRANT_CAPABILITIES.contains(name))
                .map(str::to_owned)
        })
        .collect::<Option<_>>()
        .ok_or(())?;
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(());
    }
    Ok(names)
}

/// A grant the resident could not verify: hold an otherwise allowed command
/// for review while a block rule might apply.
pub(crate) fn unverified_action(request: &LocalCliHookRequestV1) -> &str {
    let current = request.current_action.as_str();
    if !matches!(current, "allow" | "warn") {
        return current;
    }
    if has_block_rules(request) {
        "review"
    } else {
        current
    }
}

/// `has_local_cli_block_rules`; an unreadable store counts as having one.
pub(crate) fn has_block_rules(request: &LocalCliHookRequestV1) -> bool {
    let Ok(path) =
        crate::local_store_read::require_store_path(&request.store_path, &request.guard_home)
    else {
        return true;
    };
    let connection = match crate::local_store_read::open_read_only(&path) {
        Ok(Some(connection)) => connection,
        Ok(None) => return false,
        Err(_) => return true,
    };
    for (table, state) in [
        ("local_cli_grant", "blocked"),
        ("local_cli_command_grant", "block"),
    ] {
        match crate::local_store_read::table_exists(&connection, table) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => return true,
        }
        let found = connection.query_row(
            &format!("select exists(select 1 from {table} where state = ?1)"),
            [state],
            |row| row.get::<_, bool>(0),
        );
        if found.unwrap_or(true) {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "local_cli_hook_contained_tests.rs"]
mod tests;
