//! Trusted-local-tool grant read.
//!
//! The resident side of `matching_local_tool_grant` (`trusted_local_tools.py`).
//! A grant is an ordinary policy row filed under the grant selector of one
//! target, so finding one means deriving the selector of every target and
//! probing each of them non-consuming. The selector is derived here rather
//! than shipped because the digest in it is what the comparison turns on; a
//! caller that computed it differently would miss a grant it holds.
//!
//! Only an `allow` row written by the grant source answers. A row another
//! source happens to leave under the same id is not a grant, and an action the
//! hook did not recompute as reviewable is not one a grant may lift.

use guard_contracts::{LocalToolGrantLookupV1, PolicyDecisionLookupRequestV1};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::policy_decision_lookup_op::{evaluate_non_consuming, open_lookup_connection};

/// `LOCAL_TOOL_GRANT_TARGETS`, in the order Python probes them: the capability
/// grant is the narrow one, so it answers before the whole-version grant.
const TARGETS: [&str; 2] = ["capability", "version"];
/// `_SELECTOR_PREFIX`.
const SELECTOR_PREFIX: &str = "local-tool-grant:v1";
/// `_POLICY_SOURCE` — the only source whose row counts as a grant.
const POLICY_SOURCE: &str = "trusted-local-tool";
/// The recomputed actions a saved grant may lift.
const REVIEWABLE: [&str; 2] = ["review", "require-reapproval"];

pub(crate) fn evaluate(
    request: &PolicyDecisionLookupRequestV1,
    grant: &LocalToolGrantLookupV1,
) -> Result<Value, String> {
    if !REVIEWABLE.contains(&grant.current_action.as_str()) {
        // No store read happens, so there is no trust or integrity evidence to
        // report; the result still has to be the shape every caller decodes.
        return Ok(no_grant());
    }
    let connection = open_lookup_connection(&request.store_path)?;
    let mut last = Value::Null;
    for target in TARGETS {
        // The grant is filed by selector alone: the hash, workspace and
        // publisher of the command under review name nothing it was saved
        // against, so the probe carries none of them.
        let mut probe = request.clone();
        probe.probe_groups = None;
        probe.artifact_id = Some(selector(grant, target));
        probe.artifact_hash = None;
        probe.workspace = None;
        probe.publisher = None;
        probe.runtime_exact_match_context = None;
        let lookup = evaluate_non_consuming(&probe, &connection)?;
        if is_grant(&lookup) {
            return Ok(lookup);
        }
        last = lookup;
    }
    // No grant: keep the last probe's trust and integrity evidence, and say
    // plainly that it carries no decision this caller may use.
    let Some(object) = last.as_object_mut() else {
        return Ok(no_grant());
    };
    object.insert("decision".to_owned(), Value::Null);
    Ok(last)
}

/// The result of a probe that answered nothing, in the shape every caller
/// decodes. There is no trust or integrity evidence to report with it.
fn no_grant() -> Value {
    json!({
        "decision": Value::Null,
        "ignored_local_integrity": Value::Null,
        "trust_status": json!({}),
        "authority_revision": -1,
    })
}

/// `local_tool_grant_selector` — the artifact id a grant for `target` is filed
/// under. The version target is capability-independent, which Python spells as
/// the digest of `*`.
fn selector(grant: &LocalToolGrantLookupV1, target: &str) -> String {
    let capability = if target == "capability" {
        grant.capability.as_str()
    } else {
        "*"
    };
    let digest = hex::encode(Sha256::digest(capability.as_bytes()));
    format!(
        "{SELECTOR_PREFIX}:{}:{target}:{digest}",
        grant.tool_identity_hash
    )
}

fn is_grant(lookup: &Value) -> bool {
    let decision = &lookup["decision"];
    decision["action"].as_str() == Some("allow")
        && decision["source"].as_str() == Some(POLICY_SOURCE)
}

#[cfg(test)]
#[path = "policy_lookup_local_tool_grant_tests.rs"]
mod tests;
