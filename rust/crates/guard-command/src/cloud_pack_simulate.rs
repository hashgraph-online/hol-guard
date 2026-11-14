//! `simulate`: what a policy pack would decide for calls Guard already made.
//!
//! The input is the facts Guard stored when each call was decided, never the
//! call's arguments or payload. Each call is decided exactly as
//! [`PolicyPack::decide`] decides a fixture: the effect is the one the call
//! stored, else the one the shipped pack declares for the action; a call
//! without a stored session flow reads as a clean session, and a call without
//! stored usage reads every window at zero. A call whose effect, connection or
//! resource a rule covering that call would need but cannot be known refuses the
//! request (a call that named no resource says so with `resourceId: null`), so a
//! rule is never reported as matching nothing because a label was missing. The
//! result says, per call, the decision and which rules matched, so a host can
//! show "would have reviewed 14 of 500" before a rule is enforced.

use crate::cloud_action_binding::{valid_label, ActionEffect};
use crate::cloud_action_v2::effect_rank;
use crate::cloud_pack_explain::shipped_pack_for;
use crate::cloud_policy_pack::{FactCall, PolicyPack};
use guard_contracts::{ActionFactsV2, SessionFlowV2};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The most calls one request may carry.
pub const MAX_SIMULATED_CALLS: usize = 1000;
const MAX_WINDOWS: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StoredCall {
    provider: String,
    action_id: String,
    facts: Value,
    #[serde(default)]
    effect: Option<ActionEffect>,
    #[serde(default)]
    connection_id: Option<String>,
    /// Absent when the resource is unknown, `null` when the call named none.
    #[serde(default, deserialize_with = "present")]
    resource_id: Option<Option<String>>,
    #[serde(default)]
    session_flow: Option<SessionFlowV2>,
    #[serde(default)]
    usage_windows: Option<BTreeMap<String, u64>>,
    /// The call was decided as Unclassified (R16); its tool name is read again
    /// to tell whether it looks destructive.
    #[serde(default)]
    unclassified: bool,
}

/// Keeps an explicit `null` apart from an absent field.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

/// Decide every stored call against `pack`. A malformed call refuses the
/// whole request with a pointer to it, so a host never shows counts that
/// silently skipped calls.
pub fn simulate(pack: &PolicyPack, calls: Value) -> Result<Value, (&'static str, String)> {
    let Value::Array(calls) = calls else {
        return Err(("request_invalid", "/calls".into()));
    };
    if calls.len() > MAX_SIMULATED_CALLS {
        return Err(("limit", "/calls".into()));
    }
    let mut results = Vec::with_capacity(calls.len());
    for (index, call) in calls.into_iter().enumerate() {
        let pointer = format!("/calls/{index}");
        let call: StoredCall =
            serde_json::from_value(call).map_err(|_| ("request_invalid", pointer.clone()))?;
        if !valid_label(&call.provider) || !valid_label(&call.action_id) {
            return Err(("request_invalid", pointer));
        }
        let resource = call.resource_id.as_ref().map(Option::as_deref);
        let labels = [call.connection_id.as_deref(), resource.flatten()];
        if labels
            .into_iter()
            .flatten()
            .any(|label| !valid_label(label))
        {
            return Err(("request_invalid", pointer));
        }
        let (scoped_connection, scoped_resource) =
            pack.missing_scopes(&call.action_id, call.connection_id.as_deref(), resource);
        if scoped_connection {
            return Err(("scope_unknown", format!("{pointer}/connectionId")));
        }
        if scoped_resource {
            return Err(("scope_unknown", format!("{pointer}/resourceId")));
        }
        // A stored effect can raise the declared one, never lower it.
        let declared = shipped_pack_for(&call.action_id)
            .and_then(|shipped| shipped.action(&call.action_id))
            .map(|action| action.safety.effect);
        let effect = [call.effect, declared]
            .into_iter()
            .flatten()
            .max_by_key(|effect| effect_rank(*effect))
            .ok_or(("effect_unknown", format!("{pointer}/effect")))?;
        if call.usage_windows.as_ref().is_some_and(|windows| {
            windows.len() > MAX_WINDOWS || !windows.keys().all(|id| valid_label(id))
        }) {
            return Err(("request_invalid", format!("{pointer}/usageWindows")));
        }
        let facts = serde_json::to_vec(&call.facts)
            .ok()
            .and_then(|bytes| ActionFactsV2::from_bounded_json(&bytes).ok())
            .ok_or(("facts_invalid", format!("{pointer}/facts")))?;
        if call.unclassified && facts != crate::cloud_pack_facts::class_only_facts(facts.class) {
            return Err(("facts_invalid", format!("{pointer}/facts")));
        }
        let decision = pack.decide_with_rules(&FactCall {
            provider: &call.provider,
            action_id: &call.action_id,
            effect,
            connection_id: call.connection_id.as_deref().unwrap_or("fixture"),
            resource_id: resource.flatten(),
            facts: &facts,
            session: call.session_flow.as_ref(),
            windows: call.usage_windows.as_ref(),
            unclassified: call.unclassified.then(|| {
                let name = call.action_id.rsplit('.').next().unwrap_or(&call.action_id);
                crate::cloud_action_classifier::classify(name, None).destructive
            }),
        });
        results.push(json!({
            "action": decision.action,
            "matchedRuleIds": decision.matched,
            "unknownRuleIds": decision.unknown,
        }));
    }
    Ok(json!({ "results": results }))
}
