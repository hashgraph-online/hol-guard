//! PRD R16 for version 2 requests: an action no admitted pack describes.
//!
//! The host marks such a call with `unclassified` and sends the pack's
//! Unclassified section in `policy.unclassified`. The call's facts must claim
//! only a class (every other fact unknown), which is what the classifier
//! produces; anything richer came from a pack and is refused. Without the
//! pack's section the call keeps the strict unknown-fact branch.

use crate::cloud_action_canonical::domain_digest;
use crate::cloud_pack_facts::class_only_facts;
use crate::cloud_policy_pack::{validate_unclassified, Unclassified};
use crate::effect_decision::GuardAction;
use guard_contracts::ActionFactsV2;
use serde::Deserialize;
use serde_json::Value;

/// The call-level marker.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnclassifiedCall {
    /// The classifier read the tool's name or schema as destructive.
    pub destructive: bool,
}

/// Refuses a marker on facts a pack produced, and a lenient section.
pub(crate) fn validate(
    call: Option<&UnclassifiedCall>,
    pack: Option<&Unclassified>,
    facts: &ActionFactsV2,
) -> Result<(), &'static str> {
    if pack.is_some_and(|section| validate_unclassified(section).is_err()) {
        return Err("invalid_request");
    }
    if call.is_some() && *facts != class_only_facts(facts.class) {
        return Err("unclassified_facts_invalid");
    }
    Ok(())
}

/// The R16 action for this call, when both the marker and the section are present.
pub(crate) fn floor(
    call: Option<&UnclassifiedCall>,
    pack: Option<&Unclassified>,
) -> Option<GuardAction> {
    let (call, pack) = (call?, pack?);
    Some(if call.destructive {
        pack.destructive_name_action
    } else {
        pack.action
    })
}

/// The fact-rule digest. The R16 inputs join it only when sent, so a request
/// without them keeps the digest it always had.
pub(crate) fn fact_rules_digest(
    parsed: &Value,
    bytes: impl Fn(&Value) -> Result<Vec<u8>, &'static str>,
) -> Result<String, &'static str> {
    let rules = bytes(&parsed["policy"]["fact_rules"])?;
    let call = parsed.get("unclassified").filter(|value| !value.is_null());
    let pack = parsed["policy"]
        .get("unclassified")
        .filter(|value| !value.is_null());
    if call.is_none() && pack.is_none() {
        return Ok(domain_digest(
            crate::cloud_action_v2::FACT_RULES_DOMAIN,
            &[&rules],
        ));
    }
    let call = bytes(call.unwrap_or(&Value::Null))?;
    let pack = bytes(pack.unwrap_or(&Value::Null))?;
    Ok(domain_digest(
        crate::cloud_action_v2::FACT_RULES_DOMAIN,
        &[&rules, &call, &pack],
    ))
}
