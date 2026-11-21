//! `policy_shadow_verdict` runner-authority kind: whether a v2 policy-bundle
//! candidate may replace the policy a device already enforces. Ported from the
//! verdict half of `policy_bundle_candidate_decisions`.
//!
//! `{"legacy", "canonical", "evaluating", "canonical_enforcement"}` answers
//! `{"reason_codes", "rejection"}`. `legacy` and `canonical` are the shadow
//! rows `policy_shadow_mismatch` compares. A candidate rolled out to watch its
//! rules compiles to no rows on purpose, so an evaluating candidate reports no
//! drift. `rejection` is `"canonical_shadow_mismatch"` only on a rollout
//! device whose rows disagree for a reason other than a missing shadow;
//! otherwise it is `null` and the candidate is applied. Python still writes the
//! mismatch event and refuses the candidate itself when this kind cannot answer.

use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::runner_authority_signature::policy_shadow_mismatch;

const FIELDS: [&str; 4] = ["legacy", "canonical", "evaluating", "canonical_enforcement"];
const LEGACY_UNAVAILABLE: &str = "legacy_unavailable";
const SHADOW_MISMATCH: &str = "canonical_shadow_mismatch";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(ERR_INVALID);
    }
    let flag = |key: &str| fields.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID);
    let (evaluating, enforcing) = (flag("evaluating")?, flag("canonical_enforcement")?);
    let compared = policy_shadow_mismatch(args)?;
    let reasons: Vec<Value> = if evaluating {
        Vec::new()
    } else {
        compared
            .get("reason_codes")
            .and_then(Value::as_array)
            .cloned()
            .ok_or(ERR_INVALID)?
    };
    let blocking = reasons
        .iter()
        .any(|reason| reason.as_str() != Some(LEGACY_UNAVAILABLE));
    let rejection = (enforcing && blocking).then_some(SHADOW_MISMATCH);
    Ok(json!({"reason_codes": reasons, "rejection": rejection}))
}

#[cfg(test)]
#[path = "policy_shadow_verdict_tests.rs"]
mod tests;
