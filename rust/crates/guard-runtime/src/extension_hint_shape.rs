//! `extension_hint_shape` runner-authority kind: shape checks for the
//! advisory hints a review is stored with.
//!
//! `{"hint": value}` carries one stored hint as the queue holds it. The answer
//! is `{"allow", "coverage", "connector"}`: the extension allow hint, the
//! extension coverage hint (standalone or carried on an allow hint) and the
//! connector setup hint, each rebuilt from the keys it knows, or null when
//! the value is not that hint. A hint only ever offers a choice, so a value
//! that fails any check is dropped rather than refused.

use serde_json::{json, Value};

use crate::extension_coverage_hint::validated as validated_coverage;
use crate::guard_store_approval_queue_item::validated_hint as validated_allow;
use crate::hook_direct::saved_decision::review_queue::connector::validated_setup_hint;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let hint = args.get("hint").ok_or(ERR_INVALID)?;
    Ok(json!({
        "allow": validated_allow(hint).map(Value::Object),
        "coverage": validated_coverage(hint),
        "connector": validated_setup_hint(hint),
    }))
}

#[cfg(test)]
#[path = "extension_hint_shape_tests.rs"]
mod tests;
