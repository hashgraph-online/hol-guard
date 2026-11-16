//! `publication_merge_dependency`: two pins of one shared immutable artifact
//! become one, ported from `merge_transition_dependency`.
//!
//! Frozen roles share one executable. Their role names stay authenticated in
//! the hook manifest; a transition needs one filesystem dependency with the
//! strongest exact invocation contract, not duplicate targets. Mutable
//! writes and authority-only dependencies never merge.

use serde_json::{json, Map, Value};

use super::publication::Call;
use super::{Fault, Step};

const CONFLICT: Fault = Fault::Transition("adapter_preparation_generation_conflict");

pub(super) fn merge(call: &mut Call<'_>) -> Step<Value> {
    let object = |key: &str| {
        call.args
            .get(key)
            .and_then(Value::as_object)
            .ok_or(Fault::Transition("files_invalid"))
    };
    let (previous, change) = (object("previous")?, object("change")?);
    if previous == change {
        return Ok(json!({ "same": true }));
    }
    let present =
        |item: &Map<String, Value>, key: &str| item.get(key).is_some_and(|v| !v.is_null());
    for item in [previous, change] {
        if !present(item, "expected_digest")
            || !item.get("artifact_identity").is_some_and(Value::is_object)
            || present(item, "before")
            || present(item, "after")
        {
            return Err(CONFLICT);
        }
    }
    let normalized = |item: &Map<String, Value>| {
        let mut item = item.clone();
        if let Some(Value::Object(identity)) = item.get_mut("artifact_identity") {
            identity.insert("role".to_owned(), json!("artifact"));
        }
        item.remove("invocation_identity");
        item
    };
    let (first, second) = (normalized(previous), normalized(change));
    let invocation = |item: &Map<String, Value>| {
        item.get("invocation_identity")
            .filter(|value| !value.is_null())
            .cloned()
    };
    let (before, after) = (invocation(previous), invocation(change));
    if first != second || matches!((&before, &after), (Some(a), Some(b)) if a != b) {
        return Err(CONFLICT);
    }
    // `previous.invocation_identity or change.invocation_identity`: an empty
    // contract is no contract.
    let chosen = before
        .filter(|value| value.as_object().is_none_or(|fields| !fields.is_empty()))
        .or(after)
        .unwrap_or(Value::Null);
    Ok(json!({
        "artifact_identity": first.get("artifact_identity").cloned().unwrap_or(Value::Null),
        "invocation_identity": chosen,
    }))
}
