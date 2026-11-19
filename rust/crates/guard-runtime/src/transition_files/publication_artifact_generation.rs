//! The artifact generation a repair or publication inverse proves itself
//! under, ported from `verify_and_commit_codex_hook_repair` and
//! `verify_and_retire_codex_publication_inverse`.
//!
//! The generation names the plan's subject, so a proof observed for one plan
//! can never stand for another. A plan can only be verified once its native
//! runtime and verification workspace are bound, and an inverse only once
//! every one of its three files has been restored.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::publication::Call;
use super::{Fault, Step};

/// `publication_artifact_generation`: the generation string for `subject`.
///
/// - `kind` is `repair` or `inverse`.
/// - `bound` says the plan carries its native runtime and verification
///   workspace; without it a repair is `authority_repair_native_binding_missing`
///   and an inverse `publication_inverse_not_restored`.
/// - An inverse also sends `restored`, the indexes it has restored, which must
///   be exactly `{0, 1, 2}` or it is `publication_inverse_not_restored`.
pub(super) fn generation_op(call: &mut Call<'_>) -> Step<Value> {
    let bound = call.args.get("bound").and_then(Value::as_bool) == Some(true);
    let prefix = match call.text("kind")? {
        "repair" => {
            if !bound {
                return Err(Fault::Transition("authority_repair_native_binding_missing"));
            }
            "codex-authority-repair-"
        }
        "inverse" => {
            let restored: Option<BTreeSet<i64>> = call
                .args
                .get("restored")
                .and_then(Value::as_array)
                .and_then(|items| items.iter().map(Value::as_i64).collect());
            if !bound || restored != Some(BTreeSet::from([0, 1, 2])) {
                return Err(Fault::Transition("publication_inverse_not_restored"));
            }
            "codex-publication-inverse-"
        }
        _ => return Err(Fault::Transition("files_invalid")),
    };
    let (_, token) = call
        .text("subject")?
        .rsplit_once(':')
        .ok_or(Fault::Transition("files_invalid"))?;
    Ok(json!(format!("{prefix}{token}")))
}
