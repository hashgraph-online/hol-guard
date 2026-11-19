//! The Codex `detect` op: `CodexHarnessAdapter.detect` answered natively.
//!
//! It reads the authenticated baseline, detects over the live sources, merges
//! the workspace and skill inventories, and names whether Codex is installed
//! or its command is on the path. A baseline that does not verify answers
//! `{"untrusted": {reason, message}}` for the caller to raise as the
//! integrity error it is. The facts only the asking process holds arrive in
//! `facts.codex`, beside the `transition` budget the baseline read takes.

use serde_json::{json, Map, Value};

use super::codex_detection::{self, Detection};
use super::codex_managed::{baseline, bindings, facts, spec_of};
use crate::harness_adapter::{common, Ctx, Failure, Spec, Step};
use crate::transition_files::OwnedFailure;

pub(super) fn detect(spec: &Spec, ctx: &Ctx, request: &Map<String, Value>) -> Step<Value> {
    let facts = facts(ctx, request).map_err(|_| Failure::Invalid)?;
    let spec_value = spec_of(ctx, &facts).map_err(|_| Failure::Invalid)?;
    let previous = match baseline(ctx, &facts, &spec_value) {
        Ok(previous) => previous,
        Err(OwnedFailure::Untrusted(untrusted)) => {
            return Ok(json!({ "untrusted": untrusted }));
        }
        Err(OwnedFailure::Integrity(reason, message)) => {
            return Ok(json!({ "untrusted": { "reason": reason, "message": message } }));
        }
        Err(_) => return Err(Failure::Invalid),
    };
    let Detection {
        artifacts,
        found_paths,
        warnings,
        sourced,
    } = codex_detection::detect(ctx, &facts.launch, &bindings(previous.as_ref()), None)?;
    let available = common(spec, "command_available", ctx)?
        .get("available")
        .and_then(Value::as_bool)
        == Some(true);
    Ok(json!({
        "artifacts": artifacts,
        "config_paths": found_paths,
        "warnings": warnings,
        "installed": sourced || available,
        "command_available": available,
        "workspace_aibom": false,
    }))
}
