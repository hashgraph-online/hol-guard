//! The silent inbox row a safe-alternative block adds after its receipt.

use guard_contracts::McpToolCallArtifactV1;
use serde_json::{json, Map, Value};

use super::record::Plain;
use super::{strings, Stamp};
use crate::mcp_relay_decide::ask_row::{projection, silent_review_args, Queue};

/// `_record_unprompted_review`: the `queue_blocked_approvals` arguments of a
/// safe-alternative block's inbox row, written with no prompt shown and the
/// approval center origin the daemon listens on, which the relay bound. A
/// row that cannot be composed is left out, and the receipt still written.
pub(super) fn silent_review(
    plain: &Plain<'_>,
    projected: &Value,
    evidence: &[Value],
    stamp: &Stamp,
) -> Option<Map<String, Value>> {
    let (redaction_level, center) = plain.silent_review()?;
    let projection = projection(projected)?;
    let artifact: McpToolCallArtifactV1 =
        serde_json::from_value(Value::Object(plain.artifact.clone())).ok()?;
    // `str(Path.cwd())`, the writing process's, or null when it is gone.
    let cwd = std::env::current_dir().map_or(Value::Null, |cwd| json!(cwd.to_string_lossy()));
    let queue = Queue {
        harness: plain.harness,
        cwd,
        prompt_shown: false,
        center,
        now: &stamp.now,
        redaction_level,
    };
    let signals: Vec<String> = strings(&plain.decision["signals"])
        .into_iter()
        .map(str::to_owned)
        .collect();
    Some(silent_review_args(
        &queue,
        &artifact,
        plain.artifact_hash,
        &signals,
        &projection,
        plain.policy_action,
        evidence.to_vec(),
    ))
}
