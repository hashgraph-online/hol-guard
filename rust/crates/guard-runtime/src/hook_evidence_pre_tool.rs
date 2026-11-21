//! Command activity derived from a finished PreToolUse reply.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{queued_payload, signals, with_writer, WriterError, APPROVAL_REUSE_NOT_APPLICABLE};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreToolActivity {
    harness: String,
    payload: Map<String, Value>,
    response: Map<String, Value>,
    receipt_id: Option<String>,
    settled: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome<'a> {
    succeeded: bool,
    policy_action: Option<&'a str>,
    prompted: bool,
    approval_reuse_status: &'a str,
}

impl PreToolActivity {
    fn outcome(&self) -> Result<Outcome<'_>, WriterError> {
        let invalid = || {
            WriterError(
                "invalid_request",
                "invalid pre-tool evidence fields".to_owned(),
            )
        };
        let policy_action = match self.response.get("policy_action") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_str().ok_or_else(invalid)?),
        };
        let approval_reuse_status = if self.settled {
            match self.response.get("approval_reuse_status") {
                Some(value) => value.as_str().ok_or_else(invalid)?,
                None => APPROVAL_REUSE_NOT_APPLICABLE,
            }
        } else {
            APPROVAL_REUSE_NOT_APPLICABLE
        };
        Ok(Outcome {
            succeeded: self.settled || policy_action != Some("block"),
            policy_action,
            prompted: self.settled && self.response.get("prompted") == Some(&Value::Bool(true)),
            approval_reuse_status,
        })
    }

    pub(super) fn submit(&self, guard_home: &Path, source: &str) -> Result<Value, WriterError> {
        let outcome = self.outcome()?;
        let (queued, reported) = with_writer(guard_home, source, |resident| {
            let queued = resident.writer.submit_command_activity(
                &self.harness,
                "PreToolUse",
                &self.payload,
                outcome.succeeded,
                outcome.policy_action,
                if self.settled {
                    self.receipt_id.as_deref()
                } else {
                    None
                },
                outcome.prompted,
                outcome.approval_reuse_status,
            );
            (queued, signals(resident))
        })
        .map_err(|error| WriterError("writer_unavailable", error.to_string()))?;
        Ok(queued_payload(queued, reported))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unavailable_pre_tool_ignores_approval_metadata_and_records_a_block_as_failed() {
        let mut activity: PreToolActivity = serde_json::from_value(json!({
            "harness": "codex",
            "payload": {},
            "response": {"policy_action": "block", "prompted": true, "approval_reuse_status": "accepted"},
            "receipt_id": null,
            "settled": false,
        }))
        .unwrap();
        assert_eq!(
            activity.outcome().ok(),
            Some(Outcome {
                succeeded: false,
                policy_action: Some("block"),
                prompted: false,
                approval_reuse_status: APPROVAL_REUSE_NOT_APPLICABLE,
            }),
        );
        activity.settled = true;
        assert_eq!(
            activity.outcome().ok(),
            Some(Outcome {
                succeeded: true,
                policy_action: Some("block"),
                prompted: true,
                approval_reuse_status: "accepted",
            }),
        );
    }
}
