//! The two launches of an observation, and what their receipts must agree on.
//!
//! Ported from the launch loop of `_observe_configured_codex_hook`: one
//! command the policy allows and one it denies are sent to the exact
//! authenticated argv. Each launch must exit cleanly, answer a JSON object and
//! leave a receipt (on stderr for a modern package, in the store for a legacy
//! one) that shows the expected decision under the expected runtime.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::publication_observe_check::{
    digest, modern_receipt, protects, PROBE_FIELD, PROBE_SCHEMA,
};
use super::publication_observe_legacy::{expired, Legacy};
use super::{Fault, Step};
use crate::hook_evidence_correlation::derive_proven_request_correlation;
use crate::hook_process_spawn::{run_isolated_hook_process, BoundedHookProcessResult};
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::pyjson;

const OUTPUT_LIMIT: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(25);
const PROTECTION: &str = "admission_protection_failed";
const MISMATCH: &str = "admission_policy_mismatch";
/// The two probes, in order: the command is a classification input only.
const PROBES: [(&str, &str); 2] = [("pwd", "allow"), ("rm -rf /", "deny")];

fn protection<T>() -> Step<T> {
    Err(Fault::Transition(PROTECTION))
}

/// Everything one observation launches with.
pub(super) struct Run<'a> {
    pub(super) argv: &'a [String],
    pub(super) modern: bool,
    pub(super) cwd: &'a Path,
    pub(super) environment: &'a BTreeMap<String, String>,
    pub(super) workspace: &'a str,
    pub(super) operation_id: &'a str,
    pub(super) runtime: &'a str,
    pub(super) deadline: Instant,
    pub(super) legacy: Option<&'a Legacy>,
}

/// The receipts and output digests of both launches, allow first.
pub(super) struct Probed {
    pub(super) receipts: Vec<Value>,
    pub(super) outputs: Vec<String>,
}

/// A launch that did not end cleanly proves nothing.
pub(super) fn launched(result: &BoundedHookProcessResult) -> Step<()> {
    if result.returncode != Some(0)
        || result.timed_out
        || result.containment_failed
        || result.output_limit_exceeded
    {
        return Err(Fault::Transition("admission_hook_launch_failed"));
    }
    Ok(())
}

impl Run<'_> {
    fn payload(&self, command: &str, request_id: &str) -> Map<String, Value> {
        let mut payload = Map::new();
        payload.insert("hook_event_name".to_owned(), json!("PreToolUse"));
        payload.insert("tool_name".to_owned(), json!("Bash"));
        payload.insert("tool_input".to_owned(), json!({ "command": command }));
        payload.insert("cwd".to_owned(), json!(self.workspace));
        if self.modern {
            payload.insert(
                PROBE_FIELD.to_owned(),
                json!({
                    "schema": PROBE_SCHEMA,
                    "operation_id": self.operation_id,
                    "request_id": request_id,
                }),
            );
        } else {
            payload.insert("tool_call_id".to_owned(), json!(request_id));
        }
        payload
    }

    fn recheck(&self) -> Step<()> {
        expired(self.deadline)?;
        self.legacy.map_or(Ok(()), Legacy::recheck)
    }

    /// The receipt a legacy package stored for this probe, waited for until
    /// the deadline.
    fn stored(&self, legacy: &Legacy, payload: &Map<String, Value>, since: &str) -> Step<Value> {
        let correlation =
            derive_proven_request_correlation("codex", "PreToolUse", payload, legacy.key());
        let Ok(Some(correlation)) = correlation else {
            return protection();
        };
        loop {
            legacy.recheck()?;
            if let Some(receipt) = legacy.receipt(&correlation, since)? {
                return Ok(receipt);
            }
            expired(self.deadline)?;
            let left = self.deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(POLL.min(left));
        }
    }

    /// Launch both probes. `request_id` names each one.
    pub(super) fn probes(&self, request_id: &dyn Fn() -> Step<String>) -> Step<Probed> {
        let mut probed = Probed {
            receipts: Vec::new(),
            outputs: Vec::new(),
        };
        for (command, decision) in PROBES {
            expired(self.deadline)?;
            let request_id = request_id()?;
            let payload = self.payload(command, &request_id);
            self.recheck()?;
            let since = now_isoformat()?;
            // The manifest-authenticated command is the launch target; frozen
            // Desktop bridge routing happens only after that exact configured
            // command has parsed and validated this probe.
            let result = run_isolated_hook_process(
                self.argv,
                &Value::Object(payload.clone()).to_string(),
                self.cwd,
                self.environment,
                None,
                Some(OUTPUT_LIMIT),
                None,
                Some(self.deadline),
            );
            expired(self.deadline)?;
            launched(&result)?;
            let Some(output) = pyjson::parse(&result.stdout)
                .ok()
                .filter(|output| output.as_dict().is_some())
            else {
                return protection();
            };
            let Some(json_output) = output.to_json() else {
                return protection();
            };
            let receipt = match self.legacy {
                Some(legacy) => self.stored(legacy, &payload, &since)?,
                None => match modern_receipt(&result.stderr, self.operation_id, &request_id) {
                    Some(receipt) => receipt,
                    None => return protection(),
                },
            };
            if !protects(&receipt, &json_output, decision, self.runtime) {
                return protection();
            }
            probed.receipts.push(receipt);
            probed.outputs.push(digest(&output));
        }
        Ok(probed)
    }
}

/// The policy generation and digest both receipts name, when they name the
/// same ones for two different requests.
pub(super) fn agreed(receipts: &[Value]) -> Step<(Value, Value)> {
    let (allow, deny) = (&receipts[0], &receipts[1]);
    let field = |receipt: &Value, key: &str| receipt.get(key).cloned().unwrap_or(Value::Null);
    let generation = field(allow, "policy_generation");
    let policy = field(allow, "policy_digest");
    if !(generation.is_i64() || generation.is_u64())
        || !policy.is_string()
        || generation != field(deny, "policy_generation")
        || policy != field(deny, "policy_digest")
        || field(allow, "request_digest") == field(deny, "request_digest")
    {
        return Err(Fault::Transition(MISMATCH));
    }
    Ok((generation, policy))
}

/// `datetime.now(timezone.utc).isoformat()`.
fn now_isoformat() -> Step<String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .ok_or(Fault::Transition("files_invalid"))?;
    micros_to_utc_isoformat(micros, "+00:00").ok_or(Fault::Transition("files_invalid"))
}
