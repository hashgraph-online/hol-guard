//! The saved lookups a relayed call names, read from the store snapshot.
//!
//! Each answer is the observation the proxy's effect returns
//! (`native_mcp_tool_policy.py`) for a non-consuming read:
//!
//! - `grant_lookup`: `resolve_policy_decision_lookup(harness, selector)`;
//! - `policy_lookup`: `resolve_policy_decision_lookup_with_memory_pattern`,
//!   the direct, exact-command and memory ids composed most restrictive, a
//!   miss diagnosed in the same answer;
//! - `reuse_diagnostic`: `approval_reuse_validation_reason`.
//!
//! The proxy composes each candidate with the portable Git identity of the
//! workspace (`resolve_policy_decision_lookup`,
//! `store_portable_project_memory.py`). The resident derives that identity
//! itself (`project_identity`) and composes it the same way, and answers
//! whenever that identity resolves exactly. A row bound to another workspace
//! or another project's identity is read by no lookup of this one: every
//! workspace selector the lookup binds is this workspace's own.

use super::store::{Probe, Saved};
use super::POLICY_NEED;
use crate::context_digest::python_strip;
use crate::mcp_tool_policy_lookup::{most_restrictive, without_permission_elevation};
use crate::memory_pattern::{verdict, MemoryRequest};
use crate::policy_decision_lookup_op::evaluate_non_consuming;
use crate::project_identity::{portable_workspace, resolve_relative, PortableIdentity};
use guard_contracts::{ApprovalReuseDiagnosticRequestV1, APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA};
use serde_json::{json, Value};

const SAVED_LOOKUP: &str = "mcp_relay_saved_lookup_failed";
const SAVED_PORTABLE: &str = "mcp_relay_saved_portable_workspace";
const SAVED_DIAGNOSTIC: &str = "mcp_relay_saved_diagnostic_failed";

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// A need field the proxy requires to be text.
fn text<'a>(need: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    need.get(key).and_then(Value::as_str).ok_or(POLICY_NEED)
}

/// A need field the proxy requires to be text or `None`.
fn optional<'a>(need: &'a Value, key: &str) -> Result<Option<&'a str>, &'static str> {
    match need.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(POLICY_NEED),
    }
}

impl Saved<'_> {
    /// The observation the proxy returns for `need`.
    pub(super) fn answer(&self, need: &Value) -> Result<Value, &'static str> {
        match need.get("kind").and_then(Value::as_str) {
            Some("grant_lookup") => {
                let lookup = self.probe(&Probe {
                    harness: text(need, "harness")?,
                    artifact_id: text(need, "selector")?,
                    artifact_hash: None,
                    workspace: None,
                    publisher: None,
                    exact_match_context: None,
                })?;
                Ok(json!({"decision": field(&lookup, "decision")}))
            }
            Some("policy_lookup") => self.policy_lookup(need),
            Some("reuse_diagnostic") => Ok(json!({"reason": self.diagnosis(need)?})),
            _ => Err(POLICY_NEED),
        }
    }

    fn policy_lookup(&self, need: &Value) -> Result<Value, &'static str> {
        let harness = text(need, "harness")?;
        let artifact_id = text(need, "artifact_id")?;
        let probe = Probe {
            harness,
            artifact_id,
            artifact_hash: Some(text(need, "artifact_hash")?),
            workspace: optional(need, "workspace")?,
            publisher: optional(need, "publisher")?,
            exact_match_context: optional(need, "runtime_exact_match_context")?,
        };
        let memory = verdict(&MemoryRequest {
            command: optional(need, "memory_command")?,
            artifact_type: optional(need, "memory_artifact_type")?,
            artifact_id: Some(artifact_id),
            artifact_name: optional(need, "memory_artifact_name")?,
            harness: Some(harness),
        });
        let identity = self.portable_identity(probe.workspace)?;
        let portable = identity.as_deref();
        let mut lookups = vec![self.candidate(&probe, portable)?];
        for id in memory
            .exact_artifact_ids
            .iter()
            .chain(memory.memory_artifact_id.iter())
        {
            let candidate = Probe {
                artifact_id: id,
                ..probe
            };
            lookups.push(self.candidate(&candidate, portable)?);
        }
        let composed = most_restrictive(&lookups).ok_or(SAVED_LOOKUP)?;
        let decision = field(&composed, "decision").clone();
        let ignored = !field(&composed, "ignored_local_integrity").is_null();
        let mut observed = json!({"decision": decision, "ignored_local_integrity": ignored});
        if observed["decision"].is_null() && !ignored {
            observed["reuse_diagnostic"] = json!({"reason": self.diagnosis(need)?});
        }
        Ok(observed)
    }

    /// One candidate as the proxy reads it (`Prober::candidate`): the local
    /// lookup composed most restrictive with the restrictive-only lookup
    /// under the workspace's portable identity, when it has one. A workspace
    /// that already names that identity reads the portable lookup alone, as
    /// `resolve_policy_decision_lookup` returns it.
    fn candidate(&self, probe: &Probe<'_>, portable: Option<&str>) -> Result<Value, &'static str> {
        let Some(portable) = portable else {
            return self.probe(probe);
        };
        let preview = without_permission_elevation(self.probe(&Probe {
            workspace: Some(portable),
            ..*probe
        })?);
        if probe.workspace.map(python_strip) == Some(portable) {
            return Ok(preview);
        }
        let local = self.probe(probe)?;
        most_restrictive(&[local, preview]).ok_or(SAVED_LOOKUP)
    }

    /// The portable identity the proxy composes for `workspace`
    /// (`_portable_project_workspace`). A workspace that already names a
    /// portable identity is its own, and one whose identity the resident
    /// does not resolve exactly defers the call.
    fn portable_identity(&self, workspace: Option<&str>) -> Result<Option<String>, &'static str> {
        let Some(workspace) = workspace else {
            return Ok(None);
        };
        match portable_workspace(workspace) {
            PortableIdentity::Absent => Ok(None),
            PortableIdentity::Identity(identity) => Ok(Some(identity)),
            PortableIdentity::Unknown => Err(SAVED_PORTABLE),
        }
    }

    /// One candidate for a lane that names its own probe rather than a need
    /// the resident sent. The portable identity is resolved here, as
    /// `resolve_policy_decision_lookup` resolves it for every lookup it
    /// answers, so a caller cannot read the local row alone by mistake.
    ///
    /// The package lane probes a scope token rather than a directory, and
    /// `_workspace_path` reads such a name against the working directory of
    /// the process that composed it, so that directory is resolved from the
    /// facts the caller reported rather than from the resident's own.
    pub(super) fn package_candidate(
        &self,
        probe: &Probe<'_>,
        process_cwd: &str,
    ) -> Result<Value, &'static str> {
        let identity = match probe.workspace {
            None => None,
            Some(workspace) => match resolve_relative(workspace, process_cwd) {
                PortableIdentity::Absent => None,
                PortableIdentity::Identity(identity) => Some(identity),
                PortableIdentity::Unknown => return Err(SAVED_PORTABLE),
            },
        };
        self.candidate(probe, identity.as_deref())
    }

    pub(super) fn probe(&self, probe: &Probe<'_>) -> Result<Value, &'static str> {
        // A read the proxy would follow with an audit write fails here, on the
        // read-only snapshot, and defers the call.
        evaluate_non_consuming(&self.lookup_request(probe), self.connection)
            .map_err(|_| SAVED_LOOKUP)
    }

    /// `approval_reuse_diagnostic`'s reason for the selectors `need` names.
    fn diagnosis(&self, need: &Value) -> Result<Value, &'static str> {
        self.diagnosed(&Probe {
            harness: text(need, "harness")?,
            artifact_id: text(need, "artifact_id")?,
            artifact_hash: Some(text(need, "artifact_hash")?),
            workspace: optional(need, "workspace")?,
            publisher: optional(need, "publisher")?,
            // The diagnostic selects on the saved row, not on an exact
            // command match, so it reads no exact-match context.
            exact_match_context: None,
        })
        .map(|(reason, _)| reason)
    }

    /// `approval_reuse_diagnostic`'s reason and the hash it found stored: the
    /// first request carries no evidence, and the evidence the resident names
    /// follows.
    pub(super) fn diagnosed(&self, probe: &Probe<'_>) -> Result<(Value, Value), &'static str> {
        let mut request = ApprovalReuseDiagnosticRequestV1 {
            schema: APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            store_path: self.store_path.clone(),
            guard_home: self.guard_home.clone(),
            harness: probe.harness.to_owned(),
            artifact_id: probe.artifact_id.to_owned(),
            artifact_hash: probe.artifact_hash.map(str::to_owned),
            workspace: probe.workspace.map(str::to_owned),
            publisher: probe.publisher.map(str::to_owned),
            now: self.now.clone(),
            evidence: None,
            current_action: None,
        };
        let diagnose = |request: &ApprovalReuseDiagnosticRequestV1| {
            crate::approval_reuse_diagnostic_op::diagnose(
                self.connection,
                request,
                self.now.clone(),
            )
            .map_err(|_| SAVED_DIAGNOSTIC)
        };
        let mut payload = diagnose(&request)?;
        if field(&payload, "need").as_str() == Some("integrity_evidence") {
            request.evidence = Some(self.diagnostic_evidence(
                field(&payload, "policy") == &Value::Bool(true),
                field(&payload, "local_once") == &Value::Bool(true),
            ));
            payload = diagnose(&request)?;
        }
        let shaped = payload.as_object().is_some_and(|fields| {
            fields.len() == 2 && fields.contains_key("reason") && fields.contains_key("stored_hash")
        });
        let (reason, stored) = (field(&payload, "reason"), field(&payload, "stored_hash"));
        if !shaped
            || !(reason.is_null() || reason.is_string())
            || !(stored.is_null() || stored.is_string())
        {
            return Err(SAVED_DIAGNOSTIC);
        }
        Ok((reason.clone(), stored.clone()))
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_saved_tests.rs"]
pub(super) mod tests;
