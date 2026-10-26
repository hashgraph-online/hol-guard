//! Current policy is separate from captured code identity and saved consent.

use std::time::Instant;

use guard_command::bash_approval::graph::Graph;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use guard_contracts::{NativeBashCaptureV1, PreToolActionTypeV1, PreToolResultV1};
use serde_json::json;

use crate::policy_enforcement::{apply_pre_tool_policy, AdmittedPolicySnapshot};

/// This is a risk assessment, never an execution or grant receipt. The launch
/// owner must repeat it with the currently admitted generation at commit.
pub(crate) struct Assessment {
    pub(crate) decisions: Vec<PreToolResultV1>,
}

impl Assessment {
    pub(crate) fn allows_without_consent(&self) -> bool {
        !self.decisions.is_empty()
            && self.decisions.iter().all(|result| {
                result.decision == "allow"
                    && matches!(result.minimum_action.as_str(), "allow" | "warn")
            })
    }
    pub(crate) fn has_hard_deny(&self) -> bool {
        self.decisions
            .iter()
            .any(|result| matches!(result.minimum_action.as_str(), "block" | "sandbox-required"))
    }
}

pub(crate) fn assess(
    graph: &Graph,
    request: &NativeBashCaptureV1,
    snapshot: &AdmittedPolicySnapshot,
    deadline: Instant,
) -> Result<Assessment, String> {
    graph
        .source_for_launch()
        .map_err(|_| "bash_policy_unbound_graph".to_owned())?;
    let mut decisions = Vec::with_capacity(1 + graph.invocations.len() + graph.writes.len());
    let mut judge =
        |mut payload: serde_json::Value, captured_operation: bool| -> Result<(), String> {
            if Instant::now() >= deadline {
                return Err("bash_policy_deadline_exceeded".into());
            }
            payload["cwd"] = json!(request.cwd);
            let mut intrinsic = evaluate_pre_tool_envelope_with_execution_context(
                &request.harness,
                "PreToolUse",
                &payload,
                snapshot.command_extensions.as_ref(),
                Some(deadline),
                PathContext {
                    home_dir: Some(&request.home_dir),
                    cwd: Some(&request.cwd),
                    shell_home_matches: true,
                    ..PathContext::default()
                },
                Some(&request.execution_environment),
            );
            // Only generic lack-of-proof/containment requirements are discharged. The
            // caller holds this closed graph's immutable code and effect boundary;
            // every reachable operation is judged independently below. Specific
            // command/extension risks and sensitive-target reviews remain intact.
            if captured_operation
                && intrinsic.action.action_type == PreToolActionTypeV1::Command
                && !intrinsic.action.sensitive_target
                && matches!(
                    (
                        intrinsic.minimum_action.as_str(),
                        intrinsic.reason_code.as_str()
                    ),
                    ("review", "native_command_review_required")
                        | ("sandbox-required", "native_workspace_containment_required")
                        | (
                            "review",
                            "native_workspace_containment_executable_outside_roots"
                        )
                )
            {
                intrinsic.minimum_action = "allow".into();
                intrinsic.policy_action = "allow".into();
                intrinsic.decision = "allow".into();
                intrinsic.explicitly_benign = true;
                intrinsic.reason_code = "native_captured_bash_operation".into();
                intrinsic.reason =
                    "This operation is bound to the captured Bash graph and its declared effects."
                        .into();
            }
            // Apply installed policy AFTER the native graph proof. An explicit
            // execution Ask/deny or matching extension restriction still wins.
            decisions.push(apply_pre_tool_policy(snapshot, &payload, intrinsic)?);
            Ok(())
        };
    judge(command_payload(&request.command), true)?;
    for invocation in &graph.invocations {
        let command = invocation
            .operation
            .argv
            .iter()
            .map(|value| quote(value))
            .collect::<Vec<_>>()
            .join(" ");
        let captured_operation = match invocation.resolved_path.as_deref() {
            Some(path) => {
                graph.code.iter().any(|code| code.resolved_path == path)
                    || matches!(
                        invocation.operation.argv.first().map(String::as_str),
                        Some("source" | ".")
                    ) && invocation.operation.argv.len() == 2
                        && graph
                            .sources
                            .iter()
                            .any(|source| source.resolved_path == path)
                    || graph.brokered_images.contains_key(path)
                    || matches!(path, "/usr/bin/sort" | "/usr/bin/head" | "/usr/bin/curl")
                        && graph.native_images.contains_key(path)
            }
            None => matches!(
                invocation.operation.argv.first().map(String::as_str),
                Some(":" | "printf" | "echo" | "set" | "test" | "[" | "exit" | "true" | "false")
            ),
        };
        judge(command_payload(&command), captured_operation)?;
    }
    for effect in &graph.writes {
        // A held regular output FD performs a literal file mutation. Use the
        // existing native file-write authority, including its sensitive-path
        // and persistence checks, rather than a synthetic shell no-op whose
        // empty command model cannot carry extension evidence.
        judge(
            json!({"tool_name":"write", "tool_input":{
                "file_path":effect.redirect.path, "content":"", "append":effect.redirect.append
            }}),
            false,
        )?;
    }
    if Instant::now() >= deadline {
        return Err("bash_policy_deadline_exceeded".into());
    }
    Ok(Assessment { decisions })
}

fn command_payload(command: &str) -> serde_json::Value {
    json!({"tool_name":"bash", "tool_input":{"command":command}})
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
