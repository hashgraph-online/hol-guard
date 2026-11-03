//! Observed versions are not executable grants. A legacy hook that returns
//! allow cannot ensure which mutable interpreter/script bytes the host opens.
use std::time::{Duration, Instant};

use guard_contracts::{
    NativeExactActionPayloadV1, NativeExactActionQueryV1, NativeLaunchEvidenceV1,
    NATIVE_EXACT_ACTION_MAX_BUDGET_MS,
};
use serde_json::{json, Value};

use super::context::Engines;
use super::reasons::{Proof, UNPROVEN_LAUNCH};

pub(super) fn names_script_runtime(action: &NativeExactActionQueryV1) -> bool {
    let NativeExactActionQueryV1::ExactAction {
        command: Some(command),
        ..
    } = action
    else {
        return false;
    };
    let model = guard_command::command_model::parse_shell_command(
        command,
        None,
        None,
        "posix",
        "shell_string",
        "guard-script-delivery",
        true,
    );
    model.segments.iter().any(|segment| {
        let executable = segment.executable.as_deref().unwrap_or("");
        let basename = executable
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let name = basename.strip_suffix(".exe").unwrap_or(&basename);
        super::launcher_sets::is_python_launcher(name)
            || super::node_script::NODE_LAUNCHERS.contains(&name)
            || super::runner_bin::LOCAL_BIN_RUNNERS.contains(&name)
    })
}

pub(super) fn requires_owner(value: &Value) -> bool {
    fn walk(value: &Value, depth: usize) -> bool {
        if depth > 32 {
            return true;
        }
        match value {
            Value::Object(map) => {
                if matches!(
                    map.get("kind").and_then(Value::as_str),
                    Some("python-script" | "node-script" | "runner-local-bin")
                ) {
                    return true;
                }
                if map.get("entrypoint").is_some_and(|entry| {
                    matches!(
                        entry["kind"].as_str(),
                        Some("direct-script" | "direct-env-script" | "file-script" | "flag-script")
                    )
                }) {
                    return true;
                }
                map.values().any(|child| walk(child, depth + 1))
            }
            Value::Array(values) => values.iter().any(|child| walk(child, depth + 1)),
            _ => false,
        }
    }
    walk(value, 0)
}

pub(super) fn observe(
    action: &NativeExactActionQueryV1,
    engines: &dyn Engines,
) -> Proof<NativeExactActionPayloadV1> {
    let NativeExactActionQueryV1::ExactAction { budget_ms, .. } = action else {
        return Err("native_exact_action_evidence_query_invalid");
    };
    let budget = Duration::from_millis((*budget_ms).min(NATIVE_EXACT_ACTION_MAX_BUDGET_MS));
    let evidence = super::token::exact_action_components(action, Instant::now() + budget, engines)
        .and_then(|components| {
            let observed = json!({"identity":components.identity,"content":components.content});
            #[cfg(not(windows))]
            let observed = super::runner_code::version_identity(observed);
            let bytes = guard_policy_snapshot::canonical_json_bytes(&observed)
                .map_err(|_| UNPROVEN_LAUNCH)?;
            Ok(Box::new(NativeLaunchEvidenceV1 {
                schema: "guard-native-launch-evidence.v1".into(),
                inventory_sha256: super::fs_path::sha256_hex(&bytes),
                code_identity_complete: false,
                unknown_edges: vec!["unverified_code_closure".into()],
                risk_verdict: "not_evaluated".into(),
                execution_binding: "unavailable".into(),
                duration: "none".into(),
                scope: "observed_invocation".into(),
                can_run_once: false,
                can_persist: false,
            }))
        });
    Ok(match evidence {
        Ok(evidence) => NativeExactActionPayloadV1::LaunchEvidence {
            evidence: Some(evidence),
            unavailable_reason: None,
        },
        Err(reason) => NativeExactActionPayloadV1::LaunchEvidence {
            evidence: None,
            unavailable_reason: Some(reason.into()),
        },
    })
}
