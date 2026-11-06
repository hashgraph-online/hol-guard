//! `ContainedExecution` resident ops — guarded spawn surface for contained
//! node/typescript/package-script/workspace-write execution and the
//! `execute_contained` launcher.
//!
//! Every op validates `schema` before dispatch, delegates to
//! `guard_command::contained_execution`, and returns its `*Result*` via
//! `crate::encode_response`. `None` results serialise to `Value::Null` so the
//! Python caller distinguishes "not applicable" from transport failure.

use std::collections::BTreeMap;
use std::path::PathBuf;

use guard_command::{contained_execution, contained_runner};
use guard_contracts::{
    ContainedExecuteRequestV1, ContainedExecuteResultV1, ContainedNodeExecuteRequestV2,
    ContainedNodeExecuteResultV2, ContainedPackageScriptExecuteRequestV1,
    ContainedPackageScriptExecuteResultV1, ContainedTypescriptExecuteRequestV2,
    ContainedTypescriptExecuteResultV1, ContainedWorkspaceWriteExecuteRequestV1,
    ContainedWorkspaceWriteExecuteResultV1, ContainmentHealthProbeRequestV1,
    ContainmentHealthProbeResultV1, CONTAINED_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_EXECUTE_RESULT_SCHEMA, CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_NODE_EXECUTE_RESULT_SCHEMA, CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA, CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA, CONTAINED_WORKSPACE_WRITE_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_WORKSPACE_WRITE_EXECUTE_RESULT_SCHEMA, CONTAINMENT_HEALTH_PROBE_REQUEST_SCHEMA,
    CONTAINMENT_HEALTH_PROBE_RESULT_SCHEMA,
};
use serde_json::json;

fn schema_err(schema: &str) -> String {
    format!("schema_mismatch:{schema}")
}

// ---------------------------------------------------------------------------
// Per-op evaluators
// ---------------------------------------------------------------------------

/// Run one runner flow with the request's launch context. A request without
/// a shim directory cannot pin its tools, so it never reaches the flow.
///
/// Any refusal inside a flow (missing identity, drift, failed enforcement) is
/// `null`, never a partial result, so the caller returns to Guard review
/// instead of running uncontained.
fn run_runner<T>(
    request: &RunnerRequest<'_>,
    flow: impl FnOnce(&contained_runner::RunnerLaunch<'_>) -> T,
) -> Option<T> {
    let shim_directory = PathBuf::from(request.shim_directory?);
    let workspace = PathBuf::from(request.workspace);
    let empty = BTreeMap::new();
    let launch = contained_runner::RunnerLaunch {
        workspace: &workspace,
        manager: request.manager,
        argv: request.argv,
        shim_directory: &shim_directory,
        environment: request.environment.unwrap_or(&empty),
        timeout_seconds: request.timeout_seconds,
    };
    Some(flow(&launch))
}

struct RunnerRequest<'a> {
    workspace: &'a str,
    manager: &'a str,
    argv: &'a [String],
    shim_directory: Option<&'a str>,
    environment: Option<&'a BTreeMap<String, String>>,
    timeout_seconds: Option<f64>,
}

/// The resident parses the launch intent from `manager` and `argv` itself, so
/// one request decides the whole launch, including whether an uncontained
/// Vitest handoff must stop the shim instead of returning to review.
pub(crate) fn evaluate_contained_node_execute(
    request: &ContainedNodeExecuteRequestV2,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let runner = RunnerRequest {
        workspace: &request.workspace,
        manager: &request.manager,
        argv: &request.argv,
        shim_directory: request.shim_directory.as_deref(),
        environment: request.environment.as_ref(),
        timeout_seconds: request.timeout_seconds,
    };
    let outcome = run_runner(&runner, contained_runner::execute_node_command).unwrap_or_default();
    crate::encode_response(&ContainedNodeExecuteResultV2 {
        schema: CONTAINED_NODE_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: outcome.result,
        refusal: outcome.refusal,
    })
}

pub(crate) fn evaluate_contained_typescript_execute(
    request: &ContainedTypescriptExecuteRequestV2,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let runner = RunnerRequest {
        workspace: &request.workspace,
        manager: &request.manager,
        argv: &request.argv,
        shim_directory: request.shim_directory.as_deref(),
        environment: request.environment.as_ref(),
        timeout_seconds: request.timeout_seconds,
    };
    let result = run_runner(&runner, contained_runner::execute_typescript_command).flatten();
    crate::encode_response(&ContainedTypescriptExecuteResultV1 {
        schema: CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA.to_owned(),
        result,
    })
}

pub(crate) fn evaluate_contained_package_script_execute(
    request: &ContainedPackageScriptExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let runner = RunnerRequest {
        workspace: &request.workspace,
        manager: &request.manager,
        argv: &request.argv,
        shim_directory: request.shim_directory.as_deref(),
        environment: request.environment.as_ref(),
        timeout_seconds: request.timeout_seconds,
    };
    let result = run_runner(&runner, contained_runner::execute_package_script).and_then(Result::ok);
    crate::encode_response(&ContainedPackageScriptExecuteResultV1 {
        schema: CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA.to_owned(),
        result,
    })
}

pub(crate) fn evaluate_contained_workspace_write_execute(
    request: &ContainedWorkspaceWriteExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_WORKSPACE_WRITE_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let workspace = PathBuf::from(&request.workspace);
    let guard_home = PathBuf::from(&request.guard_home);
    // Structured semantic op (`patch-check`/`patch-apply`/`format-write`/
    // `copy-generated`) takes precedence over the legacy token path.
    let result = if let (Some(operation), Some(source)) =
        (request.operation.as_deref(), request.source.as_deref())
    {
        contained_execution::try_execute_contained_workspace_write_semantic(
            &workspace,
            operation,
            source,
            request.target.as_deref(),
            request.environment.as_ref(),
            request.timeout_seconds,
            &guard_home,
        )
    } else {
        let tokens = contained_execution::shlex_split(&request.command_text).unwrap_or_default();
        contained_execution::try_execute_contained_workspace_write_with_intent(
            &workspace,
            &tokens,
            &guard_home,
        )
    };
    let payload = result.map(|r| r.to_dict());
    crate::encode_response(&ContainedWorkspaceWriteExecuteResultV1 {
        schema: CONTAINED_WORKSPACE_WRITE_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}

pub(crate) fn evaluate_contained_execute(
    request: &ContainedExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let guard_home = PathBuf::from(&request.guard_home);
    let containment_request: contained_execution::ContainmentRequest =
        contained_execution::ContainmentRequest::from_dict(&request.request)
            .ok_or_else(|| "invalid_request_payload".to_owned())?;
    let containment_policy: contained_execution::ContainmentPolicy =
        contained_execution::ContainmentPolicy::from_dict(&request.policy)
            .ok_or_else(|| "invalid_policy_payload".to_owned())?;
    let result = contained_execution::execute_contained(
        &containment_request,
        &containment_policy,
        &guard_home,
        &request.run_id,
    );
    let payload = match result {
        Ok((exit_code, stdout, stderr, outputs, started_ms, enforcement, captured)) => {
            Some(json!({
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "outputs": outputs.iter().map(|o| o.to_dict()).collect::<Vec<_>>(),
                "started_epoch_ms": started_ms,
                "enforcement": enforcement,
                "captured_files": captured,
            }))
        }
        Err(_) => None,
    };
    crate::encode_response(&ContainedExecuteResultV1 {
        schema: CONTAINED_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}

/// Answer one containment health question for the daemon.
///
/// The probe runs a real contained `/usr/bin/true` and reports whether the
/// backend enforced it, so an unavailable or unenforced backend is reported as
/// such instead of being inferred. A probe that could not run at all is `null`,
/// which the caller treats as unavailable rather than healthy.
pub(crate) fn evaluate_containment_health_probe(
    request: &ContainmentHealthProbeRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINMENT_HEALTH_PROBE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let payload = contained_runner::containment_health_evidence(&request.daemon_fingerprint).ok();
    crate::encode_response(&ContainmentHealthProbeResultV1 {
        schema: CONTAINMENT_HEALTH_PROBE_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}

#[cfg(test)]
#[path = "contained_op_tests.rs"]
mod tests;
