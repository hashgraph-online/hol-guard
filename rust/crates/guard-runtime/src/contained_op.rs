//! `ContainedExecution` resident ops — guarded spawn surface for contained
//! node/typescript/package-script/workspace-write execution, `execute_contained`
//! launcher, and `contained_test_hook` shim callback.
//!
//! Every op validates `schema` before dispatch, delegates to
//! `guard_command::contained_execution`, and returns `*ResultV1` via
//! `crate::encode_response`. `None` results serialise to `Value::Null` so the
//! Python caller distinguishes "not applicable" from transport failure.

use std::path::PathBuf;

use guard_command::contained_execution;
use guard_contracts::{
    ContainedExecuteRequestV1, ContainedExecuteResultV1, ContainedNodeExecuteRequestV1,
    ContainedNodeExecuteResultV1, ContainedPackageScriptExecuteRequestV1,
    ContainedPackageScriptExecuteResultV1, ContainedTestHookRequestV1, ContainedTestHookResultV1,
    ContainedTypescriptExecuteRequestV1, ContainedTypescriptExecuteResultV1,
    ContainedWorkspaceWriteExecuteRequestV1, ContainedWorkspaceWriteExecuteResultV1,
    CONTAINED_EXECUTE_REQUEST_SCHEMA, CONTAINED_EXECUTE_RESULT_SCHEMA,
    CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA, CONTAINED_NODE_EXECUTE_RESULT_SCHEMA,
    CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA, CONTAINED_TEST_HOOK_REQUEST_SCHEMA,
    CONTAINED_TEST_HOOK_RESULT_SCHEMA, CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA, CONTAINED_WORKSPACE_WRITE_EXECUTE_REQUEST_SCHEMA,
    CONTAINED_WORKSPACE_WRITE_EXECUTE_RESULT_SCHEMA,
};
use serde_json::json;

fn schema_err(schema: &str) -> String {
    format!("schema_mismatch:{schema}")
}

// ---------------------------------------------------------------------------
// Per-op evaluators
// ---------------------------------------------------------------------------

pub(crate) fn evaluate_contained_node_execute(
    request: &ContainedNodeExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let workspace = PathBuf::from(&request.workspace);
    let guard_home = PathBuf::from(&request.guard_home);
    let result = contained_execution::try_execute_contained_node_command_with_intent(
        &workspace,
        &request.manager,
        &request.argv,
        &guard_home,
        request.evidence.as_ref(),
    );
    let payload = result.map(|r| r.to_dict());
    crate::encode_response(&ContainedNodeExecuteResultV1 {
        schema: CONTAINED_NODE_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}

pub(crate) fn evaluate_contained_typescript_execute(
    request: &ContainedTypescriptExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let workspace = PathBuf::from(&request.workspace);
    let guard_home = PathBuf::from(&request.guard_home);
    let result = contained_execution::try_execute_contained_typescript_with_intent(
        &workspace,
        &request.manager,
        &request.argv,
        &guard_home,
        request.evidence.as_ref(),
    );
    let payload = result.map(|r| r.to_dict());
    crate::encode_response(&ContainedTypescriptExecuteResultV1 {
        schema: CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}

pub(crate) fn evaluate_contained_package_script_execute(
    request: &ContainedPackageScriptExecuteRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let workspace = PathBuf::from(&request.workspace);
    let guard_home = PathBuf::from(&request.guard_home);
    let result = contained_execution::try_execute_contained_package_script_with_intent(
        &workspace,
        &request.manager,
        &request.argv,
        &guard_home,
        None,
    );
    let payload = result.map(|r| r.to_dict());
    crate::encode_response(&ContainedPackageScriptExecuteResultV1 {
        schema: CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA.to_owned(),
        result: payload,
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

pub(crate) fn evaluate_contained_test_hook(
    request: &ContainedTestHookRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTAINED_TEST_HOOK_REQUEST_SCHEMA {
        return Err(schema_err(&request.schema));
    }
    let workspace = PathBuf::from(&request.workspace);
    let guard_home = PathBuf::from(&request.guard_home);
    let result =
        contained_execution::contained_test_hook(&workspace, &request.command_text, &guard_home);
    let payload = result.map(|r| r.to_dict());
    crate::encode_response(&ContainedTestHookResultV1 {
        schema: CONTAINED_TEST_HOOK_RESULT_SCHEMA.to_owned(),
        result: payload,
    })
}
