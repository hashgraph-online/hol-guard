//! `SupplyChainEval` — the resident op behind `evaluate_package_request_artifact`.
//!
//! A child of `package_authority_op` so it shares that module's private
//! resident store and dependency wiring.

use super::*;

/// `SupplyChainEval` — `evaluate_package_request_artifact` port.
pub(crate) fn evaluate_supply_chain_eval(
    request: &SupplyChainEvalRequestV1,
) -> Result<Vec<u8>, String> {
    let test_overrides = test_seams_enabled_from(|name| std::env::var_os(name));
    evaluate_supply_chain_eval_with_seams(request, test_overrides)
}

/// `evaluate_supply_chain_eval` with the test-seam gate injected, so in-process
/// tests can honor the auth/entitlement overrides without mutating the
/// process environment.
pub(crate) fn evaluate_supply_chain_eval_with_seams(
    request: &SupplyChainEvalRequestV1,
    test_overrides: bool,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "schema_mismatch",
        ))
        .map_err(|e| e.to_string());
    }
    if let Some(rejected) = reject_empty_resident_paths(
        &request.request_id,
        &request_sha256,
        &request.store_path,
        &request.guard_home,
    ) {
        return rejected;
    }
    if test_overrides && !test_seam_overrides_are_valid(request) {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "native_supply_chain_eval_test_seam_invalid",
        ))
        .map_err(|e| e.to_string());
    }
    let store_path = PathBuf::from(&request.store_path);
    let guard_home = PathBuf::from(&request.guard_home);
    let store = ResidentSupplyChainStore::new(&store_path, &guard_home);
    let Some(saved_policy) = saved_policy_probe(request) else {
        return serde_json::to_vec(&err_result(
            &request.request_id,
            &request_sha256,
            "native_supply_chain_eval_saved_policy_invalid",
        ))
        .map_err(|e| e.to_string());
    };
    let deps_holder = ResidentEvalDeps::with_sync_auth_override(
        &store_path,
        &guard_home,
        request
            .sync_auth_context_override
            .as_ref()
            .filter(|_| test_overrides)
            .and_then(Value::as_object)
            .cloned(),
        request
            .package_entitlement_override
            .as_ref()
            .filter(|_| test_overrides)
            .and_then(Value::as_object)
            .cloned(),
    )
    .with_registry_metadata_override(
        request
            .registry_metadata_override
            .as_ref()
            .filter(|_| test_overrides)
            .and_then(Value::as_object)
            .cloned(),
    )
    .with_saved_policy(saved_policy);
    let deps = deps_holder.as_deps();
    let mut artifact = artifact_from_value(&request.artifact);
    if let Some(private) = &request.runtime_private_metadata {
        artifact.runtime_private_metadata = private.clone();
    }
    let workspace = request.workspace_dir.as_deref().map(Path::new);
    let scope = match enter_scope(request) {
        Ok(scope) => scope,
        Err(code) => {
            return serde_json::to_vec(&err_result(
                &request.request_id,
                &request_sha256,
                &format!("native_supply_chain_eval_{code}"),
            ))
            .map_err(|e| e.to_string());
        }
    };
    let evaluated = evaluate_package_request_artifact(
        &artifact,
        &store,
        &deps,
        workspace,
        request.now.as_deref(),
        request.external_archive_network_authorized,
        request.retain_external_archive_blob,
    );
    // Anything the evaluation could not answer is asked of the caller; the
    // outcome of an evaluation that was waiting on one is not a verdict.
    let needs = scope.finish();
    if !needs.is_empty() {
        return required_reply(&request.request_id, &request_sha256, needs);
    }
    let result = match evaluated {
        Ok(eval) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            payload: Some(eval.to_dict()),
        },
        Err(EvalError::SavedPolicyProbeRequired(cached)) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            // The envelope is answered (status ok) so the transport accepts it;
            // the code, not the status, tells the caller this is a question and
            // not a verdict.
            status: "ok".to_owned(),
            code: "saved_policy_probe_required".to_owned(),
            payload: Some(Value::Object(*cached)),
        },
        Err(e) => SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: format!("native_supply_chain_eval_failed:{}", eval_error_code(&e)),
            payload: None,
        },
    };
    crate::encode_response(&result)
}
