//! `PackageAuditProjection` — resident op owning the pure projections of a
//! workspace supply-chain audit that `local_supply_chain.py` used to compute in
//! Python: the receipt authority map, bundle advisory-alias enrichment, the CI
//! severity gate and the empty-inventory outcome.
//!
//! The caller hands over the audit result it assembled. The runtime reads the
//! cached advisory bundle from the store and hashes workspace files itself;
//! callers never recompute any of it.

use std::path::Path;

use guard_command::audit_receipt::{
    advisory_aliases_for_package, audit_receipt_metadata, ci_gate_result,
    resolve_empty_audit_outcome,
};
use guard_command::local_supply_chain::SupplyChainStore;
use guard_contracts::{
    PackageAuditProjectionRequestV1, PackageAuditQueryV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::{request_digest, ResidentPaths, ResidentSupplyChainStore};

fn invalid() -> String {
    "native_package_audit_projection_invalid".to_owned()
}

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value.as_object().ok_or_else(invalid)
}

/// `_cached_supply_chain_bundle_payload(store)`: the cached signed bundle body.
fn cached_bundle(store_path: &str, guard_home: &str) -> Result<Option<Map<String, Value>>, String> {
    if !Path::new(store_path).is_file() {
        return Err("native_package_audit_projection_store_unavailable".to_owned());
    }
    let store = ResidentSupplyChainStore::new(Path::new(store_path), Path::new(guard_home));
    let Some(workspace_id) = store.get_cloud_workspace_id() else {
        return Ok(None);
    };
    Ok(store
        .get_cached_supply_chain_bundle(&workspace_id)
        .and_then(|cached| cached.get("bundle").and_then(Value::as_object).cloned()))
}

fn project(request: &PackageAuditProjectionRequestV1) -> Result<Value, String> {
    match &request.query {
        PackageAuditQueryV1::Receipt(query) => {
            let bundle = match query.store_path.as_deref() {
                Some(store_path) => cached_bundle(store_path, &request.guard_home)?,
                None => None,
            };
            let workspace_dir = query.workspace_dir.as_deref().map(Path::new);
            Ok(Value::Object(audit_receipt_metadata(
                &ResidentPaths,
                object(&query.result)?,
                workspace_dir,
                bundle.as_ref(),
            )))
        }
        PackageAuditQueryV1::Aliases(query) => {
            let bundle = cached_bundle(&query.store_path, &request.guard_home)?;
            let aliases: Vec<Value> = query
                .packages
                .iter()
                .enumerate()
                .filter_map(|(index, package)| {
                    let aliases =
                        advisory_aliases_for_package(package.as_object()?, bundle.as_ref())?;
                    Some(json!({"index": index, "aliases": aliases}))
                })
                .collect();
            Ok(json!({ "aliases": aliases }))
        }
        PackageAuditQueryV1::CiGate(query) => Ok(Value::Object(ci_gate_result(
            object(&query.evaluation)?,
            &query.threshold,
        ))),
        PackageAuditQueryV1::EmptyOutcome(query) => {
            let (outcome, message) = resolve_empty_audit_outcome(
                &query.manifest_paths,
                &query.lockfile_paths,
                object(&query.posture)?,
            );
            Ok(json!({"audit_outcome": outcome, "message": message}))
        }
    }
}

pub(crate) fn evaluate_package_audit_projection(
    request: &PackageAuditProjectionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_audit_projection_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty() || request.guard_home.is_empty() {
        return Err(invalid());
    }
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(project(request)?),
    })
}

#[cfg(test)]
#[path = "package_audit_projection_op_tests.rs"]
mod tests;
