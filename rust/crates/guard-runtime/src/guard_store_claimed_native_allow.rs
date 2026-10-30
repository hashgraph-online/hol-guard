//! `settle_claimed_native_allow`: settle a once-approval the caller says it
//! was granted for this exact native request, in one store call.
//!
//! The retry names the request identity its allow was saved under. The
//! identity must equal it, then:
//!
//! 1. the exact unexpired local-once allow for that identity is read without
//!    claiming it (the `local_once_only` policy lookup), and must answer the
//!    named approval request when one is given;
//! 2. a live completion (`claim_saved_approval` false) accepts it as is; any
//!    other retry spends it, consuming the once-approval;
//! 3. without a local allow, only a live completion naming its request may
//!    accept the exact Cloud Review allow issued for that request. That allow
//!    must carry this harness, artifact, identity and workspace; the
//!    completion consumes it afterwards.
//!
//! The caller keeps the integrity key in the keyring and ships it; a missing
//! key reads as no authority. Any refusal answers `false`.

use std::path::Path;

use guard_contracts::{
    ClaimEvidenceBindingV1, PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::claim_reuse::{claim_approval_reuse_decisions_with, ClaimEvidence};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_exact_cloud_apply::integrity_material;
use crate::local_store_read::STORE_FILE_NAME;
use crate::policy_decision_lookup_op::{computed_workspace_policy_key, evaluate_non_consuming};
use crate::resident_transport::constant_time_eq;

pub(crate) fn settle(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let harness = args.str("harness")?;
    let artifact_id = args.str("artifact_id")?;
    let workspace = args.opt_str("workspace")?;
    let identity = args.opt_str("identity")?;
    let claimed_hash = args.str("claimed_saved_allow_hash")?;
    let request_id = args.opt_str("claimed_approval_request_id")?;
    let claim = args.flag("claim_saved_approval")?;
    let now = guard_contracts::canonical_utc_timestamp(args.str("now")?)
        .ok_or(StoreError::Invalid("claimed_native_allow_time_invalid"))?;
    let Some(identity) =
        identity.filter(|identity| constant_time_eq(identity.as_bytes(), claimed_hash.as_bytes()))
    else {
        return Ok(json!(false));
    };
    let Some((key, key_id)) = integrity_material(args)? else {
        return Ok(json!(false));
    };
    let key_b64 = args.str("integrity_key_b64")?;
    let request = PolicyDecisionLookupRequestV1 {
        schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        harness: harness.to_owned(),
        artifact_id: Some(artifact_id.to_owned()),
        artifact_hash: Some(identity.to_owned()),
        workspace: workspace.map(str::to_owned),
        publisher: None,
        now: now.clone(),
        runtime_exact_match_context: None,
        consume_one_shot: false,
        local_once_only: true,
        // The exact peek never refreshes the policy integrity state.
        integrity_state: Some(json!({})),
        integrity_key_b64: None,
        integrity_key_id: None,
        local_once_integrity_key_b64: Some(key_b64.to_owned()),
        local_once_integrity_key_id: Some(key_id.to_owned()),
        policy_bundle_decision_identities: None,
        exception_workspace: None,
        cloud_exception_bundle: Default::default(),
        probe_groups: None,
        portable_workspace: None,
        evidence_binding: None,
    };
    let Ok(lookup) = evaluate_non_consuming(&request, connection) else {
        return Ok(json!(false));
    };
    let decision = &lookup["decision"];
    if !allows_request(decision, request_id) {
        // A Cloud Review allow is stored apart from local approvals and only
        // answers to the request it was issued for. The live completion that
        // asks without claiming consumes it afterwards; a retry that would
        // claim it here is left to the ordinary path.
        let Some(request_id) = request_id.filter(|_| !claim) else {
            return Ok(json!(false));
        };
        let target = Target {
            harness,
            artifact_id,
            workspace,
            identity,
        };
        return exact_cloud_allow(
            connection,
            request_id,
            &now,
            (key.as_slice(), key_id),
            &target,
        );
    }
    if !claim {
        return Ok(json!(true));
    }
    if decision
        .get("approval_id")
        .and_then(Value::as_str)
        .is_none()
    {
        return Ok(json!(false));
    }
    let evidence = ClaimEvidence {
        integrity_state: None,
        integrity_key: None,
        integrity_key_id: None,
        local_once_key: Some(key.as_slice()),
        local_once_key_id: Some(key_id),
        policy_bundle_identities: None,
    };
    // `claim_evidence_binding(connection, bundle=False)`: a local-once member
    // needs neither the policy state nor the bundle re-read.
    let binding = ClaimEvidenceBindingV1::default();
    let claimed = claim_approval_reuse_decisions_with(
        connection,
        std::slice::from_ref(decision),
        &now,
        &evidence,
        &|connection, members| {
            crate::claim_reuse_binding::evidence_is_bound(
                connection,
                members,
                &evidence,
                Some(&binding),
            )
        },
        true,
    )?;
    Ok(json!(claimed))
}

fn allows_request(decision: &Value, request_id: Option<&str>) -> bool {
    decision.get("action").and_then(Value::as_str) == Some("allow")
        && request_id
            .is_none_or(|id| decision.get("request_id").and_then(Value::as_str) == Some(id))
}

struct Target<'a> {
    harness: &'a str,
    artifact_id: &'a str,
    workspace: Option<&'a str>,
    identity: &'a str,
}

fn exact_cloud_allow(
    connection: &Connection,
    request_id: &str,
    now: &str,
    (key, key_id): (&[u8], &str),
    target: &Target<'_>,
) -> StoreResult<Value> {
    // One consistent view of the request and the allow issued for it.
    connection.execute_batch("BEGIN")?;
    let decision = crate::guard_store_exact_cloud_peek::verified_decision(
        connection, request_id, now, key, key_id,
    );
    connection.execute_batch("ROLLBACK")?;
    let decision = decision?;
    if !allows_request(&decision, Some(request_id)) {
        return Ok(json!(false));
    }
    let text = |field: &str| decision.get(field).and_then(Value::as_str);
    let stored_hash = text("artifact_hash").unwrap_or_default();
    Ok(json!(
        text("harness") == Some(target.harness)
            && text("artifact_id") == Some(target.artifact_id)
            && !stored_hash.is_empty()
            && constant_time_eq(stored_hash.as_bytes(), target.identity.as_bytes())
            && text("workspace").map(str::to_owned)
                == computed_workspace_policy_key(target.workspace)
    ))
}
