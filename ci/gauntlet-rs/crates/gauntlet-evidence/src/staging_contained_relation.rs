//! Compose signed contained-route records with an outside product sample and
//! v3 writer image. This joins evidence within one run; a post-event process
//! image still cannot prove that the signed request caused the physical write.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::staging_control_record::{observe_staging_control_context, read_one};
use crate::{
    canonical_value, verify_contained_output_custody, verify_contained_route_accounting,
    verify_controller_envelope, verify_staging_product_relation_ineligible, EvidenceError, Result,
    StagingEvidencePins, StagingProductRelationPins,
};
use gauntlet_contracts::{
    canonicalize, validate_effect_writer_images, EffectFileHandle, EFFECT_IMAGE_JOURNAL_SCHEMA,
};
use serde_json::{json, Value};

const INVALID: EvidenceError =
    EvidenceError::Invalid("contained effect relation differs from outside evidence");

/// Identity obtained from a caller-held final file. Byte, mode and owner
/// checks and journal/report custody are the caller's responsibility.
pub struct ContainedFileIdentity {
    pub device: u64,
    pub inode: u64,
    pub handle: EffectFileHandle,
}

fn one(rows: &[Value], predicate: impl Fn(&Value) -> bool) -> Result<&Value> {
    let mut matching = rows.iter().filter(|row| predicate(row));
    let row = matching.next().ok_or(INVALID)?;
    if matching.next().is_some() {
        return Err(INVALID);
    }
    Ok(row)
}

fn rows(value: &Value, maximum: usize) -> Result<&[Value]> {
    value
        .as_array()
        .filter(|rows| rows.len() <= maximum)
        .map(Vec::as_slice)
        .ok_or(INVALID)
}

fn known_writer(
    journal: &Value,
    product: &Value,
    native_sha256: &str,
    file: &ContainedFileIdentity,
) -> Result<Value> {
    let events = rows(&journal["events"], 32_768)?;
    if !validate_effect_writer_images(&journal["writer_images"], events) {
        return Err(INVALID);
    }
    let mut matching = Vec::new();
    for row in events {
        if row["device"].as_u64() != Some(file.device) || row["inode"].as_u64() != Some(file.inode)
        {
            continue;
        }
        let handle = EffectFileHandle::from_json(&row["file_handle"]).ok_or(INVALID)?;
        if handle == file.handle {
            matching.push(row);
        }
    }
    // The fixed control fixture produces exactly one final-file close-write.
    // A second matching write or missing handle cannot be silently discarded.
    if matching.len() != 1 {
        return Err(INVALID);
    }
    let event = matching[0];
    let image = one(rows(&journal["writer_images"], 64)?, |row| {
        row["event_sequence"] == event["sequence"]
    })?;
    let sample = &image["sample"];
    let writer = &event["writer"];
    if image["surface"] != "contained-output"
        || sample.is_null()
        || !image["unavailable_reason"].is_null()
        || event["pidfd_available"] != true
        || event["owner"] != 10004
        || writer["cgroup"] != product["cgroup"]
        || writer["pid"] != event["reported_pid"]
        || writer["pid"] != image["writer_pid"]
        || writer["pid"] == product["pid"]
        || writer["start_ticks"] != image["writer_start_ticks"]
        || writer["start_ticks"].as_u64().ok_or(INVALID)?
            < product["start_ticks"].as_u64().ok_or(INVALID)?
        || sample["executable_sha256"] != native_sha256
        || sample["observed_action"] != "serve-managed"
        || sample["namespace_pid"].as_u64().is_none_or(|n| n <= 1)
        || ["mnt", "pid", "user"]
            .iter()
            .any(|name| sample["namespaces"][name] != product["namespaces"][name])
    {
        return Err(INVALID);
    }
    Ok(
        json!({"event_sequence":event["sequence"],"pid":writer["pid"],"start_ticks":writer["start_ticks"],
        "cgroup":writer["cgroup"],"parent_pid":sample["parent_pid"],"namespace_pid":sample["namespace_pid"],
        "executable_sha256":native_sha256,"argv_sha256":sample["argv_sha256"],
        "observed_action":"serve-managed","namespaces_matched":3,"sampled_after_close_write":true}),
    )
}

/// Verify only this composed relation. Callers must authenticate the journal,
/// product sample, Native asset digest and final-file observation separately.
pub fn verify_staging_contained_relation_ineligible(
    raw: &[u8],
    pins: &StagingProductRelationPins<'_>,
    product: &Value,
    journal: &Value,
    file: &ContainedFileIdentity,
    native_sha256: &str,
) -> Result<Value> {
    if !matches!(
        pins.role,
        "success" | "input-binding" | "injection" | "boundary"
    ) || !is_sha256(native_sha256)
        || file.device == 0
        || file.inode == 0
        || journal["schema"] != EFFECT_IMAGE_JOURNAL_SCHEMA
        || journal["run_id"] != pins.run_id
        || journal["source_sha"] != pins.source_sha
        || journal["controller_public_key_hex"] != pins.controller_public_key_hex
        || journal["execution_eligible"] != false
        || journal["guard_causality_verified"] != false
    {
        return Err(INVALID);
    }
    let product_relation = verify_staging_product_relation_ineligible(raw, pins, product)?;
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let record: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    let key = decode_hex(pins.controller_public_key_hex, 32).map_err(|_| INVALID)?;
    let runtime =
        verify_controller_envelope(record["developer_runtime"].to_string().as_bytes(), &key)?;
    let builtin =
        verify_controller_envelope(runtime["native_builtin_audit"].to_string().as_bytes(), &key)?;
    let plane = &builtin["product_plane"];
    if plane["native_sha256"] != native_sha256
        || runtime["settings"]["private_cell"]["native_sha256"] != native_sha256
        || verify_contained_route_accounting(&builtin, plane)?["matched_routes"] != 1
        || verify_contained_output_custody(&builtin)? != 1
    {
        return Err(INVALID);
    }
    let execution = one(rows(&plane["executions"], 128)?, |_| true)?;
    let transport = rows(&builtin["transport_observations"], 4096)?;
    let pre = one(transport, |row| {
        row["kind"] == "actual-hook-response" && row["hook_event_name"] == "PreToolUse"
    })?;
    let post = one(transport, |row| {
        row["kind"] == "actual-hook-response" && row["hook_event_name"] == "PostToolUse"
    })?;
    let response = &pre["product_response"];
    let pre_sha = sha256(&canonical_value(response)?);
    let post_sha = sha256(&canonical_value(&post["product_response"])?);
    for row in [pre, post] {
        if row["tool_call_id"] != "sdk-contained-control"
            || row["tool_name"] != "bash"
            || row["controller_session_id"] != pins.role
            || !row["request_digest"].as_str().is_some_and(is_sha256)
        {
            return Err(INVALID);
        }
    }
    if execution["exit_code"].as_i64() != Some(0)
        || !execution["request_sha256"].as_str().is_some_and(is_sha256)
        || pre["payload_digest"] != execution["payload_digest"]
        || pre["original_input_digest"] != post["original_input_digest"]
        || !pre["original_input_digest"].as_str().is_some_and(is_sha256)
        || pre["contained_route_issued"] != true
        || post["contained_route_issued"] != false
        || pre["response_digest"] != pre_sha
        || post["response_digest"] != post_sha
        || response["decision"] != "deny"
        || response["policy_action"] != "sandbox-required"
        || response["required_execution_profile"] != "workspace-contained-v1"
        || response.get("observe_mode").is_some_and(|v| v != false)
        || !response["command_binding_digest"]
            .as_str()
            .is_some_and(is_sha256)
        || post["product_response"]["decision"] != "allow"
        || post["product_response"]["model_output_action"] != "allow_original"
        || post["product_response"]["reviewed_output_sha256"] != post["actual_output_sha256"]
    {
        return Err(INVALID);
    }
    for (row, event_name) in [(pre, "PreToolUse"), (post, "PostToolUse")] {
        let hook = one(rows(&plane["hooks"], 4096)?, |hook| {
            hook["hook_event_name"] == event_name
        })?;
        if hook["payload_digest"] != row["payload_digest"]
            || hook["response_digest"] != row["response_digest"]
            || hook["response"] != row["product_response"]
            || hook["returncode"].as_i64() != Some(0)
        {
            return Err(INVALID);
        }
    }
    let routes = rows(&builtin["contained_transport_observations"], 4096)?;
    let prepared = one(routes, |row| row["kind"] == "contained-route-prepared")?;
    if prepared["payload_digest"] != pre["payload_digest"]
        || prepared["native_response_digest"] != pre_sha
    {
        return Err(INVALID);
    }
    let writer = known_writer(journal, product, native_sha256, file)?;
    Ok(
        json!({"schema":"hol-gauntlet-staging-contained-relation.v1","run_id":pins.run_id,"role":pins.role,
        "source_sha":pins.source_sha,"record_sha256":sha256(raw),"native_sha256":native_sha256,
        "signed_product_relation":product_relation,"writer_relation":writer,
        "tool_call_id":"sdk-contained-control","signed_payload_digest":execution["payload_digest"],
        "signed_request_sha256":execution["request_sha256"],"signed_result_sha256":sha256(&canonical_value(execution)?),
        "signed_pre_response_sha256":pre_sha,"signed_post_response_sha256":post_sha,
        "signed_output_sha256":post["actual_output_sha256"],"signed_routes_matched":1,
        "request_to_writer_causality_verified":false,"guard_causality_verified":false,"execution_eligible":false}),
    )
}

pub fn observe_staging_contained_relation_root_owned_ineligible(
    pins: &StagingEvidencePins<'_>,
    product: &Value,
    journal: &Value,
    file: &ContainedFileIdentity,
) -> Result<Value> {
    let context = observe_staging_control_context(pins)?;
    let relation = verify_staging_contained_relation_ineligible(
        &context.raw,
        &StagingProductRelationPins {
            run_id: pins.run_id,
            role: pins.role,
            source_sha: pins.source_sha,
            controller_public_key_hex: pins.controller_public_key_hex,
        },
        product,
        journal,
        file,
        &context.native_sha256,
    )?;
    if context.opening.record_sha256 != pins.record_sha256
        || read_one(pins.run_id, pins.role)? != context.raw
    {
        return Err(INVALID);
    }
    Ok(relation)
}
