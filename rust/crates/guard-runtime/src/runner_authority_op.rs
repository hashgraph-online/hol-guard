//! `RunnerAuthority` — resident op owning the `guard run` authority
//! transforms (see `guard_contracts::runner_authority`).
//!
//! Every kind is a deterministic function of its arguments (the `aibom_*`
//! kinds also read the workspace files they are pointed at) and
//! reuses the same authoritative-decision, action-lattice and approval-token
//! code the rest of the resident runs, so there is one rule set. Python ships
//! typed inputs, applies the returned patch and never recomputes an action,
//! reason or signature. Failures are typed `error` results; the caller must
//! treat them as a refusal to launch, never as an allow.

use guard_contracts::{
    RunnerAuthorityRequestV1, RunnerAuthorityResultV1, RUNNER_AUTHORITY_MAX_BYTES,
    RUNNER_AUTHORITY_REQUEST_SCHEMA, RUNNER_AUTHORITY_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::aibom_op as aibom;
use super::antigravity_detect;
use super::claude_code_detect;
use super::claude_hook_config;
use super::cline_detect;
use super::cline_hook_files;
use super::cline_plugin_render;
use super::codex_detect;
use super::context_digest_json::write_canonical_json_with_limit;
use super::copilot_detect;
use super::copilot_hook_config;
use super::cursor_detect;
use super::cursor_editor_plan;
use super::cursor_hook_config;
use super::cursor_hook_state;
use super::devin_detect;
use super::devin_jsonc;
use super::gemini_detect;
use super::grok_detect;
use super::grok_legacy_settings;
use super::grok_user_config_op;
use super::harness_hook_settings;
use super::hermes_detect;
use super::kimi_detect;
use super::kimi_hook_config;
use super::muse_detect;
use super::oci_bundle_op as oci;
use super::openclaw_detect;
use super::opencode_detect;
use super::opencode_install_plan;
use super::opencode_plugin_render;
use super::pi_detect;
use super::pi_extension_render;
use super::runner_authority_signature as signature;
use super::zcode_detect;
use super::zcode_hook_settings;
use super::{
    cloud_receipt_payload as receipt, cloud_request_snapshot as snapshot,
    cloud_sync_privacy as privacy,
};
use super::{runner_authority_detector as detector, runner_authority_evaluation as evaluation};
use super::{
    runner_sync_policy as policy, runner_sync_signals as signals, runner_sync_url as sync_url,
};

pub(crate) const ERR_INVALID: &str = "native_runner_authority_invalid";
const ERR_SCHEMA: &str = "native_runner_authority_schema_mismatch";
pub(crate) const ERR_TOO_LARGE: &str = "native_runner_authority_request_too_large";
const ERR_RESPONSE_TOO_LARGE: &str = "native_runner_authority_response_too_large";
const ERR_KIND: &str = "native_runner_authority_unknown_kind";

/// Result of one kind: its payload, or a stable failure code.
pub(crate) type KindResult = Result<Value, &'static str>;

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
fn request_digest(request: &RunnerAuthorityRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(4096);
    if write_canonical_json_with_limit(&material, &mut canonical, RUNNER_AUTHORITY_MAX_BYTES)
        .is_err()
    {
        return Err(if canonical.len() > RUNNER_AUTHORITY_MAX_BYTES {
            ERR_TOO_LARGE
        } else {
            ERR_INVALID
        });
    }
    if canonical.len() > RUNNER_AUTHORITY_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    match kind {
        "approval_wait_hint" => crate::blocked_request_mode::wait_hint_projection(args),
        "approval_link" => crate::approval_link::dispatch(args),
        "runtime_cloud_status" => crate::runtime_cloud_status::dispatch(args),
        "runtime_headline" => crate::runtime_headline::dispatch(args),
        "developer_inspection_authority" => {
            crate::developer_inspection_authority_op::dispatch(args)
        }
        "continuation_authority" => crate::continuation_authority_op::evaluate(args),
        "projection_approval"
        | "projection_receipt"
        | "projection_surfaces"
        | "projection_surfaces_batch"
        | "projection_artifact_surfaces" => crate::signal_projection_op::dispatch(kind, args),
        "decision_v2_decode"
        | "decision_enforcement_decode"
        | "decision_authoritative_decode"
        | "decision_artifact_decode"
        | "decision_legacy"
        | "decision_build" => crate::decision_authority_op::dispatch(kind, args),
        "cli_runtime_support" => crate::cli_runtime_support_op::dispatch(args),
        "approval_copy" => crate::approval_copy::dispatch(args),
        "workspace_assessment_build" | "workspace_assessment_fit" => {
            crate::workspace_assessment_sync::dispatch(kind, args)
        }
        "workspace_audit_sync" => crate::workspace_audit_sync::dispatch(args),
        "workspace_runtime_findings" => crate::workspace_runtime_findings::dispatch(args),
        "shell_request_authority" => crate::shell_request_authority_op::dispatch(args),
        "guard_product_copy" => crate::guard_product_copy::dispatch(args),
        "consumer_mode_contract" => crate::consumer_mode_contract::dispatch(args),
        "surface_server_handshake" => crate::surface_server_handshake::dispatch(args),
        "trust_attestation_shape" => crate::trust_attestation_shape::dispatch(args),
        "detector_authority" => detector::detector_authority(args),
        "detector_composition" => detector::detector_composition(args),
        "skill_content_risk" => detector::skill_content_risk(args),
        "current_authority_actions" => detector::current_authority_actions(args),
        "request_overrides" => detector::request_overrides(args),
        "claim_partition" => detector::claim_partition(args),
        "apply_detector_result" => evaluation::apply_detector_result(args),
        "preclaim_failure" => evaluation::preclaim_failure(args),
        "claim_context_failure" => evaluation::claim_context_failure(args),
        "receipt_evidence_merge" => evaluation::receipt_evidence_merge(args),
        "authority_signature" => signature::authority_signature(args),
        "authority_gate" => signature::authority_gate(args),
        "policy_shadow_mismatch" => signature::policy_shadow_mismatch(args),
        "sync_url" => sync_url::sync_url(args),
        "insights_share_payload" => crate::insights_share_payload::dispatch(args),
        "cloud_http_error" => super::runner_cloud_http_error::cloud_http_error(args),
        "network_check" => crate::network_protection::check_op(args),
        "pain_signal_batch" => signals::pain_signal_batch(args),
        "value_metrics" => signals::value_metrics(args),
        "completed_event_ids" => signals::completed_event_ids(args),
        "cloud_exceptions" => crate::runner_cloud_exceptions::cloud_exceptions(args),
        "runtime_session_payload" => crate::runner_runtime_session::runtime_session_payload(args),
        "stale_intel" => signals::stale_intel(args),
        "canonical_rollout" => policy::canonical_rollout(args),
        "downgrade_reference" => policy::downgrade_reference(args),
        "policy_simulation" => policy::policy_simulation(args),
        "paseo_providers" => crate::paseo_providers::dispatch(args),
        "remote_mcp_origins" => crate::remote_mcp_origins::dispatch(args),
        "cloud_scrub_texts" => privacy::cloud_scrub_texts(args),
        "cloud_review_event_display" => privacy::cloud_review_event_display(args),
        "cloud_sync_receipt_payloads" => receipt::cloud_sync_receipt_payloads(args),
        "cloud_request_payload" => snapshot::cloud_request_payload(args),
        "local_request_snapshot" => snapshot::local_request_snapshot(args),
        "supply_chain_audit_workspace_dir" => crate::supply_chain_audit_workspace::dispatch(args),
        "temporary_mcp_grant" => crate::temporary_mcp_grant::dispatch(args),
        "local_request_snapshot_items" => snapshot::local_request_snapshot_items(args),
        "package_manager_launch_path" => crate::package_manager_launch_path::dispatch(args),
        "oci_bundle_evidence" => oci::oci_bundle_evidence(args),
        "oci_evidence_verdict" => oci::oci_evidence_verdict(args),
        "oci_bundle_digest" => oci::oci_bundle_digest(args),
        "oci_bundle_plan" => oci::oci_bundle_plan(args),
        "aibom_trust_claims" => crate::aibom_trust_claims::dispatch(args),
        "aibom_workspace_artifacts" => aibom::workspace_artifacts(args),
        "aibom_workspace_plan" => aibom::workspace_merge_plan(args),
        "aibom_codex_skills" => aibom::codex_skills(args),
        "aibom_mcp_metadata" => aibom::mcp_metadata(args),
        "aibom_primary_content" => crate::aibom_primary_content::dispatch(args),
        "package_command_redaction" => crate::package_command_redaction::dispatch(args),
        "zcode_detect" => zcode_detect::detect(args),
        "zcode_hook_settings" => zcode_hook_settings::dispatch(args),
        "hermes_detect" => hermes_detect::detect(args),
        "pi_detect" => pi_detect::detect(args),
        "cline_plugin_render" => cline_plugin_render::render(args),
        "cline_hook_files" => cline_hook_files::dispatch(args),
        "pi_extension_render" => pi_extension_render::render(args),
        "codex_detect" => codex_detect::detect(args),
        "copilot_detect" => copilot_detect::detect(args),
        "copilot_hook_config" => copilot_hook_config::dispatch(args),
        "claude_code_detect" => claude_code_detect::detect(args),
        "claude_hook_config" => claude_hook_config::dispatch(args),
        "cline_detect" => cline_detect::detect(args),
        "gemini_detect" => gemini_detect::detect(args),
        "antigravity_detect" => antigravity_detect::detect(args),
        "devin_detect" => devin_detect::detect(args),
        "devin_jsonc" => devin_jsonc::document(args),
        "harness_hook_settings" => harness_hook_settings::dispatch(args),
        "harness_mcp_discovery" => crate::harness_mcp_discovery::dispatch(args),
        "grok_detect" => grok_detect::detect(args),
        "grok_legacy_settings" => grok_legacy_settings::dispatch(args),
        "grok_user_config" => grok_user_config_op::dispatch(args),
        "kimi_detect" => kimi_detect::detect(args),
        "kimi_hook_config" => kimi_hook_config::dispatch(args),
        "muse_detect" => muse_detect::detect(args),
        "openclaw_detect" => openclaw_detect::detect(args),
        "cursor_detect" => cursor_detect::detect(args),
        "cursor_hook_config" => cursor_hook_config::dispatch(args),
        "cursor_editor_plan" => cursor_editor_plan::plan(args),
        "cursor_hook_state" => cursor_hook_state::dispatch(args),
        "opencode_detect" => opencode_detect::detect(args),
        "opencode_plugin_render" => opencode_plugin_render::render(args),
        "opencode_install_plan" => opencode_install_plan::dispatch(args),
        _ => Err(ERR_KIND),
    }
}

fn evaluate(request: &RunnerAuthorityRequestV1) -> KindResult {
    if request.schema != RUNNER_AUTHORITY_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    match request.kind.as_str() {
        // Kinds that write under the Guard home take the home the resident
        // verified for this request, never one from their arguments.
        "package_firewall_refresh_claim" => {
            crate::package_firewall_refresh::dispatch(&request.args, &request.guard_home)
        }
        _ => dispatch(&request.kind, &request.args),
    }
}

pub(crate) fn evaluate_runner_authority(
    request: &RunnerAuthorityRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&RunnerAuthorityResultV1 {
                schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256: String::new(),
                status: "error".to_owned(),
                code: code.to_owned(),
                payload: None,
            });
        }
    };
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    let encoded = crate::encode_response(&RunnerAuthorityResultV1 {
        schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.clone(),
        status,
        code,
        payload,
    });
    // The request bound (4 MiB) is wider than the resident response bound
    // (2 MiB). A result past that bound is this op's own typed refusal, never
    // a bare transport error and never a partial answer.
    match encoded {
        Err(reason) if reason == "native_response_too_large" => {
            crate::encode_response(&RunnerAuthorityResultV1 {
                schema: RUNNER_AUTHORITY_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256,
                status: "error".to_owned(),
                code: ERR_RESPONSE_TOO_LARGE.to_owned(),
                payload: None,
            })
        }
        other => other,
    }
}

#[cfg(test)]
#[path = "runner_authority_op_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runner_sync_tests.rs"]
mod sync_tests;
