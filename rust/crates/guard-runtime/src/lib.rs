#![forbid(unsafe_code)]
#![recursion_limit = "512"]

mod active_pack_security;
#[path = "adapters/adapter_inventory.rs"]
mod adapter_inventory;
#[cfg(all(test, unix))]
#[path = "adapters/adapter_vectors_tests.rs"]
mod adapter_vectors_tests;
mod aibom_artifact;
mod aibom_discovery;
mod aibom_extend;
mod aibom_marketplace;
mod aibom_mcp_metadata;
mod aibom_op;
mod aibom_paths;
mod aibom_report_summaries_op;
mod aibom_skill_rules;
mod aibom_skills;
mod aibom_symlink;
#[cfg(all(test, unix))]
mod aibom_vectors_tests;
#[path = "adapters/detection/antigravity_detect.rs"]
mod antigravity_detect;
mod approval;
mod approval_bulk_eligibility_op;
mod approval_extension_recommendation_op;
mod approval_gate_consumers;
mod approval_gate_enrollment;
mod approval_gate_grants;
mod approval_gate_op;
mod approval_gate_settings;
mod approval_gate_state;
mod approval_gate_verify;
mod approval_persist_select_op;
mod approval_proof_op;
mod approval_queue_identity_op;
mod approval_resolution_eligibility_op;
mod approval_resolution_plan_op;
mod approval_reuse;
mod approval_reuse_diagnostic_op;
mod approval_reuse_diagnostic_probes;
#[cfg(test)]
mod approval_reuse_diagnostic_vectors_tests;
mod approval_scope_contract;
mod approval_scope_material;
mod approval_scope_op;
mod approval_scope_select_op;
mod archive_acquisition_op;
mod archive_inspect;
mod archive_inspect_containment;
mod archive_verdict_seam;
mod artifact_content_hash_op;
mod artifact_risk_op;
mod bash_post_delivery;
#[cfg(unix)]
mod binding_capture_capture;
#[cfg(unix)]
mod binding_capture_crypto;
#[cfg(unix)]
mod binding_capture_fs;
#[cfg(unix)]
mod binding_capture_join;
#[cfg(unix)]
mod binding_capture_json;
#[cfg(unix)]
mod binding_capture_op;
#[cfg(unix)]
mod binding_capture_receipt;
#[cfg(unix)]
mod binding_capture_record;
#[cfg(all(test, unix))]
mod binding_capture_vectors_tests;
mod blocked_request_mode;
mod bounded_hook_bridge;
mod bounded_hook_bridge_grok;
mod bounded_hook_bridge_grok_render;
mod bounded_hook_bridge_grok_script;
mod bounded_hook_bridge_hermes;
mod bounded_hook_bridge_render;
mod browser_open;
#[cfg(test)]
mod bundle_parse_reuse_tests;
mod business_document_compile;
mod business_source_codec;
mod cisco_containment;
mod cisco_evidence;
mod cisco_plan;
mod cisco_preflight_op;
#[cfg(test)]
mod cisco_preflight_vectors_tests;
mod claim_approval_reuse_op;
#[cfg(test)]
mod claim_consume_local_once_tests;
mod claim_reuse;
mod claim_reuse_binding;
#[cfg(test)]
mod claim_reuse_binding_tests;
#[cfg(test)]
mod claim_reuse_then_tests;
#[cfg(test)]
mod claim_reuse_vectors_tests;
mod claude_code_config;
#[path = "adapters/detection/claude_code_detect.rs"]
mod claude_code_detect;
#[cfg(all(test, unix))]
mod claude_code_vectors_tests;
mod claude_guard_question;
mod claude_hook_bridge;
mod claude_hook_bridge_auth;
#[cfg(windows)]
mod claude_hook_bridge_auth_windows;
#[cfg(all(test, unix))]
mod claude_hook_bridge_fixture;
mod claude_hook_bridge_http;
mod claude_hook_bridge_http_text;
mod claude_hook_bridge_render;
mod claude_hook_bridge_transport;
mod claude_hook_bridge_url;
mod claude_session_start;
mod claude_session_start_contract;
mod claude_session_start_live;
mod cli_copilot_resolution;
mod cli_runtime_support_op;
mod cloud_action_envelope;
mod cloud_action_envelope_fields;
mod cloud_receipt_payload;
#[cfg(test)]
mod cloud_receipt_vectors_tests;
mod cloud_request_payload;
mod cloud_request_snapshot;
mod cloud_request_text;
#[cfg(test)]
mod cloud_request_vectors_tests;
mod cloud_sync_privacy;
mod codex_app_server_socket;
#[path = "adapters/detection/codex_detect.rs"]
mod codex_detect;
mod codex_hook_artifacts;
mod codex_hook_bridge;
mod codex_hook_bridge_direct;
mod codex_hook_bridge_direct_resident;
mod codex_hook_bridge_transport;
mod codex_hook_identity;
mod codex_hook_response;
mod codex_hooks;
mod codex_identity;
#[cfg(all(test, unix))]
mod codex_post_tool_output_vectors_tests;
mod codex_proxy;
mod codex_request_resume_busy;
mod codex_request_resume_op;
mod codex_request_resume_store;
mod codex_sources;
mod codex_thread_continue_op;
mod codex_tool_output_git;
mod codex_tool_output_op;
#[cfg(all(test, unix))]
mod codex_tool_output_vectors_tests;
mod codex_value;
#[cfg(all(test, unix))]
mod codex_vectors_tests;
mod command_effect;
mod command_expression_validate_op;
mod command_policy_decide_op;
mod command_policy_repair;
mod composio_role_op;
mod compound_git_args;
mod compound_git_chain;
mod compound_git_facts;
#[cfg(test)]
mod compound_git_facts_tests;
mod compound_git_inspection_op;
#[cfg(test)]
mod compound_git_inspection_op_tests;
#[cfg(all(test, unix))]
mod compound_git_inspection_vectors_tests;
mod compound_git_paths;
mod compound_git_segments;
mod connector_setup;
mod connector_setup_context_op;
mod consumer_artifact_compose_op;
mod consumer_artifact_compose_runtime;
mod consumer_artifact_project_op;
mod consumer_capabilities;
mod consumer_capability_delta;
mod consumer_evidence;
mod consumer_incident;
mod consumer_result;
mod consumer_url;
#[cfg(unix)]
mod contained_op;
#[cfg(unix)]
mod contained_workspace_grant_plan;
#[cfg(unix)]
mod contained_workspace_sink;
mod content_sensitivity_op;
mod context_digest;
mod context_digest_json;
mod context_digest_local_cli;
mod context_digest_package_scripts;
mod context_digest_result_check;
mod continuation_authority_op;
mod continuation_grants;
mod continuation_lineage;
mod continuation_metadata;
mod continuation_store;
#[cfg(test)]
mod contributed_mcp_catalog_test_support;
mod contributed_mcp_decision_op;
#[path = "adapters/detection/copilot_detect.rs"]
mod copilot_detect;
#[cfg(all(test, unix))]
mod copilot_vectors_tests;
mod critical_floor_op;
#[path = "adapters/detection/cursor_detect.rs"]
mod cursor_detect;
mod cursor_hook_bridge;
mod cursor_hook_bridge_response;
mod cursor_hook_bridge_script;
mod cursor_observer_proof_op;
mod custom_extension_continuity;
mod custom_extension_suggestion;
mod daemon_handler_digits;
mod daemon_handler_fields;
mod daemon_handler_headless;
mod daemon_handler_op;
mod daemon_handler_policy;
mod daemon_handler_requests;
mod daemon_lifecycle_claims;
mod daemon_lifecycle_command;
mod daemon_lifecycle_decision_op;
mod daemon_lifecycle_facts;
mod daemon_lifecycle_inventory;
mod daemon_lifecycle_malformed;
mod daemon_lifecycle_ports;
mod daemon_lifecycle_state;
mod daemon_lifecycle_text;
#[cfg(test)]
mod daemon_lifecycle_unit_tests;
#[cfg(test)]
mod daemon_lifecycle_vectors_tests;
mod daemon_policy_authority;
mod daemon_route_op;
mod daemon_route_paths;
mod daemon_route_resolve;
mod daemon_route_session;
mod data_flow_analyze_op;
mod decision_authority_op;
#[cfg(test)]
mod decision_authority_vectors_tests;
mod delivery_object;
mod developer_inspection_authority_op;
mod developer_inspection_host;
#[path = "adapters/detection/devin_detect.rs"]
mod devin_detect;
mod direct_tool_context_op;
#[cfg(test)]
mod direct_tool_context_tests;
mod direct_tool_managed_bun;
mod directory_trust;
mod discovery_placement_op;
mod edge;
mod edge_git_push;
mod encrypted_secret_store;
mod extension_allow_hint_op;
mod extension_control_authority_op;
mod extension_control_mutation_op;
mod extension_control_op;
mod extension_control_prepared_op;
mod extension_control_preview_op;
mod extension_control_proof;
#[path = "adapters/detection/gemini_detect.rs"]
mod gemini_detect;
mod git_execution_safety_binary;
mod git_execution_safety_checks;
mod git_execution_safety_config;
mod git_execution_safety_op;
mod git_execution_safety_probe;
#[cfg(all(test, unix))]
mod git_execution_safety_repo_tests;
#[cfg(test)]
mod git_execution_safety_tests;
mod github_cli_classify_op;
mod github_workflow_context_io;
mod github_workflow_prepare_op;
#[path = "adapters/detection/grok_detect.rs"]
mod grok_detect;
mod guard_config_coerce;
mod guard_config_harness;
mod guard_config_iso;
mod guard_config_load;
mod guard_config_managed;
mod guard_config_update;
mod guard_config_update_coerce;
mod guard_config_update_harness;
mod guard_config_update_settings;
mod guard_config_update_value;
mod guard_paths;
mod guard_store_advisory_cache;
#[cfg(test)]
mod guard_store_advisory_cache_vectors_tests;
mod guard_store_approval_backfill;
mod guard_store_approval_created;
mod guard_store_approval_metadata;
mod guard_store_approval_page_reads;
mod guard_store_approval_queue;
mod guard_store_approval_queue_item;
mod guard_store_approval_queue_result;
mod guard_store_approval_read_rows;
mod guard_store_approval_read_scope;
mod guard_store_approval_reads;
mod guard_store_approval_request;
mod guard_store_approval_resolve;
mod guard_store_approval_row;
mod guard_store_approval_sweep;
mod guard_store_approval_write;
mod guard_store_args;
mod guard_store_claude_review;
mod guard_store_clients;
mod guard_store_cmd_activity;
mod guard_store_cmd_api;
mod guard_store_cmd_feedback;
mod guard_store_cmd_lifecycle;
mod guard_store_cmd_maintenance;
mod guard_store_cmd_privacy;
#[cfg(test)]
mod guard_store_cmd_read_vectors_tests;
mod guard_store_cmd_rollups;
#[cfg(test)]
mod guard_store_cmd_vectors_tests;
mod guard_store_cmd_wire;
mod guard_store_composio_catalog;
#[cfg(test)]
mod guard_store_composio_catalog_tests;
mod guard_store_connect;
mod guard_store_connect_effective;
#[cfg(test)]
mod guard_store_connect_vectors_tests;
mod guard_store_connector_context;
mod guard_store_db;
mod guard_store_guard_event;
#[cfg(test)]
mod guard_store_guard_event_tests;
mod guard_store_inventory;
#[cfg(test)]
mod guard_store_inventory_page_tests;
#[cfg(test)]
mod guard_store_inventory_vectors_tests;
mod guard_store_json;
mod guard_store_lineage;
mod guard_store_local_cli;
#[cfg(test)]
mod guard_store_local_cli_grant_vectors_tests;
mod guard_store_local_cli_grants;
#[cfg(test)]
mod guard_store_local_cli_vectors_tests;
mod guard_store_local_mcp_declarations;
mod guard_store_local_mcp_observation;
mod guard_store_native_receipts;
#[cfg(test)]
mod guard_store_native_receipts_tests;
mod guard_store_native_review_consume;
#[cfg(test)]
mod guard_store_native_review_consume_tests;
mod guard_store_observed_mcp;
mod guard_store_op;
mod guard_store_outbox_append;
mod guard_store_outbox_binding;
mod guard_store_outbox_decode;
mod guard_store_outbox_identity;
mod guard_store_outbox_queries;
mod guard_store_outbox_reads;
#[cfg(test)]
mod guard_store_outbox_reads_tests;
mod guard_store_outbox_recover;
mod guard_store_outbox_requeue;
mod guard_store_policy_source_context;
#[cfg(test)]
mod guard_store_policy_source_context_vectors_tests;
mod guard_store_policy_source_labels;
mod guard_store_policy_source_rows;
mod guard_store_receipt_analytics;
mod guard_store_receipt_approval;
mod guard_store_receipt_decision;
mod guard_store_receipt_envelope;
mod guard_store_receipt_events;
mod guard_store_receipt_reads;
mod guard_store_receipt_rollups;
mod guard_store_receipt_writes;
#[cfg(test)]
mod guard_store_receipts_vectors_tests;
mod guard_store_sessions;
#[cfg(test)]
mod guard_store_sessions_vectors_tests;
mod guard_store_silent_review;
mod guard_store_state_ops;
#[cfg(test)]
mod guard_store_state_ops_vectors_tests;
mod guard_store_storage_maintenance;
#[cfg(test)]
mod guard_store_storage_maintenance_vectors_tests;
mod guard_store_tool_call_evidence;
#[cfg(test)]
mod guard_store_tool_call_evidence_tests;
#[cfg(test)]
mod guard_store_vectors_tests;
mod guard_store_wfcap_authority;
mod guard_store_wfcap_claim;
mod guard_store_wfcap_contract;
mod guard_store_wfcap_control;
mod guard_store_wfcap_ctx;
mod guard_store_wfcap_error;
mod guard_store_wfcap_frame;
mod guard_store_wfcap_ledger;
mod guard_store_wfcap_ops;
mod guard_store_wfcap_schema;
mod guard_store_wfcap_schema_sql;
mod guard_store_wfcap_state;
mod guard_store_wfcap_wire;
#[cfg(test)]
mod guard_store_workflow_capability_vectors_tests;
mod guard_store_write_cache;
mod hardening;
#[path = "adapters/detection/hermes_detect.rs"]
mod hermes_detect;
mod hermes_inspect;
mod hermes_printable;
mod hermes_skills;
mod hermes_text;
#[cfg(all(test, unix))]
mod hermes_vectors_tests;
mod hermes_yaml;
mod hermes_yaml_construct;
mod hermes_yaml_resolve;
#[path = "adapters/hook_adapter_op.rs"]
mod hook_adapter_op;
mod hook_approval_context;
mod hook_artifact_compose_op;
mod hook_artifact_compose_package_firewall;
mod hook_artifact_compose_package_firewall_entitlement;
mod hook_artifact_compose_policy_lookup;
mod hook_artifact_compose_policy_tail;
mod hook_artifact_compose_prompt;
mod hook_artifact_compose_reuse;
mod hook_artifact_facts_op;
mod hook_authority_state_op;
mod hook_bridge_daemon_start;
mod hook_bridge_fallback;
mod hook_cli_claude_text;
#[cfg(test)]
mod hook_decision_apply_patch_gate_tests;
mod hook_decision_artifact_directive;
mod hook_decision_artifact_finalize;
mod hook_decision_artifact_reuse_step;
mod hook_decision_artifact_review_route;
#[cfg(all(test, unix))]
mod hook_decision_benign_tool_action_tests;
mod hook_decision_claude_permission_verdict;
mod hook_decision_compose;
mod hook_decision_containment_route;
mod hook_decision_directive;
mod hook_decision_finalize;
mod hook_decision_hook_route;
mod hook_decision_native_facts;
#[cfg(all(test, unix))]
mod hook_decision_native_facts_tests;
mod hook_decision_native_permission_persist;
mod hook_decision_op;
mod hook_decision_pretool_floor;
mod hook_decision_settle;
mod hook_direct;
mod hook_direct_counters;
mod hook_direct_evidence;
mod hook_env_stamp;
#[cfg(all(test, unix))]
mod mcp_config_discovery_tests;
mod pack_lifecycle;
mod pack_preparation;
// The seams the evidence writer runs on. Each is reached through
// hook_evidence_writer_op; the readers also have their own tests.
mod codex_hook_identity_op;
mod command_pack_record_op;
#[allow(dead_code)]
mod hook_evidence_activity;
#[allow(dead_code)]
mod hook_evidence_composio;
#[allow(dead_code)]
mod hook_evidence_correlation;
#[allow(dead_code)]
mod hook_evidence_store;
#[allow(dead_code)]
mod hook_evidence_store_gate;
#[allow(dead_code)]
mod hook_evidence_store_timeout;
#[allow(dead_code)]
mod hook_evidence_store_wire;
mod hook_evidence_writer_op;
mod hook_path_rules;
mod hook_policy_config;
mod hook_process_spawn;
mod hook_render_op;
mod inventory_item_classification_op;
mod inventory_scan_findings_op;
mod inventory_scan_targets_op;
mod inventory_snapshot_digest_op;
mod inventory_source_evidence_op;
mod inventory_url_redaction_op;
#[path = "adapters/detection/kimi_detect.rs"]
mod kimi_detect;
mod local_cli_grant_op;
mod local_cli_hook_contained;
mod local_cli_hook_op;
mod local_cli_identify;
mod local_mcp_grant_identity;
mod local_mcp_grant_launcher;
mod local_mcp_grant_op;
mod local_once_store;
mod local_store_read;
mod local_tool_eligibility_op;
mod managed_controls_policy_fields;
mod managed_policy;
mod managed_policy_file_trust;
mod managed_policy_floor;
mod managed_policy_load;
mod managed_policy_plist;
mod managed_policy_registry;
mod managed_resident;
mod mcp_classification_op;
mod mcp_probe_op;
mod mcp_proxy_actions;
mod mcp_proxy_archive;
#[cfg(test)]
mod mcp_proxy_archive_vectors_tests;
mod mcp_proxy_archive_verify;
#[cfg(all(test, unix))]
mod mcp_proxy_archive_verify_tests;
mod mcp_proxy_catalog;
mod mcp_proxy_decision_op;
#[cfg(test)]
mod mcp_proxy_decision_tests;
#[cfg(test)]
mod mcp_proxy_decision_vectors_tests;
mod mcp_proxy_inline_approval;
mod mcp_proxy_package;
mod mcp_proxy_postclaim;
mod mcp_proxy_projection;
#[cfg(test)]
mod mcp_proxy_projection_vectors_tests;
mod mcp_proxy_route;
mod mcp_proxy_shlex;
mod mcp_proxy_signals;
mod mcp_relay;
mod mcp_relay_args;
mod mcp_relay_authority;
mod mcp_relay_catalog;
mod mcp_relay_claims;
mod mcp_relay_core;
mod mcp_relay_decide;
mod mcp_relay_host;
mod mcp_relay_lane;
mod mcp_relay_launch;
mod mcp_relay_order;
mod mcp_relay_package_eval;
mod mcp_relay_pending;
mod mcp_relay_ready;
mod mcp_relay_resident;
mod mcp_relay_servers;
mod mcp_runtime_evidence_op;
mod mcp_sensitive_read;
#[cfg(test)]
mod mcp_sensitive_read_artifact_tests;
#[cfg(test)]
mod mcp_sensitive_read_vectors_tests;
mod mcp_stdio_session_op;
mod mcp_tool_call_identity_build;
mod mcp_tool_call_identity_op;
mod mcp_tool_evidence_op;
mod mcp_tool_policy_composio;
mod mcp_tool_policy_connector;
mod mcp_tool_policy_decide_op;
mod mcp_tool_policy_decision;
mod mcp_tool_policy_extension;
mod mcp_tool_policy_flow;
mod mcp_tool_policy_grants;
mod mcp_tool_policy_lookup;
mod mcp_tool_policy_proxy;
mod mcp_tool_policy_revalidate;
mod memory_pattern;
#[cfg(target_os = "macos")]
mod native_bash_client;
mod native_bash_reply_validation;
mod native_bash_review_descriptor;
mod native_bash_review_scope;
mod native_decision_receipt;
mod native_exact_action_op;
mod native_hook_receipt;
mod native_review_link;
mod native_runtime_admission;
mod native_runtime_resilience;
mod network_protection;
mod oauth_refresh;
mod oauth_secret_authority;
mod oci_bundle_evidence;
mod oci_bundle_mounts;
mod oci_bundle_op;
#[cfg(test)]
mod oci_bundle_vectors_tests;
mod oci_path;
mod omp_yield_input_scan;
mod oneshot;
#[path = "adapters/detection/openclaw_detect.rs"]
mod openclaw_detect;
#[cfg(all(test, unix))]
#[path = "adapters/detection/openclaw_detect_tests.rs"]
mod openclaw_detect_tests;
mod openclaw_mcp;
mod openclaw_skills;
#[path = "adapters/detection/opencode_detect.rs"]
mod opencode_detect;
mod package_approval_hash_op;
mod package_audit_projection_op;
mod package_authority_config;
mod package_authority_op;
mod package_context_build_op;
mod package_evaluation_compose_op;
mod package_evaluation_view_op;
mod package_policy_resolve_op;
mod package_posture_op;
mod package_protect_finalize_op;
mod package_protect_projection_op;
mod persistence_action_class;
#[path = "adapters/detection/pi_detect.rs"]
mod pi_detect;
mod pi_glob;
mod pi_hook_bridge;
#[cfg(all(test, unix))]
mod pi_vectors_tests;
#[cfg(test)]
use guard_policy_bundle::delivery as policy_bundle_delivery;
use guard_policy_bundle::{
    families as policy_bundle_families, json as policy_bundle_json, keys as policy_bundle_keys,
    python as policy_bundle_py, time as policy_bundle_time,
};
mod policy_bundle_op;
#[cfg(test)]
mod policy_bundle_transport_tests;
mod policy_decision_lookup_op;
mod policy_document_decide_op;
mod policy_document_op;
mod policy_effective;
mod policy_enforcement;
mod policy_integrity_generation;
mod policy_integrity_resolver;
mod policy_integrity_rows_op;
mod policy_lookup_groups;
mod policy_lookup_local_tool_grant;
mod policy_lookup_portable;
mod policy_lookup_reuse;
mod policy_runtime_saved;
mod policy_runtime_saved_reuse;
mod policy_snapshot_build;
mod policy_store;
mod pre_tool_extension_evidence_op;
mod project_identity;
mod prompt_analyze_op;
mod protect_request_op;
use guard_runtime_pyjson as pyjson;
#[cfg(test)]
mod registry_vectors_tests;
mod release_feed_op;
mod request_context_op;
mod request_context_shell;
mod resident_client;
mod resident_diagnostics;
mod resident_endpoint;
mod resident_inspection_services;
mod resident_op_features;
mod resident_ops;
#[allow(dead_code)] // Worker enrollment is not enabled by this OS identity input.
mod resident_peer_identity;
mod resident_process_identity;
mod resident_protocol;
mod resident_runtime_verification;
mod resident_state;
mod resident_state_encoding;
mod resident_transport;
mod resident_transport_service;
mod resident_update_lock;
mod restricted_linux_launch;
mod restricted_process_ceiling;
mod restricted_pytest_op;
mod reviewed_invocation_bindings_op;
mod rich_command_model_op;
mod runner_authority_detector;
mod runner_authority_evaluation;
mod runner_authority_op;
mod runner_authority_signature;
mod runner_sync_policy;
mod runner_sync_signals;
mod runner_sync_url;
mod runtime_artifact_identity_op;
mod runtime_cli;
mod runtime_detector_run_op;
mod secrets_cli;
mod sensitive_request_op;
#[cfg(all(test, unix))]
#[allow(dead_code, clippy::pedantic)]
#[path = "../../guard-command/tests/sfrs_support/mod.rs"]
mod sfrs_support;
mod shell_helpers_op;
mod shell_request_authority_op;
mod shell_request_inspection_host;
mod shim_op;
mod signal_projection_approval;
mod signal_projection_decode;
mod signal_projection_op;
mod signal_projection_receipt;
#[cfg(test)]
mod signal_projection_vectors_tests;
mod skill_directory_identity_op;
mod skill_identity_canon;
mod skill_identity_discovery;
mod skill_identity_inspect;
mod skill_identity_platform;
mod skill_identity_walk;
mod skill_workflow_preflight_op;
#[cfg(unix)]
mod state_directory_lock;
#[cfg(test)]
mod store_vectors_support_tests;
mod strict_json;
#[cfg(test)]
mod supply_chain_cloud_vectors_tests;
mod supply_chain_egress;
mod supply_chain_eval_caller;
mod supply_chain_eval_rounds;
mod supply_chain_eval_seams;
mod supply_chain_eval_transport;
mod tool_action_identity_op;
mod totp;
#[cfg(test)]
#[path = "../../../test_support/unique_nanos.rs"]
mod unique_nanos;
mod verified_npm_op;
mod verified_read_decision_op;
mod verified_read_plan_op;
#[cfg(windows)]
mod windows_node_build;
#[cfg(windows)]
mod windows_pytest;
#[cfg(windows)]
mod windows_readonly;
mod workspace_inventory_files;
mod workspace_inventory_op;
mod workspace_scan_targets;
mod zcode_artifacts;
#[path = "adapters/detection/zcode_detect.rs"]
mod zcode_detect;
#[cfg(all(test, unix))]
mod zcode_vectors_tests;

pub(crate) use resident_protocol::{capabilities, encode_response, strict_json_value};
pub(crate) use resident_transport::{
    constant_time_eq, hmac_sha256, BoxedResidentStream, ResidentStream,
};
pub(crate) use resident_transport_service::{
    read_resident_auth_token, resident_stdin_liveness, serve, serve_loopback,
};

pub(crate) use guard_contracts::{MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES};
use std::env;
use std::io::{self, Read, Write};
use std::time::Duration;

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const RESIDENT_PROTOCOL_VERSION: u8 = 2;
const REQUEST_MAGIC: &[u8; 4] = b"HGR2";
const RESPONSE_MAGIC: &[u8; 4] = b"HGS2";
const FRAME_REQUEST_ID_BYTES: usize = 32;
const FRAME_DIGEST_BYTES: usize = 32;
const FRAME_HEADER_BYTES: usize = 4 + FRAME_REQUEST_ID_BYTES + FRAME_DIGEST_BYTES + 4;
const AUTH_TOKEN_BYTES: usize = 32;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_PROOF_BYTES: usize = 32;
const AUTH_WORKERS: usize = 4;
const AUTH_QUEUE_CAPACITY: usize = 32;
const AUTH_QUEUE_CAPACITY_MAX: usize = 64;
const EVALUATION_WORKERS: usize = 16;
const EVALUATION_QUEUE_CAPACITY: usize = 32;
const AUTHENTICATED_PREFETCH_BYTES: usize = 64 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_millis(250);
const HEADER_TIMEOUT: Duration = Duration::from_millis(250);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_PROOF_LABEL: &[u8] = b"hol-guard-resident-server-v1\0";
const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\0";
#[cfg(unix)]
const PARENT_LIVENESS_FD_ENV: &str = "HOL_GUARD_PARENT_LIVENESS_FD";

pub(crate) fn evaluation_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(EVALUATION_WORKERS, 32))
        .unwrap_or(EVALUATION_WORKERS)
}

pub(crate) fn auth_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 4).clamp(AUTH_WORKERS, 8))
        .unwrap_or(AUTH_WORKERS)
}

pub(crate) fn evaluation_queue_capacity() -> usize {
    evaluation_workers()
        .saturating_mul(2)
        .clamp(EVALUATION_QUEUE_CAPACITY, 64)
}

pub(crate) fn auth_queue_capacity() -> usize {
    auth_workers()
        .saturating_mul(8)
        .clamp(AUTH_QUEUE_CAPACITY, AUTH_QUEUE_CAPACITY_MAX)
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| hardening::read_error(&error, "native_request_read_failed"))?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    Ok(bytes)
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

fn write_bytes_response(response: &[u8]) -> Result<(), String> {
    io::stdout()
        .write_all(response)
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|error| hardening::write_error(&error, "native_response_write_failed"))?;
    Ok(())
}

fn run() -> Result<(), String> {
    runtime_cli::run()
}

/// Launch the runtime binary: argument dispatch, panic hook, then `run`.
pub fn launch() {
    // The runtime also hosts the declarative source-compiler front end so the
    // wheel ships a single native binary. Dispatch before the panic hook so
    // compiler behavior (including its own exit paths) stays identical.
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(windows)]
    if windows_readonly::is_command(&arguments) {
        std::process::exit(windows_readonly::main(&arguments));
    }
    if guard_command::source_cli::is_command(&arguments) {
        std::process::exit(guard_command::source_cli::main(arguments));
    }
    std::panic::set_hook(Box::new(|_| eprintln!("native_runtime_panicked")));
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_hmac_matches_cross_language_vectors() {
        let token = [7u8; AUTH_TOKEN_BYTES];
        let nonce = [9u8; AUTH_NONCE_BYTES];
        let server = hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce);
        let client = hmac_sha256(&token, CLIENT_PROOF_LABEL, &nonce);
        assert_eq!(
            server,
            [
                0xb8, 0x19, 0x89, 0x8f, 0x11, 0x87, 0x8c, 0x1c, 0x14, 0x84, 0x23, 0xd0, 0x36, 0x1a,
                0x9d, 0xe2, 0x0d, 0x9e, 0xca, 0x3b, 0xb8, 0x6c, 0xe1, 0x21, 0x4c, 0xee, 0x95, 0x7f,
                0x95, 0xbb, 0x06, 0xc4,
            ]
        );
        assert_eq!(
            client,
            [
                0xfe, 0xf8, 0x3d, 0x9f, 0xf5, 0x98, 0x89, 0x22, 0xef, 0x5c, 0x4c, 0x7b, 0x54, 0xd9,
                0xc6, 0x66, 0xab, 0xf4, 0x2f, 0xdf, 0xa8, 0x39, 0x44, 0x8b, 0x57, 0x9f, 0x65, 0x07,
                0x41, 0xd0, 0x6d, 0x97,
            ]
        );
        assert_ne!(server, client);
        assert!(constant_time_eq(&server, &server));
        assert!(!constant_time_eq(&server, &client));
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_trailing_values() {
        assert!(strict_json_value(br#"{"a":1,"a":2}"#).is_err());
        assert!(strict_json_value(br#"{"a":1} {}"#).is_err());
    }

    #[test]
    fn strict_json_preserves_numeric_fields_and_literal_serde_marker_objects() {
        let parsed = strict_json_value(
            br#"{"timeout_seconds":6.0,"fraction":0.125,"maximum":1208925819614629174706177,"literal":{"$serde_json::private::Number":"123"}}"#,
        )
        .unwrap();
        assert_eq!(parsed["timeout_seconds"].as_f64(), Some(6.0));
        assert_eq!(parsed["fraction"].as_f64(), Some(0.125));
        assert_eq!(
            parsed["maximum"].as_number().unwrap().as_str(),
            "1208925819614629174706177"
        );
        assert_eq!(parsed["literal"]["$serde_json::private::Number"], "123");
        assert!(strict_json_value(br#"{"value":1e999}"#).is_err());
        assert!(strict_json_value(br#"{"name":1,"name":2}"#).is_err());
    }

    #[test]
    fn strict_json_rejects_deep_and_wide_values() {
        let deep = format!(
            "{}0{}",
            "[".repeat(strict_json::TEST_MAX_JSON_DEPTH + 2),
            "]".repeat(strict_json::TEST_MAX_JSON_DEPTH + 2)
        );
        assert!(strict_json_value(deep.as_bytes()).is_err());
        let wide = format!(
            "[{}]",
            std::iter::repeat_n("0", strict_json::TEST_MAX_JSON_COLLECTION_ITEMS + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(strict_json_value(wide.as_bytes()).is_err());
    }

    #[test]
    fn strict_json_carries_strings_up_to_the_operation_request_bound() {
        let catalog_capacity_overflow =
            format!("{{\"description\":\"{}\"}}", "x".repeat(2_000_001));
        let parsed = strict_json_value(catalog_capacity_overflow.as_bytes()).unwrap();
        assert_eq!(
            parsed["description"].as_str().map(str::len),
            Some(2_000_001)
        );
        let over_cap = format!(
            "{{\"description\":\"{}\"}}",
            "x".repeat(strict_json::TEST_MAX_JSON_STRING_BYTES + 1)
        );
        assert_eq!(
            strict_json_value(over_cap.as_bytes()).unwrap_err(),
            "native_json_string_too_large"
        );
    }

    #[test]
    fn overload_response_is_constant_and_retryable() {
        assert_eq!(
            resident_protocol::error_response("native_overloaded", true),
            b"{\"error\":\"native_overloaded\",\"retryable\":true}".to_vec()
        );
    }

    #[test]
    fn resident_hmac_changes_with_nonce() {
        let token = [3u8; AUTH_TOKEN_BYTES];
        let mut first_nonce = [1u8; AUTH_NONCE_BYTES];
        let second_nonce = [2u8; AUTH_NONCE_BYTES];
        let first = hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce);
        let second = hmac_sha256(&token, SERVER_PROOF_LABEL, &second_nonce);
        assert_ne!(first, second);
        first_nonce[0] ^= 1;
        assert_ne!(first, hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce));
    }

    #[test]
    fn resident_worker_pools_scale_within_bounds() {
        let evaluation = super::evaluation_workers();
        let auth = super::auth_workers();
        assert!((EVALUATION_WORKERS..=32).contains(&evaluation));
        assert!((AUTH_WORKERS..=8).contains(&auth));
        assert!((EVALUATION_QUEUE_CAPACITY..=64).contains(&super::evaluation_queue_capacity()));
        assert!(
            (AUTH_QUEUE_CAPACITY..=AUTH_QUEUE_CAPACITY_MAX).contains(&super::auth_queue_capacity())
        );
    }
}
