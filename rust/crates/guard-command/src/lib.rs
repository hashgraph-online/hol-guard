#![forbid(unsafe_code)]
pub mod action_lattice;
pub mod approval_reuse;
pub mod artifact_hash;
#[cfg(test)]
mod artifact_hash_tests;
mod artifact_hash_url;
#[cfg(test)]
mod artifact_hash_url_tests;
pub mod artifact_risk;
pub mod bash_approval;
pub mod benign_request_api;
pub mod browser_mcp_intent;
mod bundle_metadata;
pub mod business_gmail_plain;
pub mod business_gmail_wire;
pub mod business_gws_command;
pub mod business_input;
pub mod canonical_command;
pub mod catalog_prepare;
pub mod catalog_read_model;
#[cfg(test)]
mod catalog_read_model_tests;
mod catalog_read_projection;
mod catalog_read_query;
pub mod cloud_catalog;
pub mod cloud_scrub;
mod cloud_scrub_shell;
mod cloud_scrub_source_search;
mod codex_output_args;
mod codex_output_commands;
mod codex_output_entry;
mod codex_output_env;
pub mod command_action_risk_classes;
mod command_ascii_comparison;
mod command_candidate_common;
mod command_common_cli_matchers;
pub mod command_expression_match;
mod compound_artifact;
mod credential_store_names;
pub mod cursor_shell_command;
pub mod policy_document;
pub use codex_output_entry::{review_codex_tool_output, ToolOutputOutcome};
pub use codex_output_env::{Ctx, GitCheck, GitProbe, GitRun, InspectionHost};
pub mod codex_output_fnmatch;
mod codex_output_fs;
mod codex_output_git_conditions;
mod codex_output_git_config;
mod codex_output_git_diff;
mod codex_output_identity;
mod codex_output_inspection;
mod codex_output_inspection_flow;
mod codex_output_pathspecs;
mod codex_output_post_tool;
mod codex_output_post_tool_copy;
mod codex_output_post_tool_skips;
mod codex_output_post_tool_sources;
mod codex_output_py;
mod codex_output_search;
mod codex_output_shlex;
mod codex_output_source_paths;
mod codex_output_splitters;
mod codex_output_wrappers;
mod codex_prompt_attachment;
pub mod codex_prompt_credential_file;
pub mod command_compatibility;
mod command_contained_routine_candidates;
mod command_critical_floors;
#[cfg(test)]
mod command_critical_floors_tests;
mod command_database_matchers;
pub mod command_decision_adapter;
pub mod command_evaluation;
pub mod command_evaluation_compose;
pub mod command_evaluation_controls;
#[cfg(test)]
mod command_evaluation_lattice_tests;
pub(crate) mod command_evaluation_support;
#[cfg(test)]
mod command_evaluation_tests;
mod command_launcher_floors;
pub mod command_model;
pub mod command_native_factors;
mod command_operand_matchers;
pub mod command_option_parsing;
mod command_parse_surface;
mod command_segment_parsing;
pub mod command_shell_read_factors;
mod command_specialized_matchers;
mod command_structure;
mod command_structured_matchers;
mod command_tokens;
mod command_verified_read_candidates;
#[cfg(test)]
mod command_verified_read_candidates_tests;
mod command_workspace_write_candidates;
pub mod content_sensitivity;
pub mod contributed_mcp_decision;
mod contributed_mcp_url;
pub use contributed_mcp_url::normalized_remote_mcp_url;
mod data_flow;
pub mod dep_map;
pub mod effect_decision;
mod embedded_script_evidence;
#[cfg(test)]
mod embedded_script_evidence_tests;
mod env_wrapper;
mod executable_flag_contract;
pub mod extension_control;
pub mod extension_evidence;
pub mod extension_trust;
pub mod github_capability_contract;
#[cfg(test)]
mod github_capability_contract_tests;
mod github_capability_interaction;
pub mod github_command_capabilities;
#[cfg(test)]
mod github_command_capabilities_tests;
pub mod github_workflow_approval_record;
pub mod github_workflow_authorization;
pub mod github_workflow_descriptor;
pub mod github_workflow_lineage;
#[cfg(test)]
mod github_workflow_lineage_tests;
pub mod github_workflow_operations;
mod harness_config_names;
pub mod harness_identity;
mod home_path_text;
pub mod homebrew_intent;
mod inline_shell_quoting;
pub mod jsonc;
#[cfg(unix)]
pub mod launch_identity;
#[cfg(not(unix))]
#[path = "launch_identity_stub.rs"]
pub mod launch_identity;
#[cfg(unix)]
pub mod launch_identity_binding;
mod launch_identity_common;
pub mod launch_identity_environment;
#[cfg(windows)]
mod launch_identity_windows;
pub mod local_tool_eligibility;
pub mod mcp_arguments;
pub mod mcp_launch_environment;
pub mod mcp_runtime_evidence;
pub mod mcp_skill_firewall;
pub mod mcp_tool_approval;
pub mod mcp_tool_catalog;
pub mod mcp_tool_policy;
pub mod mcp_tool_risk;
pub mod mcp_tool_signals;
pub mod native_command_catalog;
pub mod native_command_controls;
pub mod native_command_extension_evidence;
#[cfg(test)]
mod native_command_extension_evidence_tests;
pub mod native_command_program;
pub mod network_url;
pub mod npm_source_spec;
pub mod ordered_json;
#[cfg(unix)]
pub mod package_context_build;
pub mod package_execution_context;
pub mod package_intent_common;
pub mod package_intent_parser;
pub mod package_manager_command;
pub mod package_manifest_diff;
#[cfg(not(guard_source_bootstrap))]
mod packaged_blob;
mod parser_brace_command;
mod parser_executables;
mod parser_segments;
mod parser_wrappers;
mod powershell_command;
mod powershell_effects;
mod powershell_floors;
mod powershell_parser;
mod powershell_reads;
pub mod protect_request;
pub mod pytest_argv;
mod read_only_fanout;
pub mod reviewed_invocation_bindings;
pub mod rich_command_model_api;
use parser_executables::*;
use parser_segments::*;
pub mod developer_inspection_authority;
pub mod environment_secret_dump;
pub mod pretool;
pub mod runtime_artifact_identity;
#[cfg(test)]
mod runtime_artifact_identity_tests;
mod runtime_read_paths;
pub mod secret_path_probe;
pub mod sensitive_request;
mod sfrs_agent_guidance;
mod sfrs_benign_reads;
mod sfrs_benign_tool_action;
mod sfrs_constants;
mod sfrs_credential_exfil;
mod sfrs_destructive;
mod sfrs_destructive_classifier;
#[cfg(all(test, unix))]
mod sfrs_destructive_vectors;
mod sfrs_developer_graph;
#[cfg(all(test, unix))]
mod sfrs_developer_graph_vectors;
mod sfrs_developer_inspection;
mod sfrs_developer_routines;
#[cfg(all(test, not(windows)))]
mod sfrs_developer_vectors;
mod sfrs_dispatcher;
mod sfrs_dispatcher_request;
#[cfg(all(test, unix))]
mod sfrs_dispatcher_vectors;
mod sfrs_docker_args;
#[cfg(all(test, not(windows)))]
mod sfrs_docker_vectors;
mod sfrs_encoded_commands;
mod sfrs_encoded_payloads;
mod sfrs_environment_secret;
mod sfrs_file_identity;
#[cfg(all(test, unix))]
mod sfrs_fs_vectors;
mod sfrs_gh_actions_env;
mod sfrs_gh_actions_filters;
mod sfrs_gh_actions_read;
mod sfrs_gh_bindings;
mod sfrs_gh_body_file;
mod sfrs_gh_body_file_check;
mod sfrs_gh_body_safety;
mod sfrs_gh_control_flow;
mod sfrs_gh_definitions;
mod sfrs_gh_environment;
mod sfrs_gh_ephemeral_body;
mod sfrs_gh_pr_expansion;
mod sfrs_gh_pyshim;
mod sfrs_gh_redirections;
mod sfrs_gh_service;
mod sfrs_gh_shell;
#[cfg(all(test, not(windows)))]
mod sfrs_gh_shell_vectors;
mod sfrs_gh_static_body_safety;
mod sfrs_git_audit;
mod sfrs_git_cached_diff;
mod sfrs_git_fetch;
mod sfrs_git_index;
mod sfrs_git_routines;
#[cfg(all(test, unix))]
mod sfrs_github_body_vectors;
#[cfg(all(test, not(windows)))]
mod sfrs_github_vectors;
#[cfg(all(test, unix))]
mod sfrs_host_divergence;
#[cfg(all(test, unix))]
mod sfrs_index_vectors;
mod sfrs_interpreter_heredoc;
mod sfrs_interpreter_identity;
mod sfrs_interpreter_launch;
mod sfrs_interpreter_observers;
mod sfrs_interpreter_scripts;
mod sfrs_interpreter_trust;
#[cfg(all(test, unix))]
mod sfrs_interpreter_vectors;
mod sfrs_jq;
mod sfrs_json;
mod sfrs_kubernetes_commands;
mod sfrs_kubernetes_cp;
mod sfrs_kubernetes_heredoc;
mod sfrs_kubernetes_heredoc_scan;
mod sfrs_kubernetes_options;
mod sfrs_kubernetes_support;
#[cfg(test)]
mod sfrs_kubernetes_vectors;
#[cfg(all(test, unix))]
mod sfrs_leaf_vectors;
#[cfg(all(test, unix))]
mod sfrs_net_vectors;
mod sfrs_network_upload;
mod sfrs_node_heredoc;
mod sfrs_node_redaction;
mod sfrs_node_templates;
#[cfg(all(test, unix))]
mod sfrs_node_vectors;
mod sfrs_node_workflows;
mod sfrs_path_word_lookups;
mod sfrs_patterns;
mod sfrs_perl_read_only;
#[cfg(all(test, unix))]
mod sfrs_pr_expansion_vectors;
mod sfrs_pytest_binary;
mod sfrs_pytest_config;
mod sfrs_pytest_config_ini;
mod sfrs_pytest_config_read;
mod sfrs_pytest_config_safety;
mod sfrs_pytest_config_search;
mod sfrs_pytest_config_toml;
mod sfrs_pytest_config_value;
mod sfrs_pytest_env;
mod sfrs_pytest_target;
#[cfg(all(test, unix))]
mod sfrs_pytest_vectors;
mod sfrs_pytest_wrappers;
mod sfrs_python_imports;
mod sfrs_quote_parsing;
mod sfrs_quote_tokens;
#[cfg(all(test, unix))]
mod sfrs_quote_vectors;
#[cfg(test)]
mod sfrs_read_only_filter_tests;
mod sfrs_read_only_filters;
pub mod sfrs_replay;
mod sfrs_replay_context;
mod sfrs_request_data;
mod sfrs_requests;
mod sfrs_routine_dirs;
mod sfrs_routine_move;
mod sfrs_routine_setup;
mod sfrs_routines_support;
#[cfg(all(test, unix))]
mod sfrs_routines_vectors;
mod sfrs_search_filters;
mod sfrs_selectors;
mod sfrs_self_approval;
mod sfrs_sensitive_pipeline;
mod sfrs_shell_classifier;
mod sfrs_shell_classifier_context;
mod sfrs_shell_initial_risk;
mod sfrs_shell_tokens;
mod sfrs_shlex;
mod sfrs_source_edit;
mod sfrs_source_edit_context;
mod sfrs_static_safety;
#[cfg(all(test, not(windows)))]
mod sfrs_static_vectors;
mod sfrs_stdin_sources;
mod sfrs_substitution;
#[cfg(test)]
mod sfrs_token_vectors;
mod sfrs_tool_request;
mod sfrs_typescript_graphql;
mod sfrs_upload_arguments;
mod shell_command_wrappers;
pub mod shell_execution_context;
mod shell_execution_context_support;
pub mod shell_helpers;
mod shell_model_limits;
mod shell_read_literal_wrapper;
pub mod shell_request_authority;
#[cfg(test)]
mod shell_secret_read_containment_tests;
mod shell_secret_read_flow;
#[cfg(test)]
mod shell_secret_read_script_operand_tests;
mod shell_secret_read_support;
pub mod shell_secret_reads;
mod shell_structure;
pub mod source_cli;
pub mod tool_action_identity;
#[cfg(test)]
mod tool_action_identity_tests;
pub mod typescript_launch_evidence;
#[cfg(test)]
#[path = "../../../test_support/unique_nanos.rs"]
mod unique_nanos;
mod unmodeled_shell_artifact;

pub mod package_context_environment;

mod critical_floor_context;
pub use command_evaluation::CompositeCommandEvaluation;
pub use command_evaluation_compose::{evaluate_command, CommandEvaluationInput};
pub use command_model::parse_shell_command;
// Modules that `use super::*` resolve these names through the root, so rustc
// cannot see this re-export as used; removing it breaks those consumers.
#[allow(unused_imports)]
pub(crate) use command_parse_surface::{
    default_dialect, default_provenance, default_transport, is_fd_dup_redirect,
    parse_command_unbound, parse_explicit_powershell, parse_inline_shell_script,
    parse_posix_command, uncertain, Quote, RawSegment,
};
pub use command_parse_surface::{
    parse_command, CanonicalCommandV1, CommandModelRequestV1, CommandSegmentV1, CommandSpanV1,
    MAX_COMMAND_BYTES, MAX_COMMAND_SEGMENTS, MAX_COMMAND_TOKENS,
};
pub use critical_floor_context::critical_floor_action;

#[cfg(test)]
#[path = "powershell_parser_tests.rs"]
mod powershell_parser_tests;
#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;

// RTM-019 pending modules — compile signal only until legs complete
pub mod audit_receipt;
pub mod cloud_audit_sync;
pub mod guard_run_launch;
pub mod install_time_event;
pub mod local_supply_chain;
#[cfg(test)]
mod local_supply_chain_risk_action_tests;
#[cfg(test)]
mod local_supply_chain_saved_claim_tests;
#[cfg(test)]
mod local_supply_chain_stale_policy_tests;
#[cfg(test)]
mod local_supply_chain_timestamp_tests;
pub mod package_approval;
#[cfg(test)]
mod package_intent_exact_decode_tests;
pub mod package_policy_override;
pub mod package_protect_projection;
mod package_shim_invocation;
#[cfg(test)]
mod package_shim_invocation_tests;
pub mod prompt_analysis;
pub mod redacted_command_tokens;
pub mod supply_chain_package_eval;
pub mod target_identities;
pub mod workspace_inventory;
#[cfg(test)]
mod workspace_path_guard_tests;

// RTM-014/017/020/023 pending modules — compile signal only until legs complete.
pub mod aibom_reporting;
pub mod aibom_trust_metadata;
pub mod archive_inspection;
pub mod command_operation_classification;
pub mod composition_rules;
pub mod contained_argv;
#[cfg(unix)]
pub mod contained_execution;
#[cfg(unix)]
pub mod contained_runner;
pub mod credential_patterns;
pub mod data_flow_request_artifact;
pub mod data_flow_rules;
pub mod decisions;
pub mod detectors;
pub mod direct_vitest;
mod egress_archive;
pub mod egress_broker;
pub mod egress_caller;
pub mod egress_caller_archive;
pub mod egress_caller_policy;
pub mod egress_proxy_credentials;
mod egress_spool;
pub mod false_positive_rules;
pub mod guard_sync_transport;
#[path = "adapters/hook/hook_adapter_envelope.rs"]
pub mod hook_adapter_envelope;
#[path = "adapters/hook/hook_adapter_envelope_tables.rs"]
mod hook_adapter_envelope_tables;
#[path = "adapters/hook/hook_adapter_envelope_text.rs"]
mod hook_adapter_envelope_text;
#[cfg(test)]
#[path = "adapters/hook/hook_adapter_omp_tests.rs"]
mod hook_adapter_omp_tests;
#[path = "adapters/hook/hook_adapter_paths.rs"]
pub mod hook_adapter_paths;
use guard_hook_payload::{hook_adapter_cline_tables, hook_adapter_pyjson, hook_adapter_pytext};
pub use guard_hook_payload::{
    hook_adapter_prepare, hook_adapter_prepare_cline, hook_adapter_value,
};
#[path = "adapters/hook/hook_adapter_redact.rs"]
mod hook_adapter_redact;
#[path = "adapters/hook/hook_adapter_secret_path.rs"]
mod hook_adapter_secret_path;
#[cfg(all(test, unix))]
#[path = "adapters/hook/hook_adapter_vector_tests.rs"]
mod hook_adapter_vector_tests;
mod hook_evidence_deferred_post;
pub mod hook_evidence_writer;
#[cfg(test)]
mod hook_evidence_writer_tests;
pub mod hook_responses;
pub mod inventory_agent_types;
pub mod inventory_contract;
#[cfg(test)]
mod inventory_contract_tests;
pub mod inventory_fingerprints;
pub mod inventory_item_metadata;
pub mod inventory_path_redaction;
pub mod inventory_redaction;
pub mod js_semver;
pub mod linux_artifact_supply_chain;
#[cfg(any(unix, windows))]
pub mod local_mcp_stdio;
#[cfg(all(unix, test))]
mod local_mcp_stdio_tests;
pub mod mcp_decision;
mod mcp_package_sources;
#[cfg(any(unix, windows))]
pub mod mcp_stdio_session;
pub mod pep440;
pub mod persistence_rules;
mod python_netloc;
mod python_url;
pub mod registry_metadata_transport;
pub mod restricted_archive;
mod restricted_archive_address;
mod restricted_archive_destination;
mod restricted_archive_peer;
mod restricted_archive_stream;
pub mod restricted_archive_transport;
mod restricted_archive_write;
pub mod restricted_command;
#[cfg(unix)]
pub mod restricted_pytest;
pub mod resume_template;
pub mod safe_decode;
#[cfg(unix)]
pub mod sandbox;
#[cfg(unix)]
pub(crate) mod semantic_workspace;
pub mod shims;
pub mod signals;
pub mod skill_content_risk;
pub mod skill_dependency_manifest;
pub mod skill_identity;
pub mod strict_json;
pub mod supply_chain_bundle;
pub mod supply_chain_package_identity;
pub mod supply_chain_risk;
pub mod supply_chain_support;
pub mod verified_npm;
pub mod verified_read_decision;
#[cfg(test)]
mod verified_read_decision_tests;
