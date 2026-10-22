//! Host-side compile surface for the command catalog compiler. The lib
//! root reaches only the modules that `native_command_program` and
//! `source_cli` import, path-mounting the production sources instead of
//! copying any lowering or admission algorithm. `command_parse_surface`
//! carries the crate-root model and parser entry points that reachable
//! modules import through `crate::` paths.
#![forbid(unsafe_code)]
// This unit is a reachability mirror: reachable modules legitimately keep
// public items that only the production crate's wider surface calls.
#![allow(dead_code, unused_imports)]

#[path = "../../guard-command/src/action_lattice.rs"]
pub mod action_lattice;
#[path = "../../guard-command/src/approval_reuse.rs"]
pub mod approval_reuse;
#[path = "../../guard-command/src/audit_receipt.rs"]
pub mod audit_receipt;
#[path = "../../guard-command/src/bundle_metadata.rs"]
mod bundle_metadata;
#[path = "../../guard-command/src/canonical_command.rs"]
pub mod canonical_command;
#[path = "../../guard-command/src/catalog_prepare.rs"]
pub mod catalog_prepare;
#[path = "../../guard-command/src/catalog_read_model.rs"]
pub mod catalog_read_model;
#[path = "../../guard-command/src/catalog_read_projection.rs"]
mod catalog_read_projection;
#[path = "../../guard-command/src/catalog_read_query.rs"]
mod catalog_read_query;
#[path = "../../guard-command/src/cloud_audit_sync.rs"]
pub mod cloud_audit_sync;
#[path = "../../guard-command/src/cloud_scrub_shell.rs"]
mod cloud_scrub_shell;
#[path = "../../guard-command/src/codex_output_args.rs"]
mod codex_output_args;
#[path = "../../guard-command/src/codex_output_env.rs"]
mod codex_output_env;
#[path = "../../guard-command/src/codex_output_fnmatch.rs"]
pub mod codex_output_fnmatch;
#[path = "../../guard-command/src/codex_output_fs.rs"]
mod codex_output_fs;
#[path = "../../guard-command/src/codex_output_py.rs"]
mod codex_output_py;
#[path = "../../guard-command/src/codex_output_search.rs"]
mod codex_output_search;
#[path = "../../guard-command/src/codex_output_shlex.rs"]
mod codex_output_shlex;
#[path = "../../guard-command/src/codex_output_source_paths.rs"]
mod codex_output_source_paths;
#[path = "../../guard-command/src/command_ascii_comparison.rs"]
mod command_ascii_comparison;
#[path = "../../guard-command/src/command_common_cli_matchers.rs"]
mod command_common_cli_matchers;
#[path = "../../guard-command/src/command_compatibility.rs"]
pub mod command_compatibility;
#[path = "../../guard-command/src/command_critical_floors.rs"]
mod command_critical_floors;
#[path = "../../guard-command/src/command_database_matchers.rs"]
mod command_database_matchers;
#[path = "../../guard-command/src/command_launcher_floors.rs"]
mod command_launcher_floors;
#[path = "../../guard-command/src/command_model.rs"]
pub mod command_model;
#[path = "../../guard-command/src/command_operand_matchers.rs"]
mod command_operand_matchers;
#[path = "../../guard-command/src/command_option_parsing.rs"]
pub mod command_option_parsing;
#[path = "../../guard-command/src/command_segment_parsing.rs"]
mod command_segment_parsing;
#[path = "../../guard-command/src/command_specialized_matchers.rs"]
mod command_specialized_matchers;
#[path = "../../guard-command/src/command_structure.rs"]
mod command_structure;
#[path = "../../guard-command/src/command_structured_matchers/mod.rs"]
mod command_structured_matchers;
#[path = "../../guard-command/src/command_tokens.rs"]
mod command_tokens;
#[path = "../../guard-command/src/contained_argv.rs"]
pub mod contained_argv;
#[cfg(unix)]
#[path = "../../guard-command/src/contained_runner/mod.rs"]
pub mod contained_runner;
#[path = "../../guard-command/src/contributed_mcp_decision.rs"]
pub mod contributed_mcp_decision;
#[path = "../../guard-command/src/contributed_mcp_url.rs"]
mod contributed_mcp_url;
#[path = "../../guard-command/src/credential_patterns.rs"]
pub mod credential_patterns;
#[path = "../../guard-command/src/credential_store_names.rs"]
mod credential_store_names;
#[path = "../../guard-command/src/critical_floor_context.rs"]
mod critical_floor_context;
#[path = "../../guard-command/src/data_flow.rs"]
mod data_flow;
#[path = "../../guard-command/src/data_flow_rules.rs"]
pub mod data_flow_rules;
#[path = "../../guard-command/src/dep_map.rs"]
pub mod dep_map;
#[path = "../../guard-command/src/detectors.rs"]
pub mod detectors;
#[path = "../../guard-command/src/direct_vitest.rs"]
pub mod direct_vitest;
#[path = "../../guard-command/src/effect_decision.rs"]
pub mod effect_decision;
#[path = "../../guard-command/src/egress_archive.rs"]
mod egress_archive;
#[path = "../../guard-command/src/egress_broker.rs"]
pub mod egress_broker;
#[path = "../../guard-command/src/egress_spool.rs"]
mod egress_spool;
#[path = "../../guard-command/src/env_wrapper.rs"]
mod env_wrapper;
#[path = "../../guard-command/src/environment_secret_dump.rs"]
pub mod environment_secret_dump;
#[path = "../../guard-command/src/executable_flag_contract.rs"]
mod executable_flag_contract;
#[path = "../../guard-command/src/extension_control.rs"]
pub mod extension_control;
#[path = "../../guard-command/src/false_positive_rules.rs"]
pub mod false_positive_rules;
#[path = "../../guard-command/src/github_capability_contract.rs"]
pub mod github_capability_contract;
#[path = "../../guard-command/src/github_capability_interaction.rs"]
mod github_capability_interaction;
#[path = "../../guard-command/src/github_command_capabilities.rs"]
pub mod github_command_capabilities;
#[path = "../../guard-command/src/github_workflow_authorization.rs"]
pub mod github_workflow_authorization;
#[path = "../../guard-command/src/github_workflow_operations.rs"]
pub mod github_workflow_operations;
#[path = "../../guard-command/src/guard_sync_transport.rs"]
pub mod guard_sync_transport;
#[path = "../../guard-command/src/harness_config_names.rs"]
mod harness_config_names;
#[path = "../../guard-command/src/harness_identity.rs"]
pub mod harness_identity;
#[path = "../../guard-command/src/home_path_text.rs"]
mod home_path_text;
#[path = "../../guard-command/src/homebrew_intent.rs"]
pub mod homebrew_intent;
#[path = "../../guard-command/src/inline_shell_quoting.rs"]
mod inline_shell_quoting;
#[path = "../../guard-command/src/install_time_event.rs"]
pub mod install_time_event;
#[path = "../../guard-command/src/jsonc.rs"]
pub mod jsonc;
#[cfg(unix)]
#[path = "../../guard-command/src/launch_identity.rs"]
pub mod launch_identity;
#[cfg(not(unix))]
#[path = "../../guard-command/src/launch_identity_stub.rs"]
pub mod launch_identity;
#[path = "../../guard-command/src/launch_identity_common.rs"]
mod launch_identity_common;
#[cfg(windows)]
#[path = "../../guard-command/src/launch_identity_windows.rs"]
mod launch_identity_windows;
#[path = "../../guard-command/src/local_supply_chain.rs"]
pub mod local_supply_chain;
#[path = "../../guard-command/src/native_command_catalog.rs"]
pub mod native_command_catalog;
#[path = "../../guard-command/src/native_command_controls.rs"]
pub mod native_command_controls;
#[path = "../../guard-command/src/native_command_program.rs"]
pub mod native_command_program;
#[path = "../../guard-command/src/network_url.rs"]
pub mod network_url;
#[path = "../../guard-command/src/npm_source_spec.rs"]
pub mod npm_source_spec;
#[path = "../../guard-command/src/ordered_json.rs"]
pub mod ordered_json;
#[path = "../../guard-command/src/package_approval.rs"]
pub mod package_approval;
#[path = "../../guard-command/src/package_execution_context.rs"]
pub mod package_execution_context;
#[path = "../../guard-command/src/package_intent_common.rs"]
pub mod package_intent_common;
#[path = "../../guard-command/src/package_intent_parser.rs"]
pub mod package_intent_parser;
#[path = "../../guard-command/src/package_manager_command.rs"]
pub mod package_manager_command;
#[path = "../../guard-command/src/package_manifest_diff.rs"]
pub mod package_manifest_diff;
#[path = "../../guard-command/src/package_policy_override.rs"]
pub mod package_policy_override;
#[path = "../../guard-command/src/package_protect_projection.rs"]
pub mod package_protect_projection;
#[path = "../../guard-command/src/package_shim_invocation.rs"]
mod package_shim_invocation;
#[cfg(not(guard_source_bootstrap))]
#[path = "../../guard-command/src/packaged_blob.rs"]
mod packaged_blob;
#[path = "../../guard-command/src/parser_brace_command.rs"]
mod parser_brace_command;
#[path = "../../guard-command/src/parser_executables.rs"]
mod parser_executables;
#[path = "../../guard-command/src/parser_segments.rs"]
mod parser_segments;
#[path = "../../guard-command/src/parser_wrappers.rs"]
mod parser_wrappers;
#[path = "../../guard-command/src/powershell_command.rs"]
mod powershell_command;
#[path = "../../guard-command/src/powershell_effects.rs"]
mod powershell_effects;
#[path = "../../guard-command/src/powershell_floors.rs"]
mod powershell_floors;
#[path = "../../guard-command/src/powershell_parser.rs"]
mod powershell_parser;
#[path = "../../guard-command/src/powershell_reads.rs"]
mod powershell_reads;
#[path = "../../guard-command/src/pretool/mod.rs"]
pub mod pretool;
#[path = "../../guard-command/src/prompt_analysis.rs"]
pub mod prompt_analysis;
#[path = "../../guard-command/src/pytest_argv.rs"]
pub mod pytest_argv;
#[path = "../../guard-command/src/read_only_fanout.rs"]
mod read_only_fanout;
#[path = "../../guard-command/src/redacted_command_tokens.rs"]
pub mod redacted_command_tokens;
#[path = "../../guard-command/src/runtime_read_paths.rs"]
mod runtime_read_paths;
#[path = "../../guard-command/src/secret_path_probe.rs"]
pub mod secret_path_probe;
#[path = "../../guard-command/src/sfrs_constants.rs"]
mod sfrs_constants;
#[path = "../../guard-command/src/sfrs_developer_graph.rs"]
mod sfrs_developer_graph;
#[path = "../../guard-command/src/sfrs_developer_inspection.rs"]
mod sfrs_developer_inspection;
#[path = "../../guard-command/src/sfrs_docker_args.rs"]
mod sfrs_docker_args;
#[path = "../../guard-command/src/sfrs_file_identity.rs"]
mod sfrs_file_identity;
#[path = "../../guard-command/src/sfrs_gh_bindings.rs"]
mod sfrs_gh_bindings;
#[path = "../../guard-command/src/sfrs_gh_body_file.rs"]
mod sfrs_gh_body_file;
#[path = "../../guard-command/src/sfrs_gh_body_file_check.rs"]
mod sfrs_gh_body_file_check;
#[path = "../../guard-command/src/sfrs_gh_body_safety.rs"]
mod sfrs_gh_body_safety;
#[path = "../../guard-command/src/sfrs_gh_control_flow.rs"]
mod sfrs_gh_control_flow;
#[path = "../../guard-command/src/sfrs_gh_definitions.rs"]
mod sfrs_gh_definitions;
#[path = "../../guard-command/src/sfrs_gh_environment.rs"]
mod sfrs_gh_environment;
#[path = "../../guard-command/src/sfrs_gh_pr_expansion.rs"]
mod sfrs_gh_pr_expansion;
#[path = "../../guard-command/src/sfrs_gh_pyshim.rs"]
mod sfrs_gh_pyshim;
#[path = "../../guard-command/src/sfrs_gh_redirections.rs"]
mod sfrs_gh_redirections;
#[path = "../../guard-command/src/sfrs_gh_service.rs"]
mod sfrs_gh_service;
#[path = "../../guard-command/src/sfrs_gh_shell.rs"]
mod sfrs_gh_shell;
#[path = "../../guard-command/src/sfrs_gh_static_body_safety.rs"]
mod sfrs_gh_static_body_safety;
#[path = "../../guard-command/src/sfrs_git_cached_diff.rs"]
mod sfrs_git_cached_diff;
#[path = "../../guard-command/src/sfrs_git_index.rs"]
mod sfrs_git_index;
#[path = "../../guard-command/src/sfrs_interpreter_scripts.rs"]
mod sfrs_interpreter_scripts;
#[path = "../../guard-command/src/sfrs_jq.rs"]
mod sfrs_jq;
#[path = "../../guard-command/src/sfrs_json.rs"]
mod sfrs_json;
#[path = "../../guard-command/src/sfrs_kubernetes_options.rs"]
mod sfrs_kubernetes_options;
#[path = "../../guard-command/src/sfrs_kubernetes_support.rs"]
mod sfrs_kubernetes_support;
#[path = "../../guard-command/src/sfrs_node_redaction.rs"]
mod sfrs_node_redaction;
#[path = "../../guard-command/src/sfrs_path_word_lookups.rs"]
mod sfrs_path_word_lookups;
#[path = "../../guard-command/src/sfrs_patterns.rs"]
mod sfrs_patterns;
#[path = "../../guard-command/src/sfrs_pytest_target.rs"]
mod sfrs_pytest_target;
#[path = "../../guard-command/src/sfrs_python_imports.rs"]
mod sfrs_python_imports;
#[path = "../../guard-command/src/sfrs_quote_parsing.rs"]
mod sfrs_quote_parsing;
#[path = "../../guard-command/src/sfrs_quote_tokens.rs"]
mod sfrs_quote_tokens;
#[path = "../../guard-command/src/sfrs_read_only_filters.rs"]
mod sfrs_read_only_filters;
#[path = "../../guard-command/src/sfrs_request_data.rs"]
mod sfrs_request_data;
#[path = "../../guard-command/src/sfrs_requests.rs"]
mod sfrs_requests;
#[path = "../../guard-command/src/sfrs_search_filters.rs"]
mod sfrs_search_filters;
#[path = "../../guard-command/src/sfrs_selectors.rs"]
mod sfrs_selectors;
#[path = "../../guard-command/src/sfrs_shell_tokens.rs"]
mod sfrs_shell_tokens;
#[path = "../../guard-command/src/sfrs_shlex.rs"]
mod sfrs_shlex;
#[path = "../../guard-command/src/sfrs_source_edit.rs"]
mod sfrs_source_edit;
#[path = "../../guard-command/src/sfrs_source_edit_context.rs"]
mod sfrs_source_edit_context;
#[path = "../../guard-command/src/sfrs_static_safety.rs"]
mod sfrs_static_safety;
#[path = "../../guard-command/src/sfrs_substitution.rs"]
mod sfrs_substitution;
#[path = "../../guard-command/src/sfrs_tool_request.rs"]
mod sfrs_tool_request;
#[path = "../../guard-command/src/shell_command_wrappers.rs"]
mod shell_command_wrappers;
#[path = "../../guard-command/src/shell_execution_context.rs"]
pub mod shell_execution_context;
#[path = "../../guard-command/src/shell_execution_context_support.rs"]
mod shell_execution_context_support;
#[path = "../../guard-command/src/shell_model_limits.rs"]
mod shell_model_limits;
#[path = "../../guard-command/src/shell_secret_read_support.rs"]
mod shell_secret_read_support;
#[path = "../../guard-command/src/shell_structure.rs"]
mod shell_structure;
#[path = "../../guard-command/src/source_cli.rs"]
pub mod source_cli;
#[path = "../../guard-command/src/supply_chain_package_eval.rs"]
pub mod supply_chain_package_eval;
#[path = "../../guard-command/src/target_identities.rs"]
pub mod target_identities;
#[path = "../../guard-command/src/typescript_launch_evidence.rs"]
pub mod typescript_launch_evidence;
#[path = "../../guard-command/src/workspace_inventory.rs"]
pub mod workspace_inventory;
use guard_hook_payload::{
    hook_adapter_cline_tables, hook_adapter_prepare_cursor, hook_adapter_pyjson,
    hook_adapter_pytext,
};
pub use guard_hook_payload::{
    hook_adapter_prepare, hook_adapter_prepare_cline, hook_adapter_value,
};

#[path = "../../guard-command/src/command_parse_surface.rs"]
mod command_parse_surface;
#[path = "../../guard-command/src/adapters/hook/hook_adapter_envelope_tables.rs"]
mod hook_adapter_envelope_tables;
#[path = "../../guard-command/src/adapters/hook/hook_adapter_envelope_text.rs"]
mod hook_adapter_envelope_text;
#[path = "../../guard-command/src/hook_responses/mod.rs"]
pub mod hook_responses;
#[path = "../../guard-command/src/js_semver.rs"]
pub mod js_semver;
#[path = "../../guard-command/src/mcp_decision.rs"]
pub mod mcp_decision;
#[path = "../../guard-command/src/mcp_package_sources.rs"]
mod mcp_package_sources;
#[path = "../../guard-command/src/pep440.rs"]
pub mod pep440;
#[path = "../../guard-command/src/restricted_command.rs"]
pub mod restricted_command;
#[cfg(unix)]
#[path = "../../guard-command/src/restricted_pytest/mod.rs"]
pub mod restricted_pytest;
#[path = "../../guard-command/src/safe_decode/mod.rs"]
pub mod safe_decode;
#[path = "../../guard-command/src/shims/mod.rs"]
pub mod shims;
#[path = "../../guard-command/src/strict_json.rs"]
pub mod strict_json;
#[path = "../../guard-command/src/supply_chain_bundle.rs"]
pub mod supply_chain_bundle;
#[path = "../../guard-command/src/supply_chain_package_identity.rs"]
pub mod supply_chain_package_identity;
#[path = "../../guard-command/src/supply_chain_risk.rs"]
pub mod supply_chain_risk;
pub(crate) use command_parse_surface::{
    default_dialect, default_provenance, default_transport, is_fd_dup_redirect,
    parse_command_unbound, parse_explicit_powershell, parse_inline_shell_script,
    parse_posix_command, uncertain, Quote, RawSegment,
};
pub use command_parse_surface::{
    parse_command, CanonicalCommandV1, CommandModelRequestV1, CommandSegmentV1, CommandSpanV1,
    MAX_COMMAND_BYTES, MAX_COMMAND_SEGMENTS, MAX_COMMAND_TOKENS,
};
use parser_executables::*;
use parser_segments::*;
