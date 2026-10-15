#![forbid(unsafe_code)]
pub mod action_lattice;
pub mod approval_reuse;
pub mod benign_request_api;
pub mod browser_mcp_intent;
pub mod business_gmail_plain;
pub mod business_gmail_wire;
pub mod business_gws_command;
pub mod business_input;
pub mod canonical_command;
pub mod catalog_read_model;
#[cfg(test)]
mod catalog_read_model_tests;
mod catalog_read_projection;
mod catalog_read_query;
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
pub mod github_workflow_operations;
mod harness_config_names;
mod home_path_text;
pub mod homebrew_intent;
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
mod parser_executables;
mod parser_segments;
mod parser_wrappers;
mod powershell_command;
mod powershell_effects;
mod powershell_floors;
mod powershell_parser;
mod powershell_reads;
pub mod protect_request;
mod read_only_fanout;
pub mod rich_command_model_api;
use parser_executables::*;
use parser_segments::*;
pub mod developer_inspection_authority;
pub mod environment_secret_dump;
pub mod pretool;
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
mod shell_secret_read_flow;
#[cfg(test)]
mod shell_secret_read_script_operand_tests;
mod shell_secret_read_support;
pub mod shell_secret_reads;
mod shell_structure;
pub mod source_cli;
pub mod typescript_launch_evidence;

pub mod package_context_environment;

mod critical_floor_context;
pub use command_evaluation::CompositeCommandEvaluation;
pub use command_evaluation_compose::{evaluate_command, CommandEvaluationInput};
pub use command_model::parse_shell_command;
pub use critical_floor_context::critical_floor_action;

use serde::{Deserialize, Serialize};

pub const MAX_COMMAND_BYTES: usize = 32_768;
pub const MAX_COMMAND_SEGMENTS: usize = 128;
pub const MAX_COMMAND_TOKENS: usize = 2_048;

fn default_dialect() -> String {
    "posix".to_owned()
}

fn default_transport() -> String {
    "shell_string".to_owned()
}

fn default_provenance() -> String {
    "guard-shell".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandModelRequestV1 {
    pub command: String,
    #[serde(default = "default_dialect")]
    pub dialect: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_provenance")]
    pub extraction_provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandSpanV1 {
    pub source: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandSegmentV1 {
    pub text: String,
    pub tokens: Vec<String>,
    pub executable: Option<String>,
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
    pub wrapper_chain: Vec<String>,
    pub path_overridden: bool,
    pub execution_context: String,
    pub pipeline_index: usize,
    pub span: CommandSpanV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalCommandV1 {
    #[serde(skip)]
    pub(crate) exact_raw_text: bool,
    pub normalized_text: String,
    pub dialect: String,
    pub transport: String,
    pub extraction_provenance: String,
    pub wrapper_chain: Vec<String>,
    pub segments: Vec<CommandSegmentV1>,
    pub confidence: String,
    pub uncertainty_reason: Option<String>,
    pub path_overridden: bool,
    pub parser_profile: String,
    /// Python `CanonicalCommand.security_identity` — the authoritative
    /// `command-security-v2:` digest serialized on `to_dict`. The wire omits
    /// embedded-command `text` and redirect spans, so the identity cannot be
    /// re-derived from the public model; the resident path supplies it. Empty
    /// string on the pure-native path → `from_v1` recomputes it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub security_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawSegment {
    group_index: usize,
    pipeline_index: usize,
    start: usize,
    end: usize,
}

pub fn parse_command(request: &CommandModelRequestV1) -> Result<CanonicalCommandV1, String> {
    let mut command = parse_command_unbound(request)?;
    command.security_identity = canonical_command::command_security_identity(&command);
    Ok(command)
}

fn parse_command_unbound(request: &CommandModelRequestV1) -> Result<CanonicalCommandV1, String> {
    let raw = request.command.trim();
    if request.dialect == "powershell" && request.transport == "shell_string" && !raw.is_empty() {
        return Ok(parse_explicit_powershell(request, raw));
    }
    let posix = parse_posix_command(request)?;
    if request.dialect != "posix" || !powershell_reads::windows_powershell_host() {
        return Ok(posix);
    }
    // Windows agents run PowerShell. A cmdlet name means POSIX only saw an
    // unknown word, so the PowerShell result stands even when it is uncertain.
    if posix.confidence == "exact" && powershell_command::names_powershell_effect(&posix.segments) {
        return Ok(parse_explicit_powershell(request, raw));
    }
    // Otherwise retry only input that POSIX cannot prove.
    if posix.confidence != "exact"
        && raw.chars().count() <= MAX_COMMAND_BYTES
        && raw.len() <= MAX_COMMAND_BYTES
    {
        if let Ok(model) = powershell_command::parse(request, raw) {
            return Ok(model);
        }
    }
    Ok(posix)
}

fn parse_explicit_powershell(request: &CommandModelRequestV1, raw: &str) -> CanonicalCommandV1 {
    if raw.chars().count() > MAX_COMMAND_BYTES || raw.len() > MAX_COMMAND_BYTES {
        return uncertain(request, raw, "command_byte_limit_exceeded");
    }
    match powershell_command::parse(request, raw) {
        Ok(model) => model,
        Err(reason) => {
            let mut model = uncertain(request, raw, reason);
            model.parser_profile = powershell_command::POWERSHELL_PROFILE.to_owned();
            model
        }
    }
}

fn parse_posix_command(request: &CommandModelRequestV1) -> Result<CanonicalCommandV1, String> {
    let raw = request.command.trim();
    if raw.is_empty() {
        return Err("command_text_empty".to_owned());
    }
    // Unquoted Windows paths keep backslash separators. Quoted POSIX escapes
    // stay intact, and cmd/PowerShell stay uncertain until they have their own
    // separator and quoting rules.
    let preserve_unquoted_backslash = cfg!(windows) && request.dialect == "posix";
    if request.dialect != "posix" || request.transport != "shell_string" {
        return Ok(uncertain(request, raw, "unsupported_dialect_or_transport"));
    }
    if raw.chars().count() > MAX_COMMAND_BYTES || raw.len() > MAX_COMMAND_BYTES {
        return Ok(uncertain(request, raw, "command_byte_limit_exceeded"));
    }

    let raw_segments = if let Some(value) = contained_compile_check_segments(raw) {
        value
    } else {
        match split_execution_segments(raw, preserve_unquoted_backslash) {
            Ok(value) => value,
            Err(reason) => return Ok(uncertain(request, raw, reason)),
        }
    };
    if raw_segments.len() > MAX_COMMAND_SEGMENTS {
        return Ok(uncertain(request, raw, "command_segment_limit_exceeded"));
    }

    let chars: Vec<char> = raw.chars().collect();
    let mut segments = Vec::with_capacity(raw_segments.len());
    let mut total_tokens = 0usize;
    for raw_segment in raw_segments {
        let text: String = chars[raw_segment.start..raw_segment.end].iter().collect();
        let tokens = match shell_tokens(&text, preserve_unquoted_backslash) {
            Ok(value) => value,
            Err(reason) => return Ok(uncertain(request, raw, reason)),
        };
        total_tokens = total_tokens.saturating_add(tokens.len());
        if total_tokens > MAX_COMMAND_TOKENS {
            return Ok(uncertain(request, raw, "command_token_limit_exceeded"));
        }

        let mut environment_names = Vec::new();
        let mut executable_index = 0usize;
        while executable_index < tokens.len() {
            let Some(name) = assignment_name(&tokens[executable_index]) else {
                break;
            };
            environment_names.push(name.to_owned());
            executable_index += 1;
        }
        let (executable_index, wrapper_chain) = match parser_wrappers::unwrap_wrappers(
            &tokens,
            executable_index,
            &mut environment_names,
        ) {
            Ok(value) => value,
            Err(reason) => return Ok(uncertain(request, raw, reason)),
        };
        let mut tokens = tokens;
        let mut executable = tokens.get(executable_index).cloned();
        let mut arguments = if executable.is_some() {
            tokens[executable_index + 1..].to_vec()
        } else {
            Vec::new()
        };
        if executable_index == 0 && powershell_reads::windows_powershell_host() {
            if let Some(operands) = executable.as_deref().and_then(|name| {
                powershell_reads::plain_get_content_operands(name, &arguments, &text)
            }) {
                tokens = std::iter::once("cat".to_owned())
                    .chain(operands.iter().cloned())
                    .collect();
                executable = Some("cat".to_owned());
                arguments = operands;
            }
        }
        if executable.as_deref().is_some_and(is_shell_control_keyword) {
            return Ok(uncertain(request, raw, "compound_shell_not_yet_supported"));
        }
        if executable.as_deref().is_some_and(is_transparent_wrapper)
            && !parser_wrappers::is_encoded_stdin_shell(
                executable.as_deref(),
                &arguments,
                &raw_segment,
                segments.last(),
            )
            && !parser_wrappers::is_file_shell_invocation(executable.as_deref(), &arguments)
            && !parser_wrappers::is_command_lookup(executable.as_deref(), &arguments)
        {
            return Ok(uncertain(
                request,
                raw,
                "transparent_wrapper_not_yet_supported",
            ));
        }
        let read_only_xargs = executable
            .as_deref()
            .is_some_and(|value| executable_basename(value) == "xargs")
            && environment_names.is_empty()
            && wrapper_chain.is_empty()
            && segments.last().is_some_and(|previous| {
                let context = format!("top:{}", raw_segment.group_index);
                read_only_fanout::xargs_follows_find(
                    previous,
                    raw_segment.pipeline_index,
                    &context,
                    &arguments,
                ) || read_only_fanout::xargs_follows_object_names(
                    previous,
                    raw_segment.pipeline_index,
                    &context,
                    &arguments,
                )
            });
        if !read_only_xargs
            && executable
                .as_deref()
                .is_some_and(|value| is_nested_command_executor(value, &arguments))
        {
            return Ok(uncertain(
                request,
                raw,
                "nested_command_executor_not_yet_supported",
            ));
        }
        let path_overridden = environment_names.iter().any(|name| name == "PATH");
        segments.push(CommandSegmentV1 {
            text,
            tokens,
            executable,
            arguments,
            environment_names,
            wrapper_chain,
            path_overridden,
            execution_context: format!("top:{}", raw_segment.group_index),
            pipeline_index: raw_segment.pipeline_index,
            span: CommandSpanV1 {
                source: "normalized".to_owned(),
                start: raw_segment.start,
                end: raw_segment.end,
            },
        });
    }

    let path_overridden = segments.iter().any(|segment| segment.path_overridden);
    let wrapper_chain = segments
        .iter()
        .flat_map(|segment| segment.wrapper_chain.iter().cloned())
        .collect::<Vec<_>>();
    let parser_profile = if wrapper_chain.is_empty() {
        "posix-simple-v1"
    } else {
        "posix-bounded-wrappers-v2"
    };
    Ok(CanonicalCommandV1 {
        exact_raw_text: true,
        normalized_text: raw.to_owned(),
        dialect: request.dialect.clone(),
        transport: request.transport.clone(),
        extraction_provenance: request.extraction_provenance.clone(),
        wrapper_chain,
        segments,
        confidence: "exact".to_owned(),
        uncertainty_reason: None,
        path_overridden,
        parser_profile: parser_profile.to_owned(),
        security_identity: String::new(),
    })
}

fn uncertain(request: &CommandModelRequestV1, raw: &str, reason: &str) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: false,
        normalized_text: raw.to_owned(),
        dialect: request.dialect.clone(),
        transport: request.transport.clone(),
        extraction_provenance: request.extraction_provenance.clone(),
        wrapper_chain: Vec::new(),
        segments: Vec::new(),
        confidence: "uncertain".to_owned(),
        uncertainty_reason: Some(reason.to_owned()),
        path_overridden: false,
        parser_profile: "posix-simple-v1".to_owned(),
        security_identity: String::new(),
    }
}

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
mod local_supply_chain_stale_policy_tests;
pub mod package_approval;
pub mod package_policy_override;
pub mod package_protect_projection;
pub mod prompt_analysis;
pub mod redacted_command_tokens;
pub mod supply_chain_package_eval;
pub mod target_identities;
pub mod workspace_inventory;

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
pub mod data_flow_rules;
pub mod decisions;
pub mod detectors;
pub mod direct_vitest;
mod egress_archive;
pub mod egress_broker;
mod egress_spool;
pub mod false_positive_rules;
pub mod guard_sync_transport;
mod hook_adapter_cline_tables;
pub mod hook_adapter_envelope;
mod hook_adapter_envelope_tables;
mod hook_adapter_envelope_text;
#[cfg(test)]
mod hook_adapter_omp_tests;
pub mod hook_adapter_paths;
pub mod hook_adapter_prepare;
pub mod hook_adapter_prepare_cline;
mod hook_adapter_prepare_cursor;
mod hook_adapter_pyjson;
mod hook_adapter_pytext;
mod hook_adapter_redact;
mod hook_adapter_secret_path;
pub mod hook_adapter_value;
#[cfg(all(test, unix))]
mod hook_adapter_vector_tests;
pub mod hook_evidence_writer;
pub mod hook_responses;
pub mod inventory_contract;
pub mod js_semver;
pub mod linux_artifact_supply_chain;
#[cfg(unix)]
pub mod local_mcp_stdio;
#[cfg(all(unix, test))]
mod local_mcp_stdio_tests;
pub mod mcp_decision;
mod mcp_package_sources;
#[cfg(unix)]
pub mod mcp_stdio_session;
pub mod pep440;
pub mod persistence_rules;
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
pub mod supply_chain_bundle;
pub mod supply_chain_package_identity;
pub mod supply_chain_risk;
pub mod supply_chain_support;
