#![forbid(unsafe_code)]
pub mod action_lattice;
pub mod approval_reuse;
pub mod browser_mcp_intent;
pub mod business_gmail_plain;
pub mod business_gmail_wire;
pub mod business_gws_command;
pub mod business_input;
pub mod canonical_command;
mod command_ascii_comparison;
mod command_candidate_common;
mod command_common_cli_matchers;
pub mod command_compatibility;
mod command_contained_routine_candidates;
mod command_critical_floors;
#[cfg(test)]
mod command_critical_floors_tests;
mod command_database_matchers;
pub mod command_decision_adapter;
pub mod command_evaluation;
#[cfg(test)]
mod command_evaluation_tests;
mod command_launcher_floors;
pub mod command_model;
mod command_operand_matchers;
pub mod command_option_parsing;
mod command_segment_parsing;
#[cfg(unix)]
pub mod command_shell_read_factors;
mod command_specialized_matchers;
mod command_structure;
mod command_structured_matchers;
mod command_tokens;
mod command_verified_read_candidates;
#[cfg(test)]
mod command_verified_read_candidates_tests;
mod command_workspace_write_candidates;
mod data_flow;
pub mod effect_decision;
mod env_wrapper;
mod executable_flag_contract;
pub mod extension_control;
pub mod extension_evidence;
pub mod extension_trust;
mod github_capability_contract;
#[cfg(test)]
mod github_capability_contract_tests;
mod github_capability_interaction;
mod github_command_capabilities;
#[cfg(test)]
mod github_command_capabilities_tests;
pub mod github_workflow_approval_record;
pub mod github_workflow_authorization;
pub mod github_workflow_operations;
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
pub mod mcp_tool_approval;
pub mod mcp_tool_catalog;
pub mod mcp_tool_policy;
pub mod mcp_tool_risk;
pub mod native_command_catalog;
pub mod native_command_controls;
pub mod native_command_extension_evidence;
#[cfg(test)]
mod native_command_extension_evidence_tests;
pub mod native_command_program;
pub mod npm_source_spec;
pub mod package_execution_context;
pub mod package_intent_common;
pub mod package_intent_parser;
pub mod package_manager_command;
pub mod package_manifest_diff;
mod parser_executables;
mod parser_segments;
mod parser_wrappers;
mod powershell_reads;
use parser_executables::*;
use parser_segments::*;
pub mod pretool;
#[cfg(unix)]
mod runtime_read_paths;
mod shell_command_wrappers;
mod shell_execution_context;
mod shell_execution_context_support;
mod shell_read_literal_wrapper;
mod shell_secret_read_flow;
mod shell_secret_read_support;
#[cfg(unix)]
pub mod shell_secret_reads;
mod shell_structure;
pub mod typescript_launch_evidence;

pub mod package_context_environment;

pub use command_evaluation::{evaluate_command, CompositeCommandEvaluation};
pub use command_model::parse_shell_command;

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
        let (executable_index, wrapper_chain) =
            match parser_wrappers::unwrap_sudo(&tokens, executable_index) {
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
        if executable_index == 0 && powershell_reads::windows_powershell_reads() {
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
        {
            return Ok(uncertain(
                request,
                raw,
                "transparent_wrapper_not_yet_supported",
            ));
        }
        if executable
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
#[path = "parser_tests.rs"]
mod tests;

// RTM-019 pending modules — compile signal only until legs complete
pub mod audit_receipt;
pub mod cloud_audit_sync;
pub mod guard_run_launch;
pub mod install_time_event;
pub mod local_supply_chain;
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
#[cfg(unix)]
pub mod contained_execution;
pub mod data_flow_rules;
pub mod decisions;
pub mod detectors;
#[cfg(unix)]
pub mod direct_vitest;
pub mod false_positive_rules;
pub mod guard_sync_transport;
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
pub mod restricted_archive;
pub mod restricted_archive_transport;
#[cfg(unix)]
pub mod restricted_pytest;
pub mod resume_template;
pub mod review_event_outbox;
pub mod review_event_outbox_schema;
#[cfg(unix)]
pub mod sandbox;
pub mod shims;
pub mod signals;
pub mod supply_chain_bundle;
pub mod supply_chain_package_identity;
pub mod supply_chain_risk;
pub mod supply_chain_support;
