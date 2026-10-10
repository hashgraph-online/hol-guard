//! Builds the canonical command model for the bounded PowerShell subset.

use crate::parser_executables::{
    executable_basename, is_nested_command_executor, is_shell_control_keyword,
    is_transparent_wrapper,
};
use crate::powershell_effects::canonicalize;
use crate::powershell_parser::{parse_statements, PsCall};
use crate::{
    CanonicalCommandV1, CommandModelRequestV1, CommandSegmentV1, CommandSpanV1,
    MAX_COMMAND_SEGMENTS, MAX_COMMAND_TOKENS,
};

pub(crate) const POWERSHELL_PROFILE: &str = "powershell-subset-v1";

const BLOCKED_COMMANDS: &[&str] = &[
    "invoke-expression",
    "iex",
    "invoke-command",
    "icm",
    "start-job",
    "sajb",
    "add-type",
    "new-object",
    "foreach-object",
    "foreach",
    "where-object",
    "where",
    "invoke-item",
    "ii",
    "invoke-wmimethod",
    "invoke-cimmethod",
    "set-alias",
    "sal",
    "new-alias",
    "nal",
    "import-module",
    "powershell",
    "pwsh",
    "cmd",
];

const CONTROL_KEYWORDS: &[&str] = &[
    "if", "elseif", "else", "for", "while", "do", "switch", "function", "filter", "try", "catch",
    "finally", "trap", "return", "throw", "begin", "process", "end", "param", "class", "using",
    "workflow", "data", "until", "break", "continue", "exit",
];

pub(crate) fn parse(
    request: &CommandModelRequestV1,
    raw: &str,
) -> Result<CanonicalCommandV1, &'static str> {
    let chars: Vec<char> = raw.chars().collect();
    let statements = parse_statements(&chars)?;
    if statements.len() > MAX_COMMAND_SEGMENTS {
        return Err("command_segment_limit_exceeded");
    }
    let mut segments = Vec::with_capacity(statements.len());
    let mut total_tokens = 0usize;
    for statement in statements {
        if let PsCall::Command { name, .. } = &statement.call {
            let lowered = name.to_ascii_lowercase();
            let lowered = lowered.strip_suffix(".exe").unwrap_or(&lowered);
            let lowered = lowered.rsplit(['/', '\\']).next().unwrap_or(lowered);
            if BLOCKED_COMMANDS.contains(&lowered) {
                return Err("powershell_dynamic_execution_not_supported");
            }
            if CONTROL_KEYWORDS.contains(&lowered) {
                return Err("powershell_control_keyword_not_supported");
            }
        }
        let tokens = canonicalize(&statement.call)?;
        // PowerShell binds piped input to a web request body, which the curl
        // mapping cannot express.
        if statement.pipeline_index > 0 && tokens.first().is_some_and(|name| name == "curl") {
            return Err("powershell_piped_request_body_not_supported");
        }
        total_tokens = total_tokens.saturating_add(tokens.len());
        if total_tokens > MAX_COMMAND_TOKENS {
            return Err("command_token_limit_exceeded");
        }
        let executable = tokens.first().cloned();
        let arguments: Vec<String> = tokens.iter().skip(1).cloned().collect();
        if let Some(name) = executable.as_deref() {
            let lowered = name.to_ascii_lowercase();
            if is_shell_control_keyword(&lowered) {
                return Err("compound_shell_not_yet_supported");
            }
            if is_transparent_wrapper(&lowered) {
                return Err("transparent_wrapper_not_yet_supported");
            }
            if is_nested_command_executor(&lowered, &arguments)
                || is_nested_command_executor(executable_basename(&lowered), &arguments)
            {
                return Err("nested_command_executor_not_yet_supported");
            }
        }
        let text: String = chars[statement.start..statement.end].iter().collect();
        segments.push(CommandSegmentV1 {
            text,
            tokens,
            executable,
            arguments,
            environment_names: Vec::new(),
            wrapper_chain: Vec::new(),
            path_overridden: false,
            execution_context: format!("top:{}", statement.group_index),
            pipeline_index: statement.pipeline_index,
            span: CommandSpanV1 {
                source: "normalized".to_owned(),
                start: statement.start,
                end: statement.end,
            },
        });
    }
    Ok(CanonicalCommandV1 {
        exact_raw_text: true,
        normalized_text: raw.to_owned(),
        dialect: "powershell".to_owned(),
        transport: request.transport.clone(),
        extraction_provenance: request.extraction_provenance.clone(),
        wrapper_chain: Vec::new(),
        segments,
        confidence: "exact".to_owned(),
        uncertainty_reason: None,
        path_overridden: false,
        parser_profile: POWERSHELL_PROFILE.to_owned(),
        security_identity: String::new(),
    })
}

/// True when a POSIX-exact segment list names a PowerShell-only effect cmdlet.
pub(crate) fn names_powershell_effect(segments: &[CommandSegmentV1]) -> bool {
    segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .is_some_and(crate::powershell_effects::is_powershell_specific)
    })
}
