//! Rich `command_model.py` canonical parse (`parse_shell_command`, :124-489)
//! — segments, redirects, embedded substitution/heredoc executions. Verbatim.

use std::path::Path;

use serde_json::{json, Value};

use crate::command_segment_parsing::shell_tokens_without_redirects;
use crate::command_structure::{
    build_command_security_identity, extract_command_redirects, CommandRedirect, EmbeddedCommand,
    IdentitySegment,
};
use crate::command_tokens::{executable_name, leading_environment, shell_tokens};
use crate::data_flow::{
    extract_command_segments, extract_command_substitution_spans,
    extract_expanded_heredoc_substitution_spans, extract_heredocs, extract_pipes,
    mask_heredoc_bodies, ShellHeredoc,
};
use crate::shell_command_wrappers::{
    normalize_transparent_shell_command, SHELL_COMMAND_NORMALIZE_MAX_BYTES,
};

pub const MAX_COMMAND_BYTES: usize = 32_768;
pub const MAX_COMMAND_SEGMENTS: usize = 128;
pub const MAX_COMMAND_TOKENS: usize = 2_048;

const SHELL_SCRIPT_EXECUTABLES: &[&str] = &["ash", "bash", "dash", "sh", "zsh"];

/// `CommandSegment` (:41-67). `start`/`end` are char offsets into
/// `normalized_text`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSegment {
    pub text: String,
    pub tokens: Vec<String>,
    pub executable: Option<String>,
    pub arguments: Vec<String>,
    pub environment_names: Vec<String>,
    pub wrapper_chain: Vec<String>,
    pub path_overridden: bool,
    pub execution_context: String,
    pub pipeline_index: usize,
    pub start: usize,
    pub end: usize,
}

impl CommandSegment {
    pub fn to_dict(&self) -> Value {
        json!({
            "text": self.text,
            "tokens": self.tokens,
            "executable": self.executable,
            "arguments": self.arguments,
            "environment_names": self.environment_names,
            "wrapper_chain": self.wrapper_chain,
            "path_overridden": self.path_overridden,
            "execution_context": self.execution_context,
            "pipeline_index": self.pipeline_index,
            "span": {"source": "normalized", "start": self.start, "end": self.end},
        })
    }

    fn identity_segment(&self) -> IdentitySegment {
        IdentitySegment {
            tokens: self.tokens.clone(),
            environment_names: self.environment_names.clone(),
            wrapper_chain: self.wrapper_chain.clone(),
            execution_context: self.execution_context.clone(),
            pipeline_index: self.pipeline_index,
        }
    }
}

/// `CanonicalCommand` (:70-121).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCommand {
    pub raw_text: String,
    pub normalized_text: String,
    /// "posix" | ...
    pub dialect: String,
    /// "shell_string" | ...
    pub transport: String,
    pub extraction_provenance: String,
    pub wrapper_chain: Vec<String>,
    pub segments: Vec<CommandSegment>,
    pub redirects: Vec<CommandRedirect>,
    pub embedded_commands: Vec<EmbeddedCommand>,
    /// "exact" | "fallback" | "uncertain".
    pub confidence: String,
    pub uncertainty_reason: Option<String>,
}

impl CanonicalCommand {
    pub fn path_overridden(&self) -> bool {
        self.segments.iter().any(|s| s.path_overridden)
    }

    pub fn security_identity(&self) -> String {
        build_command_security_identity(
            &self.normalized_text,
            &self.dialect,
            &self.transport,
            &self.wrapper_chain,
            &self
                .segments
                .iter()
                .map(|s| s.identity_segment())
                .collect::<Vec<_>>(),
            &self.redirects,
            &self.embedded_commands,
        )
    }

    pub fn to_dict(&self) -> Value {
        json!({
            "normalized_text": self.normalized_text,
            "dialect": self.dialect,
            "transport": self.transport,
            "extraction_provenance": self.extraction_provenance,
            "wrapper_chain": self.wrapper_chain,
            "segments": self.segments.iter().map(|s| s.to_dict()).collect::<Vec<_>>(),
            "redirects": self.redirects.iter().map(|r| r.to_dict()).collect::<Vec<_>>(),
            "embedded_commands": self.embedded_commands.iter().map(|e| e.to_dict()).collect::<Vec<_>>(),
            "security_identity": self.security_identity(),
            "confidence": self.confidence,
            "uncertainty_reason": self.uncertainty_reason,
            "path_overridden": self.path_overridden(),
        })
    }
}

/// `parse_shell_command` (:124-283).
pub fn parse_shell_command(
    command: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    dialect: &str,
    transport: &str,
    extraction_provenance: &str,
    normalize_wrappers: bool,
) -> CanonicalCommand {
    let raw_text = command.trim().to_owned();
    assert!(!raw_text.is_empty(), "Command text cannot be empty");
    let uncertain = |normalized: String, wrappers: Vec<String>, reason: &str| CanonicalCommand {
        raw_text: raw_text.clone(),
        normalized_text: normalized,
        dialect: dialect.to_owned(),
        transport: transport.to_owned(),
        extraction_provenance: extraction_provenance.to_owned(),
        wrapper_chain: wrappers,
        segments: Vec::new(),
        redirects: Vec::new(),
        embedded_commands: Vec::new(),
        confidence: "uncertain".to_owned(),
        uncertainty_reason: Some(reason.to_owned()),
    };
    if dialect != "posix" || transport != "shell_string" {
        return uncertain(
            raw_text.clone(),
            Vec::new(),
            &format!("unsupported_{dialect}_{transport}"),
        );
    }
    let command_bytes = raw_text.len();
    if command_bytes > MAX_COMMAND_BYTES {
        return uncertain(raw_text.clone(), Vec::new(), "command_byte_limit_exceeded");
    }

    let (normalized_text, wrapper_chain): (String, Vec<String>) = if normalize_wrappers {
        let normalization = normalize_transparent_shell_command(&raw_text, cwd, home_dir);
        (
            normalization.normalized_command,
            normalization.wrapper_chain,
        )
    } else {
        (raw_text.clone(), Vec::new())
    };
    let mut confidence = "exact".to_owned();
    let mut uncertainty_reason: Option<String> = None;
    if command_bytes > SHELL_COMMAND_NORMALIZE_MAX_BYTES {
        confidence = "uncertain".to_owned();
        uncertainty_reason = Some("wrapper_normalization_limit_exceeded".to_owned());
    }

    let heredocs = extract_heredocs(&normalized_text);
    let masked_command = mask_heredoc_bodies(&normalized_text, &heredocs);
    let command_redirects = extract_command_redirects(&masked_command, &heredocs);
    let segment_texts = execution_segment_texts(&masked_command, "top");
    if segment_texts.len() > MAX_COMMAND_SEGMENTS {
        return uncertain(
            normalized_text,
            wrapper_chain,
            "command_segment_limit_exceeded",
        );
    }

    let mut segments: Vec<CommandSegment> = Vec::new();
    let mut segment_wrappers: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    let mut total_tokens = 0usize;
    let normalized_chars: Vec<char> = normalized_text.chars().collect();
    for (execution_context, pipeline_index, segment_text, source_offset) in &segment_texts {
        let (tokens, exact) = shell_tokens(segment_text);
        total_tokens += tokens.len();
        if total_tokens > MAX_COMMAND_TOKENS {
            return CanonicalCommand {
                raw_text: raw_text.clone(),
                normalized_text: normalized_text.clone(),
                dialect: dialect.to_owned(),
                transport: transport.to_owned(),
                extraction_provenance: extraction_provenance.to_owned(),
                wrapper_chain: wrapper_chain.clone(),
                segments,
                redirects: Vec::new(),
                embedded_commands: Vec::new(),
                confidence: "uncertain".to_owned(),
                uncertainty_reason: Some("command_token_limit_exceeded".to_owned()),
            };
        }
        if !exact && confidence == "exact" {
            confidence = "fallback".to_owned();
            uncertainty_reason = Some("malformed_shell_quoting".to_owned());
        }
        // `normalized_text.find(segment_text, max(cursor, source_offset))` —
        // char offsets.
        let find_from = |hay: &[char], needle: &str, at: usize| -> isize {
            let nch: Vec<char> = needle.chars().collect();
            if nch.is_empty() || at > hay.len() || hay.len() - at < nch.len() {
                return -1;
            }
            for i in at..=(hay.len() - nch.len()) {
                if hay[i..i + nch.len()] == nch[..] {
                    return i as isize;
                }
            }
            -1
        };
        let mut start = find_from(&normalized_chars, segment_text, cursor.max(*source_offset));
        if start < 0 {
            start = find_from(&normalized_chars, segment_text, 0);
        }
        let start = if start < 0 {
            cursor.min(normalized_chars.len())
        } else {
            start as usize
        };
        let seg_chars = segment_text.chars().count();
        let end = (start + seg_chars).min(normalized_chars.len());
        cursor = end;
        let command_tokens =
            shell_tokens_without_redirects(segment_text, start, &command_redirects);
        let (environment_names, executable_index, wrappers) = leading_environment(&command_tokens);
        for wrapper in &wrappers {
            if !segment_wrappers.contains(wrapper) {
                segment_wrappers.push(wrapper.clone());
            }
        }
        let executable = if executable_index < command_tokens.len() {
            Some(command_tokens[executable_index].clone())
        } else {
            None
        };
        let arguments = if executable.is_some() {
            command_tokens[executable_index + 1..].to_vec()
        } else {
            Vec::new()
        };
        segments.push(CommandSegment {
            text: segment_text.clone(),
            tokens,
            executable,
            arguments,
            path_overridden: environment_names.iter().any(|n| n == "PATH"),
            environment_names,
            wrapper_chain: wrappers,
            execution_context: execution_context.clone(),
            pipeline_index: *pipeline_index,
            start,
            end,
        });
    }

    let (embedded_commands, embedded_segments) =
        embedded_execution(&normalized_text, &heredocs, &segments, cwd, home_dir);
    segments.extend(embedded_segments);
    if segments.len() > MAX_COMMAND_SEGMENTS
        || segments.iter().map(|s| s.tokens.len()).sum::<usize>() > MAX_COMMAND_TOKENS
    {
        confidence = "uncertain".to_owned();
        uncertainty_reason = Some("embedded_command_limit_exceeded".to_owned());
    }
    let mut full_chain = wrapper_chain.clone();
    full_chain.extend(segment_wrappers);
    CanonicalCommand {
        raw_text,
        normalized_text,
        dialect: dialect.to_owned(),
        transport: transport.to_owned(),
        extraction_provenance: extraction_provenance.to_owned(),
        wrapper_chain: full_chain,
        segments,
        redirects: command_redirects,
        embedded_commands,
        confidence,
        uncertainty_reason,
    }
}

/// `_execution_segment_texts` (:286-314). `(context, pipeline_index, text,
/// char_source_offset)`.
fn execution_segment_texts(
    command: &str,
    context_prefix: &str,
) -> Vec<(String, usize, String, usize)> {
    let chars: Vec<char> = command.chars().collect();
    let find = |needle: &str, from: usize| -> isize {
        let nch: Vec<char> = needle.chars().collect();
        if nch.is_empty() || from > chars.len() || chars.len() - from < nch.len() {
            return -1;
        }
        for i in from..=(chars.len() - nch.len()) {
            if chars[i..i + nch.len()] == nch[..] {
                return i as isize;
            }
        }
        -1
    };
    let mut segments: Vec<(String, usize, String, usize)> = Vec::new();
    let mut cursor = 0usize;
    for (group_index, command_segment) in extract_command_segments(command).iter().enumerate() {
        let mut source_offset = find(command_segment, cursor);
        if source_offset < 0 {
            source_offset = cursor as isize;
        }
        let source_offset = source_offset as usize;
        cursor = source_offset + command_segment.chars().count();
        let execution_context = format!("{context_prefix}:{group_index}");
        let pipes = extract_pipes(command_segment);
        if pipes.is_empty() {
            let stripped = command_segment.trim();
            if !stripped.is_empty() {
                segments.push((execution_context, 0, stripped.to_owned(), source_offset));
            }
            continue;
        }
        let mut pipe_parts = vec![pipes[0].left.clone()];
        pipe_parts.extend(pipes.iter().map(|p| p.right.clone()));
        let mut part_cursor = source_offset;
        for (index, part) in pipe_parts.iter().enumerate() {
            let stripped = part.trim();
            if stripped.is_empty() {
                continue;
            }
            let mut part_offset = find(stripped, part_cursor);
            if part_offset < 0 {
                part_offset = part_cursor as isize;
            }
            let part_offset = part_offset as usize;
            segments.push((
                execution_context.clone(),
                index,
                stripped.to_owned(),
                part_offset,
            ));
            part_cursor = part_offset + stripped.chars().count();
        }
    }
    segments
}

/// `_embedded_execution` (:317-388).
fn embedded_execution(
    command: &str,
    heredocs: &[ShellHeredoc],
    top_level_segments: &[CommandSegment],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> (Vec<EmbeddedCommand>, Vec<CommandSegment>) {
    let mut embedded: Vec<EmbeddedCommand> = Vec::new();
    let mut segments: Vec<CommandSegment> = Vec::new();
    let excluded: Vec<(usize, usize)> = heredocs.iter().map(|h| (h.body_start, h.end)).collect();
    append_substitution_execution(
        command,
        0,
        "substitution",
        &excluded,
        &mut embedded,
        &mut segments,
        0,
        cwd,
        home_dir,
        false,
    );

    for (index, heredoc) in heredocs.iter().enumerate() {
        let owner = top_level_segments
            .iter()
            .find(|s| s.start <= heredoc.operator_start && heredoc.operator_start <= s.end);
        let executable = owner.and_then(|s| executable_name(s.executable.as_deref()));
        if executable
            .as_deref()
            .map(|e| !SHELL_SCRIPT_EXECUTABLES.contains(&e))
            .unwrap_or(true)
        {
            if !heredoc.quoted {
                append_substitution_execution(
                    &heredoc.body,
                    heredoc.body_start,
                    &format!("heredoc:{index}:substitution"),
                    &[],
                    &mut embedded,
                    &mut segments,
                    0,
                    cwd,
                    home_dir,
                    true,
                );
            }
            continue;
        }
        let context = format!("heredoc:{index}");
        embedded.push(EmbeddedCommand {
            kind: "heredoc".to_owned(),
            text: heredoc.body.clone(),
            execution_context: context.clone(),
            start: heredoc.body_start,
            end: heredoc.body_end,
        });
        segments.extend(segments_for_embedded(
            &heredoc.body,
            &context,
            heredoc.body_start,
            cwd,
            home_dir,
        ));
        append_substitution_execution(
            &heredoc.body,
            heredoc.body_start,
            &format!("{context}:substitution"),
            &[],
            &mut embedded,
            &mut segments,
            0,
            cwd,
            home_dir,
            false,
        );
    }
    (embedded, segments)
}

/// `_append_substitution_execution` (:391-431).
#[allow(clippy::too_many_arguments)]
fn append_substitution_execution(
    command: &str,
    source_offset: usize,
    context_prefix: &str,
    excluded_ranges: &[(usize, usize)],
    embedded: &mut Vec<EmbeddedCommand>,
    segments: &mut Vec<CommandSegment>,
    depth: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    expanded_heredoc: bool,
) {
    if depth >= 4 {
        return;
    }
    let substitutions = if expanded_heredoc {
        extract_expanded_heredoc_substitution_spans(command)
    } else {
        extract_command_substitution_spans(command)
    };
    for (index, substitution) in substitutions.iter().enumerate() {
        let absolute_start = source_offset + substitution.body_start;
        if excluded_ranges
            .iter()
            .any(|&(start, end)| start <= absolute_start && absolute_start < end)
        {
            continue;
        }
        let context = format!("{context_prefix}:{index}");
        embedded.push(EmbeddedCommand {
            kind: "substitution".to_owned(),
            text: substitution.body.clone(),
            execution_context: context.clone(),
            start: absolute_start,
            end: source_offset + substitution.body_end,
        });
        segments.extend(segments_for_embedded(
            &substitution.body,
            &context,
            absolute_start,
            cwd,
            home_dir,
        ));
        append_substitution_execution(
            &substitution.body,
            absolute_start,
            &format!("{context}:nested"),
            &[],
            embedded,
            segments,
            depth + 1,
            cwd,
            home_dir,
            false,
        );
    }
}

/// `_segments_for_embedded` (:434-489).
fn segments_for_embedded(
    command: &str,
    execution_context: &str,
    source_offset: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<CommandSegment> {
    let mut results = Vec::new();
    let normalization = normalize_transparent_shell_command(command, cwd, home_dir);
    let heredocs = extract_heredocs(&normalization.normalized_command);
    let redirects = extract_command_redirects(
        &mask_heredoc_bodies(&normalization.normalized_command, &heredocs),
        &heredocs,
    );
    let command_chars: Vec<char> = command.chars().collect();
    for (context, pipeline_index, segment_text, local_offset) in
        execution_segment_texts(&normalization.normalized_command, execution_context)
    {
        let (tokens, _exact) = shell_tokens(&segment_text);
        let command_tokens =
            shell_tokens_without_redirects(&segment_text, local_offset, &redirects);
        let (environment_names, executable_index, wrappers) = leading_environment(&command_tokens);
        let executable = if executable_index < command_tokens.len() {
            Some(command_tokens[executable_index].clone())
        } else {
            None
        };
        let arguments = if executable.is_some() {
            command_tokens[executable_index + 1..].to_vec()
        } else {
            Vec::new()
        };
        // `command.find(segment_text)` on the *pre-normalization* body, char
        // offsets.
        let seg_chars: Vec<char> = segment_text.chars().collect();
        let mut original_offset: isize = -1;
        if !seg_chars.is_empty() && command_chars.len() >= seg_chars.len() {
            for i in 0..=(command_chars.len() - seg_chars.len()) {
                if command_chars[i..i + seg_chars.len()] == seg_chars[..] {
                    original_offset = i as isize;
                    break;
                }
            }
        }
        let start = source_offset
            + if original_offset >= 0 {
                original_offset as usize
            } else {
                local_offset
            };
        let mut wrapper_chain = normalization.wrapper_chain.clone();
        wrapper_chain.extend(wrappers);
        results.push(CommandSegment {
            text: segment_text.clone(),
            tokens,
            executable,
            arguments,
            path_overridden: environment_names.iter().any(|n| n == "PATH"),
            environment_names,
            wrapper_chain,
            execution_context: context,
            pipeline_index,
            start,
            end: start + seg_chars.len(),
        });
    }
    results
}
