#![forbid(unsafe_code)]
pub mod pretool;

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
    if request.dialect != "posix" || request.transport != "shell_string" {
        return Ok(uncertain(request, raw, "unsupported_dialect_or_transport"));
    }
    if raw.chars().count() > MAX_COMMAND_BYTES || raw.len() > MAX_COMMAND_BYTES {
        return Ok(uncertain(request, raw, "command_byte_limit_exceeded"));
    }

    let raw_segments = match split_execution_segments(raw) {
        Ok(value) => value,
        Err(reason) => return Ok(uncertain(request, raw, reason)),
    };
    if raw_segments.len() > MAX_COMMAND_SEGMENTS {
        return Ok(uncertain(request, raw, "command_segment_limit_exceeded"));
    }

    let chars: Vec<char> = raw.chars().collect();
    let mut segments = Vec::with_capacity(raw_segments.len());
    let mut total_tokens = 0usize;
    for raw_segment in raw_segments {
        let text: String = chars[raw_segment.start..raw_segment.end].iter().collect();
        let tokens = match shell_tokens(&text) {
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
        let executable = tokens.get(executable_index).cloned();
        let arguments = if executable.is_some() {
            tokens[executable_index + 1..].to_vec()
        } else {
            Vec::new()
        };
        if executable.as_deref().is_some_and(is_shell_control_keyword) {
            return Ok(uncertain(request, raw, "compound_shell_not_yet_supported"));
        }
        if executable.as_deref().is_some_and(is_transparent_wrapper) {
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
            wrapper_chain: Vec::new(),
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
    Ok(CanonicalCommandV1 {
        normalized_text: raw.to_owned(),
        dialect: request.dialect.clone(),
        transport: request.transport.clone(),
        extraction_provenance: request.extraction_provenance.clone(),
        wrapper_chain: Vec::new(),
        segments,
        confidence: "exact".to_owned(),
        uncertainty_reason: None,
        path_overridden,
        parser_profile: "posix-simple-v1".to_owned(),
    })
}

fn uncertain(request: &CommandModelRequestV1, raw: &str, reason: &str) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
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
    }
}

fn split_execution_segments(command: &str) -> Result<Vec<RawSegment>, &'static str> {
    let chars: Vec<char> = command.chars().collect();
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut segments = Vec::new();
    let mut segment_start = 0usize;
    let mut group_index = 0usize;
    let mut pipeline_index = 0usize;
    let mut index = 0usize;

    while index < chars.len() {
        let current = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
                index += 1;
                continue;
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '`' || (current == '$' && chars.get(index + 1) == Some(&'(')) {
                    return Err("command_substitution_not_yet_supported");
                }
                index += 1;
                continue;
            }
            Quote::None => {}
        }

        match current {
            '\'' => quote = Quote::Single,
            '"' => quote = Quote::Double,
            '\\' => escaped = true,
            '`' => return Err("command_substitution_not_yet_supported"),
            '$' if chars.get(index + 1) == Some(&'(') => {
                return Err("command_substitution_not_yet_supported");
            }
            '$' if chars
                .get(index + 1)
                .is_some_and(|next| *next == '\'' || *next == '"') =>
            {
                return Err("non_posix_quoting_not_yet_supported");
            }
            '<' | '>' => return Err("command_redirect_not_yet_supported"),
            '(' | ')' | '{' | '}' => return Err("compound_shell_not_yet_supported"),
            '&' => {
                if chars.get(index + 1) != Some(&'&') {
                    return Err("background_job_not_yet_supported");
                }
                push_segment(
                    &chars,
                    segment_start,
                    index,
                    group_index,
                    pipeline_index,
                    &mut segments,
                )?;
                index += 1;
                segment_start = index + 1;
                group_index += 1;
                pipeline_index = 0;
            }
            '|' => {
                let logical_or = chars.get(index + 1) == Some(&'|');
                push_segment(
                    &chars,
                    segment_start,
                    index,
                    group_index,
                    pipeline_index,
                    &mut segments,
                )?;
                if logical_or {
                    index += 1;
                    group_index += 1;
                    pipeline_index = 0;
                } else {
                    pipeline_index += 1;
                }
                segment_start = index + 1;
            }
            ';' | '\n' => {
                push_segment(
                    &chars,
                    segment_start,
                    index,
                    group_index,
                    pipeline_index,
                    &mut segments,
                )?;
                segment_start = index + 1;
                group_index += 1;
                pipeline_index = 0;
            }
            _ => {}
        }
        index += 1;
    }

    if quote != Quote::None || escaped {
        return Err("malformed_shell_quoting");
    }
    push_segment(
        &chars,
        segment_start,
        chars.len(),
        group_index,
        pipeline_index,
        &mut segments,
    )?;
    if segments.is_empty() {
        return Err("empty_command_segment");
    }
    Ok(segments)
}

fn push_segment(
    chars: &[char],
    start: usize,
    end: usize,
    group_index: usize,
    pipeline_index: usize,
    output: &mut Vec<RawSegment>,
) -> Result<(), &'static str> {
    let mut left = start;
    let mut right = end;
    while left < right && chars[left].is_whitespace() {
        left += 1;
    }
    while right > left && chars[right - 1].is_whitespace() {
        right -= 1;
    }
    if left == right {
        return Err("empty_command_segment");
    }
    output.push(RawSegment {
        group_index,
        pipeline_index,
        start: left,
        end: right,
    });
    Ok(())
}

fn shell_tokens(command: &str) -> Result<Vec<String>, &'static str> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = Quote::None;
    let mut escaped = false;

    for current in command.chars() {
        if escaped {
            if quote == Quote::Double && current != '"' && current != '\\' {
                token.push('\\');
            }
            token.push(current);
            token_started = true;
            escaped = false;
            continue;
        }
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                } else {
                    token.push(current);
                    token_started = true;
                }
            }
            Quote::Double => {
                if current == '"' {
                    quote = Quote::None;
                } else if current == '\\' {
                    escaped = true;
                    token_started = true;
                } else {
                    token.push(current);
                    token_started = true;
                }
            }
            Quote::None => match current {
                '\'' => {
                    quote = Quote::Single;
                    token_started = true;
                }
                '"' => {
                    quote = Quote::Double;
                    token_started = true;
                }
                '\\' => {
                    escaped = true;
                    token_started = true;
                }
                value if is_shell_token_whitespace(value) => {
                    if token_started {
                        tokens.push(std::mem::take(&mut token));
                        token_started = false;
                    }
                }
                value => {
                    token.push(value);
                    token_started = true;
                }
            },
        }
    }
    if quote != Quote::None || escaped {
        return Err("malformed_shell_quoting");
    }
    if token_started {
        tokens.push(token);
    }
    Ok(tokens)
}

fn is_shell_token_whitespace(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\r' | '\n')
}

fn assignment_name(token: &str) -> Option<&str> {
    let (name, _value) = token.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !chars.all(|value| value == '_' || value.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}
fn executable_basename(executable: &str) -> &str {
    executable.rsplit(['/', '\\']).next().unwrap_or(executable)
}

fn is_shell_control_keyword(executable: &str) -> bool {
    if executable.contains('/') {
        return false;
    }
    matches!(
        executable,
        "!" | "[["
            | "case"
            | "coproc"
            | "do"
            | "done"
            | "elif"
            | "else"
            | "esac"
            | "fi"
            | "for"
            | "function"
            | "if"
            | "in"
            | "select"
            | "then"
            | "until"
            | "while"
    )
}

fn is_transparent_wrapper(executable: &str) -> bool {
    matches!(
        executable_basename(executable),
        "ash"
            | "bash"
            | "command"
            | "dash"
            | "doas"
            | "env"
            | "fish"
            | "lean-ctx"
            | "nice"
            | "nohup"
            | "setsid"
            | "sh"
            | "stdbuf"
            | "sudo"
            | "time"
            | "timeout"
            | "zsh"
    )
}

fn is_nested_command_executor(executable: &str, arguments: &[String]) -> bool {
    let basename = executable_basename(executable);
    if matches!(
        basename,
        "." | "eval" | "exec" | "parallel" | "source" | "xargs"
    ) {
        return true;
    }
    basename == "find"
        && arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(command: &str) -> CommandModelRequestV1 {
        CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: default_dialect(),
            transport: default_transport(),
            extraction_provenance: default_provenance(),
        }
    }

    #[test]
    fn parses_simple_command_without_execution() {
        let parsed = parse_command(&request("git status --short")).unwrap();
        assert_eq!(parsed.confidence, "exact");
        assert_eq!(parsed.segments.len(), 1);
        assert_eq!(parsed.segments[0].executable.as_deref(), Some("git"));
        assert_eq!(parsed.segments[0].arguments, ["status", "--short"]);
        assert_eq!(parsed.segments[0].span.start, 0);
        assert_eq!(parsed.segments[0].span.end, 18);
    }

    #[test]
    fn preserves_quotes_environment_and_path_override() {
        let parsed = parse_command(&request("FOO=bar PATH=/tmp tool --name 'two words'")).unwrap();
        let segment = &parsed.segments[0];
        assert_eq!(segment.environment_names, ["FOO", "PATH"]);
        assert_eq!(segment.executable.as_deref(), Some("tool"));
        assert_eq!(segment.arguments, ["--name", "two words"]);
        assert!(segment.path_overridden);
        assert!(parsed.path_overridden);
    }

    #[test]
    fn matches_python_shlex_escape_and_whitespace_semantics() {
        let parsed = parse_command(&request(
            "printf \"%s\" \"a\\q\" \"a\\$b\" \"a\\\"b\" \"a\\\\b\" x\u{00a0}y",
        ))
        .unwrap();
        assert_eq!(parsed.confidence, "exact");
        assert_eq!(
            parsed.segments[0].tokens,
            [
                "printf",
                "%s",
                "a\\q",
                "a\\$b",
                "a\"b",
                "a\\b",
                "x\u{00a0}y"
            ]
        );
    }

    #[test]
    fn splits_pipeline_but_not_quoted_pipe() {
        let parsed = parse_command(&request("printf 'a|b' | grep b")).unwrap();
        assert_eq!(parsed.segments.len(), 2);
        assert_eq!(parsed.segments[0].tokens, ["printf", "a|b"]);
        assert_eq!(parsed.segments[0].pipeline_index, 0);
        assert_eq!(parsed.segments[1].tokens, ["grep", "b"]);
        assert_eq!(parsed.segments[1].pipeline_index, 1);
    }

    #[test]
    fn marks_complex_shell_forms_uncertain_without_partial_segments() {
        for command in [
            "echo $(uname)",
            "cat <<EOF",
            "echo hello > out.txt",
            "sleep 1 &",
            "sudo rm -rf /tmp/example",
            "sh -c 'rm -rf /tmp/example'",
            "eval 'rm -rf /tmp/example'",
            "if true; then echo yes; fi",
            "[[ -f Cargo.toml ]]",
            "echo $'non-posix quote'",
            "xargs rm -rf",
            "find . -exec rm {} ;",
        ] {
            let parsed = parse_command(&request(command)).unwrap();
            assert_eq!(parsed.confidence, "uncertain", "{command}");
            assert!(parsed.segments.is_empty(), "{command}");
            assert!(parsed.uncertainty_reason.is_some(), "{command}");
        }
    }

    #[test]
    fn rejects_oversized_commands_without_partial_exact_parse() {
        let parsed = parse_command(&request(&"x".repeat(MAX_COMMAND_BYTES + 1))).unwrap();
        assert_eq!(parsed.confidence, "uncertain");
        assert_eq!(
            parsed.uncertainty_reason.as_deref(),
            Some("command_byte_limit_exceeded")
        );
        assert!(parsed.segments.is_empty());
    }
}
