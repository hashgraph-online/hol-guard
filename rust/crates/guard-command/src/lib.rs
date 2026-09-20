#![forbid(unsafe_code)]
mod command_ascii_comparison;
mod command_common_cli_matchers;
pub mod command_compatibility;
mod command_database_matchers;
mod command_operand_matchers;
mod command_option_parsing;
mod command_specialized_matchers;
mod command_structured_matchers;
mod executable_flag_contract;
pub mod native_command_controls;
pub mod native_command_program;
mod parser_wrappers;
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

    let raw_segments = if let Some(value) = contained_compile_check_segments(raw) {
        value
    } else {
        match split_execution_segments(raw) {
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
        let (executable_index, wrapper_chain) =
            match parser_wrappers::unwrap_sudo(&tokens, executable_index) {
                Ok(value) => value,
                Err(reason) => return Ok(uncertain(request, raw, reason)),
            };
        let executable = tokens.get(executable_index).cloned();
        let arguments = if executable.is_some() {
            tokens[executable_index + 1..].to_vec()
        } else {
            Vec::new()
        };
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
            '$' if chars.get(index + 1) == Some(&'{') => {
                return Err("parameter_expansion_not_yet_supported");
            }
            '$' if chars
                .get(index + 1)
                .is_some_and(|next| *next == '\'' || *next == '"') =>
            {
                return Err("non_posix_quoting_not_yet_supported");
            }
            '<' | '>' if is_stderr_to_stdout_redirect(&chars, index) => {}
            '<' | '>' => return Err("command_redirect_not_yet_supported"),
            '(' | ')' => return Err("compound_shell_not_yet_supported"),
            '{' | '}'
                if (index == 0
                    || is_shell_token_whitespace(chars[index - 1])
                    || matches!(chars[index - 1], ';' | '&' | '|'))
                    && chars.get(index + 1).is_none_or(|value| {
                        is_shell_token_whitespace(*value) || matches!(*value, ';' | '&' | '|')
                    }) =>
            {
                return Err("compound_shell_not_yet_supported");
            }
            '&' => {
                if is_stderr_to_stdout_redirect(&chars, index) {
                    index += 1;
                    continue;
                }
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

fn contained_compile_check_segments(command: &str) -> Option<Vec<RawSegment>> {
    let chars: Vec<char> = command.chars().collect();
    let and_index = chars.windows(2).position(|window| window == ['&', '&'])?;
    if chars[and_index + 2..]
        .windows(2)
        .any(|window| window == ['&', '&'])
    {
        return None;
    }
    let (cd_start, cd_end) = trimmed_bounds(&chars, 0, and_index)?;
    let (find_start, find_end) = trimmed_bounds(&chars, and_index + 2, chars.len())?;
    let cd: String = chars[cd_start..cd_end].iter().collect();
    let find: String = chars[find_start..find_end].iter().collect();
    let cd_tokens = shell_tokens(&cd).ok()?;
    let find_tokens = shell_tokens(&find).ok()?;
    if cd_tokens.len() != 2
        || cd_tokens.first().map(String::as_str) != Some("cd")
        || !is_plain_cd_target(&cd_tokens[1])
        || find_tokens.first().map(String::as_str) != Some("find")
        || !is_contained_compile_check_arguments(&find_tokens[1..])
    {
        return None;
    }
    Some(vec![
        RawSegment {
            group_index: 0,
            pipeline_index: 0,
            start: cd_start,
            end: cd_end,
        },
        RawSegment {
            group_index: 1,
            pipeline_index: 0,
            start: find_start,
            end: find_end,
        },
    ])
}

fn trimmed_bounds(chars: &[char], start: usize, end: usize) -> Option<(usize, usize)> {
    let mut left = start;
    let mut right = end;
    while left < right && chars[left].is_whitespace() {
        left += 1;
    }
    while right > left && chars[right - 1].is_whitespace() {
        right -= 1;
    }
    (left < right).then_some((left, right))
}

fn is_stderr_to_stdout_redirect(chars: &[char], index: usize) -> bool {
    let start = match chars.get(index) {
        Some('&') => index.checked_sub(2),
        Some('>') => index.checked_sub(1),
        _ => None,
    };
    let Some(start) = start else {
        return false;
    };
    let Some(redirect) = chars.get(start..start.saturating_add(4)) else {
        return false;
    };
    redirect == ['2', '>', '&', '1']
        && (start == 0 || is_shell_token_whitespace(chars[start - 1]))
        && chars.get(start + 4).is_none_or(|value| {
            is_shell_token_whitespace(*value) || matches!(*value, '|' | '&' | ';')
        })
}

fn is_plain_cd_target(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && !value.chars().any(|value| {
            matches!(
                value,
                '$' | '`' | '<' | '>' | '|' | ';' | '&' | '(' | ')' | '{' | '}' | '\0'
            )
        })
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
    if matches!(basename, "fd" | "fd.exe") {
        return fd_arguments_execute_command(arguments);
    }
    basename == "find"
        && !is_contained_compile_check_arguments(arguments)
        && arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
}

fn fd_arguments_execute_command(arguments: &[String]) -> bool {
    // fd substitutes filesystem search results into a subprocess invocation.
    // Its exec modes need their own bounded source and execution proof; an
    // exact shell tokenization must not silently treat them as a plain search.
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return false;
        }
        if matches!(argument.as_str(), "--exec" | "--exec-batch")
            || argument.starts_with("--exec=")
            || argument.starts_with("--exec-batch=")
        {
            return true;
        }
        if argument.starts_with("--") {
            if matches!(
                argument.as_str(),
                "--base-directory"
                    | "--changed-after"
                    | "--changed-before"
                    | "--changed-within"
                    | "--color"
                    | "--exact-depth"
                    | "--exclude"
                    | "--extension"
                    | "--format"
                    | "--ignore-file"
                    | "--max-depth"
                    | "--max-results"
                    | "--min-depth"
                    | "--owner"
                    | "--path-separator"
                    | "--search-path"
                    | "--size"
                    | "--threads"
                    | "--type"
            ) {
                arguments.next();
            }
            continue;
        }
        let Some(cluster) = argument.strip_prefix('-') else {
            continue;
        };
        for (offset, flag) in cluster.char_indices() {
            if matches!(flag, 'x' | 'X') {
                return true;
            }
            if matches!(flag, 'c' | 'd' | 'E' | 'e' | 'j' | 'o' | 'S' | 't') {
                if offset + flag.len_utf8() == cluster.len() {
                    arguments.next();
                }
                break;
            }
        }
    }
    false
}

fn is_contained_compile_check_arguments(arguments: &[String]) -> bool {
    const EXPECTED: [&str; 9] = [
        "src",
        "-name",
        "*.py",
        "-exec",
        "python",
        "-m",
        "py_compile",
        "{}",
        "+",
    ];
    arguments.len() == EXPECTED.len()
        && arguments
            .iter()
            .zip(EXPECTED)
            .all(|(actual, expected)| actual == expected)
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
    fn parses_frozen_contained_routine_forms_without_general_shell_expansion() {
        let stderr_pipeline = parse_command(&request(
            "cd workspace/service && bun run typecheck 2>&1 | head -40",
        ))
        .unwrap();
        assert_eq!(
            stderr_pipeline.confidence, "exact",
            "{:?}",
            stderr_pipeline.uncertainty_reason
        );
        assert_eq!(stderr_pipeline.segments.len(), 3);
        assert_eq!(
            stderr_pipeline.segments[1].arguments,
            ["run", "typecheck", "2>&1"]
        );
        assert_eq!(stderr_pipeline.segments[2].tokens, ["head", "-40"]);

        let compile_check = parse_command(&request(
            "cd workspace/service && find src -name '*.py' -exec python -m py_compile {} +",
        ))
        .unwrap();
        assert_eq!(compile_check.confidence, "exact");
        assert_eq!(compile_check.segments.len(), 2);
        assert_eq!(
            compile_check.segments[1].arguments,
            [
                "src",
                "-name",
                "*.py",
                "-exec",
                "python",
                "-m",
                "py_compile",
                "{}",
                "+"
            ]
        );
    }

    #[test]
    fn marks_complex_shell_forms_uncertain_without_partial_segments() {
        for command in [
            "echo $(uname)",
            "cat <<EOF",
            "echo hello > out.txt",
            "sleep 1 &",
            "sudo -s rm -rf /tmp/example",
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
