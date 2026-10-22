use crate::parser_executables::*;
use crate::parser_segments::*;
use crate::{
    canonical_command, inline_shell_quoting, parser_wrappers, powershell_command, powershell_reads,
    read_only_fanout,
};
use serde::{Deserialize, Serialize};

pub const MAX_COMMAND_BYTES: usize = 32_768;
pub const MAX_COMMAND_SEGMENTS: usize = 128;
pub const MAX_COMMAND_TOKENS: usize = 2_048;

pub(crate) fn default_dialect() -> String {
    "posix".to_owned()
}

pub(crate) fn default_transport() -> String {
    "shell_string".to_owned()
}

pub(crate) fn default_provenance() -> String {
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
pub(crate) enum Quote {
    None,
    Single,
    Double,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSegment {
    pub(crate) group_index: usize,
    pub(crate) pipeline_index: usize,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub fn parse_command(request: &CommandModelRequestV1) -> Result<CanonicalCommandV1, String> {
    let mut command = parse_command_unbound(request)?;
    command.security_identity = canonical_command::command_security_identity(&command);
    Ok(command)
}

pub(crate) fn parse_command_unbound(
    request: &CommandModelRequestV1,
) -> Result<CanonicalCommandV1, String> {
    let raw = request.command.trim();
    if request.dialect == "powershell" && request.transport == "shell_string" && !raw.is_empty() {
        return Ok(parse_explicit_powershell(request, raw));
    }
    if let Some(model) = parse_inline_shell_script(request, raw) {
        return Ok(model);
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
    // Otherwise retry input that POSIX cannot prove, or where it only saw a
    // read-only cmdlet as an unknown word. Either keeps POSIX if PowerShell fails.
    if (posix.confidence != "exact" || powershell_command::names_powershell_benign(&posix.segments))
        && raw.chars().count() <= MAX_COMMAND_BYTES
        && raw.len() <= MAX_COMMAND_BYTES
    {
        if let Ok(model) = powershell_command::parse(request, raw) {
            return Ok(model);
        }
    }
    Ok(posix)
}

/// A shell whose whole script is in this same text, modelled from that script.
///
/// `sh -c 'npm run build'` runs the programs those words name, yet every `-c`
/// form reached `transparent_wrapper_not_yet_supported` and blocked outright,
/// with no approval left to give it, while the same words without the shell in
/// front modelled exactly. The script is parsed as the command text it is, so
/// it reaches the rules, proofs and floors its own words reach, and nothing
/// else: a wrapped `rm -rf /` still blocks and a wrapped `gh pr merge --auto`
/// still needs fresh approval.
///
/// Only the spellings that read no startup file are modelled this way: `sh -c`,
/// `bash -c`, `dash -c` and `ash -c`. A login shell (`-lc`) sources the profile
/// files first and `zsh` reads `~/.zshenv` whatever option it is given, so
/// those run code this text does not hold and keep the wrapper's own
/// uncertainty. The bounded shape is what keeps the rest true: three words, a
/// known shell, the `-c` option, and no expansion the parser would have to
/// guess at. Anything else — an extra operand, `-s`, a prefix, a shell this
/// text only names — keeps that uncertainty too, as does a script this parser
/// cannot model exactly.
///
/// A Windows agent runs PowerShell, which reads quotes differently from the
/// shell this text names: `''` closes and reopens a POSIX single-quoted word
/// while PowerShell hands the shell a literal `'`. Where the two readings could
/// disagree about where the script ends, that host keeps the existing
/// PowerShell path instead of an exact model of a command the shell would
/// never run. A plain quoted script reads the same under both, so it is
/// modelled there too (`inline_shell_quoting`).
///
/// The raw text is no longer the command, so `exact_raw_text` is false and a
/// matcher that reads the literal raw spelling keeps failing closed.
pub(crate) fn parse_inline_shell_script(
    request: &CommandModelRequestV1,
    raw: &str,
) -> Option<CanonicalCommandV1> {
    if request.dialect != "posix"
        || request.transport != "shell_string"
        || (powershell_reads::windows_powershell_host()
            && !inline_shell_quoting::powershell_reads_the_same_words(raw))
    {
        return None;
    }
    let script = parser_wrappers::inline_shell_script(raw)?;
    let mut model = parse_posix_command(&CommandModelRequestV1 {
        command: script,
        ..request.clone()
    })
    .ok()?;
    if model.confidence != "exact" || model.segments.is_empty() {
        return None;
    }
    model.exact_raw_text = false;
    Some(model)
}

pub(crate) fn parse_explicit_powershell(
    request: &CommandModelRequestV1,
    raw: &str,
) -> CanonicalCommandV1 {
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

/// `2>&1` and `>&1`. A path or a program never has this shape.
pub(crate) fn is_fd_dup_redirect(token: &str) -> bool {
    let bytes = token.as_bytes();
    let rest = bytes
        .strip_prefix(b"2>&")
        .or_else(|| bytes.strip_prefix(b">&"));
    rest.is_some_and(|rest| !rest.is_empty() && rest.iter().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn parse_posix_command(
    request: &CommandModelRequestV1,
) -> Result<CanonicalCommandV1, String> {
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
            if let Some(name) = assignment_name(&tokens[executable_index]) {
                environment_names.push(name.to_owned());
                executable_index += 1;
                continue;
            }
            // `;2>&1 python3 evil.py` tokenizes the redirect as the first word.
            // It is not the program.
            if is_fd_dup_redirect(&tokens[executable_index]) {
                executable_index += 1;
                continue;
            }
            break;
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

pub(crate) fn uncertain(
    request: &CommandModelRequestV1,
    raw: &str,
    reason: &str,
) -> CanonicalCommandV1 {
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
