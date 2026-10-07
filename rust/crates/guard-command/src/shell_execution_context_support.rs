//! Private lexer and path helpers for shell execution-context modeling
//! (`runtime/_shell_execution_context_support.py`, 595 lines — verbatim).

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::shell_structure::extract_heredocs;

#[cfg(unix)]
fn stat_mode(m: &std::fs::Metadata) -> u32 {
    m.mode()
}
#[cfg(not(unix))]
fn stat_mode(m: &std::fs::Metadata) -> u32 {
    m.file_attributes()
}

pub const SHELL_CWD_UNRESOLVED_EXPRESSION: &str = "shell_cwd_unresolved_expression";
pub const SHELL_CWD_MISSING_DIRECTORY: &str = "shell_cwd_missing_directory";
pub const SHELL_CWD_NOT_DIRECTORY: &str = "shell_cwd_not_directory";
pub const SHELL_CWD_UNREADABLE_DIRECTORY: &str = "shell_cwd_unreadable_directory";
pub const SHELL_CWD_AMBIGUOUS_STACK: &str = "shell_cwd_ambiguous_stack";
pub const SHELL_CWD_STACK_LIMIT: &str = "shell_cwd_stack_limit";
pub const SHELL_CWD_WORKSPACE_ESCAPE: &str = "shell_cwd_workspace_escape";
pub const SHELL_CWD_SYMLINK_ESCAPE: &str = "shell_cwd_symlink_escape";
pub const SHELL_CWD_UNRESOLVED_CONTROL_FLOW: &str = "shell_cwd_unresolved_control_flow";
pub const SHELL_CWD_UNRESOLVED_PARENT_SHELL: &str = "shell_cwd_unresolved_parent_shell_effect";
pub const SHELL_CWD_UNRESOLVED_SYNTAX: &str = "shell_cwd_unresolved_syntax";
pub const SHELL_CWD_PATH_CHANGED: &str = "shell_cwd_path_changed";

pub const MAX_DIRECTORY_STACK_DEPTH: usize = 32;

const NEWLINE_SENTINEL: &str = "__HOL_GUARD_SHELL_NEWLINE__";
const FD_AMPERSAND_SENTINEL: &str = "__HOL_GUARD_SHELL_FD_AMPERSAND__";
const NOCLOBBER_PIPE_SENTINEL: &str = "__GUARD_SHELL_NOCLOBBER_PIPE__";
const FIND_PLACEHOLDER_SENTINEL: &str = "__HOL_GUARD_FIND_PLACEHOLDER__";
const ESCAPED_SEMICOLON_SENTINEL: &str = "__HOL_GUARD_ESCAPED_SEMICOLON__";

fn flow_operators() -> &'static [&'static str] {
    &["&&", "||", ";", "\n", "|", "|&", "&"]
}
fn group_operators() -> &'static [&'static str] {
    &["(", ")", "{", "}"]
}
fn is_control_token(t: &str) -> bool {
    flow_operators().contains(&t) || group_operators().contains(&t)
}
fn directory_commands() -> &'static [&'static str] {
    &["cd", "pushd", "popd"]
}
const UNMODELED_SHELL_CONTROL_WORDS: &[&str] =
    &["do", "elif", "else", "if", "then", "until", "while"];

fn shell_assignment(t: &str) -> bool {
    match t.find('=') {
        None => false,
        Some(i) => {
            let name = &t[..i];
            !name.is_empty()
                && name
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic() || c == '_')
                    .unwrap_or(false)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

fn redirection_token(t: &str) -> bool {
    // `^(?:[012]?(?:>|>>|<|<<|<>).*)$`
    let chars: Vec<char> = t.chars().collect();
    let mut i = 0;
    if i < chars.len() && matches!(chars[i], '0' | '1' | '2') {
        i += 1;
    }
    if i >= chars.len() {
        return false;
    }
    match chars[i] {
        '>' => i + 1 == chars.len() || chars[i + 1] == '>',
        '<' => i + 1 == chars.len() || chars[i + 1] == '<' || chars[i + 1] == '>',
        _ => false,
    }
}

/// `ShellPathIdentity` (:47-66).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellPathIdentity {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub change_time_ns: i64,
    pub creation_time_ns: i64,
}

impl ShellPathIdentity {
    #[cfg(unix)]
    pub fn from_stat(m: &std::fs::Metadata) -> Self {
        ShellPathIdentity {
            device: m.dev(),
            inode: m.ino(),
            mode: m.mode() & 0o170000, // S_IFMT
            change_time_ns: m.ctime() * 1_000_000_000 + m.ctime_nsec(),
            creation_time_ns: m
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| (d.as_secs_f64() * 1_000_000_000.0) as i64)
                .unwrap_or(0),
        }
    }

    /// Windows has no POSIX st_dev/st_ino/ctime — map volume serial, file
    /// index and change time into the same tuple shape so identity digests
    /// stay deterministic per-platform (Python falls back to `st_dev`/`st_ino`
    /// via `os.stat` which Windows reports as volume/index anyway).
    #[cfg(windows)]
    pub fn from_stat(m: &std::fs::Metadata) -> Self {
        let write_ns = (m.last_write_time() / 100) as i64;
        ShellPathIdentity {
            device: 0,
            inode: 0,
            mode: m.file_attributes() & 0o170000,
            change_time_ns: write_ns,
            creation_time_ns: m
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(write_ns),
        }
    }
}

/// `shell_path_identity_payload` (:69-80) → JSON or None.
pub fn shell_path_identity_payload(
    identity: Option<&ShellPathIdentity>,
) -> Option<serde_json::Value> {
    identity.map(|i| {
        serde_json::json!({
            "change_time_ns": i.change_time_ns,
            "creation_time_ns": i.creation_time_ns,
            "device": i.device,
            "inode": i.inode,
            "mode": i.mode,
        })
    })
}

/// `ShellPathProof` (:83-89).
#[derive(Clone, Debug)]
pub struct ShellPathProof {
    pub lexical_path: PathBuf,
    pub resolved_path: PathBuf,
    pub identity: ShellPathIdentity,
}

/// `DirectoryOperation` (:92-96).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryOperation {
    pub name: String,
    pub operand: Option<String>,
    pub reason_code: Option<&'static str>,
}

/// `_remove_shell_line_continuations` (:99-136).
fn remove_shell_line_continuations(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let n = chars.len();
    let mut result: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while index < n {
        let character = chars[index];
        if character == '\'' && quote.is_none() {
            quote = Some('\'');
            result.push(character);
            index += 1;
            continue;
        }
        if character == '\'' && quote == Some('\'') {
            quote = None;
            result.push(character);
            index += 1;
            continue;
        }
        if (character == '"' || character == '`') && quote.is_none() {
            quote = Some(character);
            result.push(character);
            index += 1;
            continue;
        }
        if Some(character) == quote && (quote == Some('"') || quote == Some('`')) {
            quote = None;
            result.push(character);
            index += 1;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            if index + 2 < n && chars[index + 1] == '\r' && chars[index + 2] == '\n' {
                index += 3;
                continue;
            }
            if index + 1 < n && chars[index + 1] == '\n' {
                index += 2;
                continue;
            }
        }
        result.push(character);
        index += 1;
    }
    result.iter().collect()
}

/// `split_shell_tokens` (:139-170). shlex posix + punctuation_chars `;&|(){}`,
/// whitespace_split, commenters off.
pub fn split_shell_tokens(command_text: &str) -> Result<Vec<String>, String> {
    let command_text = mask_heredoc_bodies_local(command_text);
    let command_text = remove_shell_line_continuations(&command_text);
    let command_text = protect_fd_redirection_ampersands(&command_text)?;
    if command_text.contains(FIND_PLACEHOLDER_SENTINEL)
        || command_text.contains(ESCAPED_SEMICOLON_SENTINEL)
    {
        return Err("reserved shell parsing sentinel".to_owned());
    }
    // `re.sub(r"(?<!\S)\{\}(?!\S)", _FIND_PLACEHOLDER_SENTINEL, ...)` —
    // whitespace-bounded `{}` replaced.
    let command_text = protect_find_placeholder(&command_text);
    let command_text = protect_escaped_semicolons(&command_text);
    let command_text = replace_unquoted_newlines(&command_text);
    let raw = punctuation_shlex(&command_text)?;
    let mut tokens: Vec<String> = Vec::new();
    for token in raw {
        if token == NEWLINE_SENTINEL {
            tokens.push("\n".to_owned());
        } else if !token.is_empty() && token.chars().all(|c| ";&|(){}".contains(c)) {
            tokens.extend(split_punctuation_run(&token));
        } else {
            tokens.push(
                token
                    .replace(FD_AMPERSAND_SENTINEL, "&")
                    .replace(NOCLOBBER_PIPE_SENTINEL, "|")
                    .replace(FIND_PLACEHOLDER_SENTINEL, "{}")
                    .replace(ESCAPED_SEMICOLON_SENTINEL, "\\;"),
            );
        }
    }
    Ok(tokens)
}

/// `re.sub(r"(?<!\S)\{\}(?!\S)", sentinel, text)` — `{}` not preceded/followed
/// by a non-whitespace char.
fn protect_find_placeholder(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(command_text.len());
    let mut i = 0;
    while i < n {
        if chars[i] == '{'
            && i + 1 < n
            && chars[i + 1] == '}'
            && (i == 0 || chars[i - 1].is_whitespace())
            && (i + 2 >= n || chars[i + 2].is_whitespace())
        {
            out.push_str(FIND_PLACEHOLDER_SENTINEL);
            i += 2;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// `_protect_escaped_semicolons` (:173-194).
fn protect_escaped_semicolons(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let n = chars.len();
    let mut result: Vec<String> = Vec::new();
    let mut quote: Option<char> = None;
    let mut index = 0;
    while index < n {
        let character = chars[index];
        if character == '\\' && quote != Some('\'') {
            let next_character = if index + 1 < n {
                Some(chars[index + 1])
            } else {
                None
            };
            if quote.is_none() && next_character == Some(';') {
                result.push(ESCAPED_SEMICOLON_SENTINEL.to_owned());
            } else {
                result.push(character.to_string());
                if let Some(nc) = next_character {
                    result.push(nc.to_string());
                }
            }
            index += if next_character.is_some() { 2 } else { 1 };
            continue;
        }
        if character == '\'' || character == '"' {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
        }
        result.push(character.to_string());
        index += 1;
    }
    result.concat()
}

/// `_protect_fd_redirection_ampersands` (:197-233).
fn protect_fd_redirection_ampersands(command_text: &str) -> Result<String, String> {
    if command_text.contains(FD_AMPERSAND_SENTINEL)
        || command_text.contains(NOCLOBBER_PIPE_SENTINEL)
    {
        return Err("reserved shell parsing sentinel".to_owned());
    }
    let chars: Vec<char> = command_text.chars().collect();
    let n = chars.len();
    let mut result: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0;
    while index < n {
        let character = chars[index];
        if escaped {
            result.push(character);
            escaped = false;
            index += 1;
            continue;
        }
        if character == '\\' {
            result.push(character);
            escaped = true;
            index += 1;
            continue;
        }
        if quote.is_none() && (character == '\'' || character == '"' || character == '`') {
            quote = Some(character);
            result.push(character);
            index += 1;
            continue;
        }
        if quote == Some(character) {
            quote = None;
            result.push(character);
            index += 1;
            continue;
        }
        if quote.is_none() && character == '|' && index > 0 && chars[index - 1] == '>' {
            result.extend(NOCLOBBER_PIPE_SENTINEL.chars());
        } else if quote.is_none() && character == '&' && is_adjacent_fd_duplication(&chars, index) {
            result.extend(FD_AMPERSAND_SENTINEL.chars());
        } else {
            result.push(character);
        }
        index += 1;
    }
    Ok(result.iter().collect())
}

/// `_is_adjacent_fd_duplication` (:236-254).
fn is_adjacent_fd_duplication(chars: &[char], ampersand_index: usize) -> bool {
    if ampersand_index == 0
        || !(chars[ampersand_index - 1] == '<' || chars[ampersand_index - 1] == '>')
    {
        return false;
    }
    if ampersand_index >= 2
        && (chars[ampersand_index - 2] == '<' || chars[ampersand_index - 2] == '>')
    {
        return false;
    }
    let mut target_index = ampersand_index + 1;
    if target_index >= chars.len() {
        return false;
    }
    let target_end;
    if chars[target_index] == '-' {
        target_end = target_index + 1;
    } else if chars[target_index].is_ascii_digit() {
        target_index += 1;
        while target_index < chars.len() && chars[target_index].is_ascii_digit() {
            target_index += 1;
        }
        target_end = target_index;
    } else {
        return false;
    }
    target_end == chars.len()
        || chars[target_end].is_whitespace()
        || ";&|(){}".contains(chars[target_end])
}

/// `_mask_heredoc_bodies` (:257-268) — *different* from `mask_heredoc_bodies`
/// in shell_structure: blanks from `body_start - 1` to `end`, preserving the
/// trailing newline.
fn mask_heredoc_bodies_local(command_text: &str) -> String {
    let heredocs = extract_heredocs(command_text);
    if heredocs.is_empty() {
        return command_text.to_owned();
    }
    let original: Vec<char> = command_text.chars().collect();
    let mut characters = original.clone();
    let len = characters.len();
    for heredoc in &heredocs {
        let start = heredoc.body_start.saturating_sub(1);
        let end = heredoc.end.min(len);
        for slot in characters[start..end].iter_mut() {
            *slot = ' ';
        }
        if heredoc.end > 0 && heredoc.end <= len && original[heredoc.end - 1] == '\n' {
            characters[heredoc.end - 1] = '\n';
        }
    }
    characters.iter().collect()
}

/// `_split_punctuation_run` (:271-282).
fn split_punctuation_run(token: &str) -> Vec<String> {
    let chars: Vec<char> = token.chars().collect();
    let mut result = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let pair: String = chars[index..(index + 2).min(chars.len())].iter().collect();
        if pair == "&&" || pair == "||" || pair == "|&" {
            result.push(pair);
            index += 2;
            continue;
        }
        result.push(chars[index].to_string());
        index += 1;
    }
    result
}

/// `_replace_unquoted_newlines` (:285-310).
fn replace_unquoted_newlines(command_text: &str) -> String {
    let chars: Vec<char> = command_text.chars().collect();
    let mut result: Vec<String> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for &character in &chars {
        if escaped {
            result.push(character.to_string());
            escaped = false;
            continue;
        }
        if character == '\\' {
            result.push(character.to_string());
            escaped = true;
            continue;
        }
        if quote.is_none() && (character == '\'' || character == '"' || character == '`') {
            quote = Some(character);
            result.push(character.to_string());
            continue;
        }
        if quote == Some(character) {
            quote = None;
            result.push(character.to_string());
            continue;
        }
        if quote.is_none() && (character == '\n' || character == '\r') {
            result.push(" ".to_owned());
            result.push(NEWLINE_SENTINEL.to_owned());
            result.push(" ".to_owned());
            continue;
        }
        result.push(character.to_string());
    }
    result.concat()
}

/// Minimal POSIX shlex with `punctuation_chars=";&|(){}"`, `whitespace_split`,
/// `commenters=""`, `escape` (POSIX `\\`; on Windows the lexer escapes nothing
/// since the port targets posix dialect). Mirrors the token boundaries the
/// Python lexer produces.
fn punctuation_shlex(command: &str) -> Result<Vec<String>, String> {
    #[cfg(windows)]
    let escape = '\0';
    #[cfg(not(windows))]
    let escape = '\\';
    let chars: Vec<char> = command.chars().collect();
    let n = chars.len();
    let mut tokens: Vec<String> = Vec::new();
    let mut current: Vec<char> = Vec::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut index = 0;
    let punctuation = |c: char| ";&|(){}".contains(c);
    let flush = |tokens: &mut Vec<String>, current: &mut Vec<char>, started: &mut bool| {
        if *started {
            tokens.push(current.iter().collect());
            current.clear();
            *started = false;
        }
    };
    while index < n {
        let c = chars[index];
        if let Some(q) = quote {
            if c == q {
                quote = None;
                index += 1;
                continue;
            }
            if c == escape && q == '"' && index + 1 < n {
                let nc = chars[index + 1];
                if matches!(nc, '"' | '\\' | '$' | '`' | '\n') {
                    if nc != '\n' {
                        current.push(nc);
                    }
                    started = true;
                    index += 2;
                    continue;
                }
            }
            current.push(c);
            started = true;
            index += 1;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            started = true;
            index += 1;
            continue;
        }
        if c == escape {
            if index + 1 < n {
                let nc = chars[index + 1];
                if nc == '\n' {
                    index += 2;
                    continue;
                }
                current.push(nc);
                started = true;
                index += 2;
                continue;
            }
            return Err("No escaped character".to_owned());
        }
        if c.is_whitespace() {
            flush(&mut tokens, &mut current, &mut started);
            index += 1;
            continue;
        }
        if punctuation(c) {
            // punctuation_chars: consecutive punctuation forms one run unless
            // a quote starts.
            flush(&mut tokens, &mut current, &mut started);
            let mut run = String::new();
            while index < n && punctuation(chars[index]) {
                run.push(chars[index]);
                index += 1;
            }
            tokens.push(run);
            continue;
        }
        current.push(c);
        started = true;
        index += 1;
    }
    if quote.is_some() {
        return Err("No closing quotation".to_owned());
    }
    flush(&mut tokens, &mut current, &mut started);
    Ok(tokens)
}

/// `ordered_segments` (:313-335) → `(segments, pending_controls)` where each
/// segment is `(tokens, controls_before)`.
#[allow(clippy::type_complexity)]
pub fn ordered_segments(tokens: &[String]) -> (Vec<(Vec<String>, Vec<String>)>, Vec<String>) {
    let mut segments: Vec<(Vec<String>, Vec<String>)> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut pending_controls: Vec<String> = Vec::new();
    let mut controls_before: Vec<String> = Vec::new();
    for token in tokens {
        if token != "{}" && (is_control_token(token) || is_unknown_control_token(token)) {
            if !current.is_empty() {
                segments.push((
                    std::mem::take(&mut current),
                    std::mem::take(&mut controls_before),
                ));
            }
            pending_controls.push(token.clone());
            continue;
        }
        if current.is_empty() {
            controls_before = std::mem::take(&mut pending_controls);
        }
        current.push(token.clone());
    }
    if !current.is_empty() {
        segments.push((current, controls_before));
        pending_controls.clear();
    }
    (segments, pending_controls)
}

/// `parent_shell_cwd_construct_reason` (:338-350).
pub fn parent_shell_cwd_construct_reason(
    segments: &[(Vec<String>, Vec<String>)],
    trailing_controls: &[String],
) -> Option<&'static str> {
    for index in 0..segments.len() {
        let (tokens, _cb) = &segments[index];
        let controls_after: &[String] = if index + 1 < segments.len() {
            &segments[index + 1].1
        } else {
            trailing_controls
        };
        if is_function_definition(tokens, controls_after)
            && function_body_may_change_cwd(segments, index)
        {
            return Some(SHELL_CWD_UNRESOLVED_PARENT_SHELL);
        }
        if segment_has_unmodeled_parent_cwd_effect(tokens) {
            return Some(SHELL_CWD_UNRESOLVED_PARENT_SHELL);
        }
    }
    None
}

/// `_is_function_definition` (:353-363).
fn is_function_definition(tokens: &[String], controls_after: &[String]) -> bool {
    let ident = |s: &str| {
        !s.is_empty()
            && s.chars()
                .next()
                .map(|c| c.is_ascii_alphabetic() || c == '_')
                .unwrap_or(false)
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if !controls_after.iter().any(|c| c == "{") {
        return false;
    }
    if tokens.len() >= 2 && tokens[0] == "function" {
        return ident(&tokens[1]);
    }
    tokens.len() == 1
        && ident(&tokens[0])
        && controls_after.iter().any(|c| c == "(")
        && controls_after.iter().any(|c| c == ")")
}

/// `_function_body_may_change_cwd` (:366-381).
fn function_body_may_change_cwd(
    segments: &[(Vec<String>, Vec<String>)],
    definition_index: usize,
) -> bool {
    let mut brace_depth = 0i32;
    for (tokens, controls_before) in &segments[definition_index + 1..] {
        for control in controls_before {
            if control == "{" {
                brace_depth += 1;
            } else if control == "}" {
                brace_depth -= 1;
            }
        }
        if brace_depth <= 0 {
            return false;
        }
        if directory_operation(tokens).is_some() || segment_has_unmodeled_parent_cwd_effect(tokens)
        {
            return true;
        }
    }
    false
}

/// `_segment_has_unmodeled_parent_cwd_effect` (:384-397).
fn segment_has_unmodeled_parent_cwd_effect(tokens: &[String]) -> bool {
    let mut index = 0;
    while index < tokens.len() && shell_assignment(&tokens[index]) {
        index += 1;
    }
    if index >= tokens.len() {
        return false;
    }
    let command = tokens[index].as_str();
    if command == "." || command == "eval" || command == "source" {
        return true;
    }
    if command != "trap" || index + 2 >= tokens.len() {
        return false;
    }
    let handler = &tokens[index + 1];
    let signals: std::collections::HashSet<String> = tokens[index + 2..]
        .iter()
        .map(|t| {
            let upper = t.to_uppercase();
            upper.strip_prefix("SIG").unwrap_or(&upper).to_owned()
        })
        .collect();
    signals.contains("DEBUG") && !handler.is_empty() && handler != "-"
}

/// `_is_unknown_control_token` (:400-401).
fn is_unknown_control_token(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| ";&|(){}".contains(c))
}

/// `control_sequence_reason` (:404-428).
pub fn control_sequence_reason(controls: &[String], trailing: bool) -> Option<&'static str> {
    if controls.iter().any(|c| !is_control_token(c)) {
        return Some(SHELL_CWD_UNRESOLVED_SYNTAX);
    }
    let mut flows: Vec<&String> = Vec::new();
    for (index, control) in controls.iter().enumerate() {
        if !flow_operators().contains(&control.as_str()) {
            continue;
        }
        let next_control = controls.get(index + 1).map(|s| s.as_str());
        if next_control == Some(")") || next_control == Some("}") {
            if !(control == ";" || control == "\n" || control == "&") {
                return Some(SHELL_CWD_UNRESOLVED_SYNTAX);
            }
            continue;
        }
        flows.push(control);
    }
    if trailing {
        if flows.is_empty() {
            return None;
        }
        if flows.len() == 1 && (flows[0] == ";" || flows[0] == "\n" || flows[0] == "&") {
            return None;
        }
        return Some(SHELL_CWD_UNRESOLVED_SYNTAX);
    }
    if flows.len() > 1 {
        return Some(SHELL_CWD_UNRESOLVED_SYNTAX);
    }
    None
}

/// `directory_operation` (:431-471).
pub fn directory_operation(tokens: &[String]) -> Option<DirectoryOperation> {
    let op =
        |name: &str, operand: Option<String>, reason: Option<&'static str>| DirectoryOperation {
            name: name.to_owned(),
            operand,
            reason_code: reason,
        };
    let mut index = 0;
    while index < tokens.len() && shell_assignment(&tokens[index]) {
        index += 1;
    }
    if index >= tokens.len() {
        return None;
    }
    let mut command = tokens[index].clone();
    if UNMODELED_SHELL_CONTROL_WORDS.contains(&command.as_str()) {
        if let Some(embedded) = tokens[index + 1..]
            .iter()
            .find(|t| directory_commands().contains(&t.as_str()))
        {
            return Some(op(embedded, None, Some(SHELL_CWD_UNRESOLVED_CONTROL_FLOW)));
        }
    }
    if command == "!"
        || command == "builtin"
        || command == "command"
        || command == "function"
        || command == "time"
    {
        let wrapped_index =
            (index + 1..tokens.len()).find(|&i| directory_commands().contains(&tokens[i].as_str()));
        match wrapped_index {
            None => return None,
            Some(wi) => {
                if (command == "command" || command == "time") && wi == index + 1 {
                    index = wi;
                    command = tokens[index].clone();
                } else {
                    return Some(op(&tokens[wi], None, Some(SHELL_CWD_UNRESOLVED_EXPRESSION)));
                }
            }
        }
    }
    if !directory_commands().contains(&command.as_str()) {
        return None;
    }
    let mut arguments = match directory_arguments(&tokens[index + 1..]) {
        Some(a) => a,
        None => return Some(op(&command, None, Some(SHELL_CWD_UNRESOLVED_EXPRESSION))),
    };
    if command == "popd" {
        if !arguments.is_empty() {
            return Some(op(&command, None, Some(SHELL_CWD_AMBIGUOUS_STACK)));
        }
        return Some(op(&command, None, None));
    }
    if command == "cd" && arguments.first().map(|a| a == "--").unwrap_or(false) {
        arguments.remove(0);
    } else if arguments
        .first()
        .map(|a| a.starts_with('-'))
        .unwrap_or(false)
    {
        return Some(op(&command, None, Some(SHELL_CWD_UNRESOLVED_EXPRESSION)));
    }
    if arguments.len() != 1 || operand_is_dynamic(&arguments[0]) {
        return Some(op(&command, None, Some(SHELL_CWD_UNRESOLVED_EXPRESSION)));
    }
    if command == "pushd" && pushd_stack_offset(&arguments[0]) {
        return Some(op(&command, None, Some(SHELL_CWD_AMBIGUOUS_STACK)));
    }
    Some(op(&command, Some(arguments.remove(0)), None))
}

/// `re.fullmatch(r"[+-]\d+", arg)` for the `pushd` stack-offset check.
fn pushd_stack_offset(arg: &str) -> bool {
    let t = arg.strip_prefix(['+', '-']).unwrap_or(arg);
    !t.is_empty()
        && t.len() == t.chars().filter(|c| c.is_ascii_digit()).count()
        && (arg.starts_with('+') || arg.starts_with('-'))
}

/// `_directory_arguments` (:474-489).
fn directory_arguments(tokens: &[String]) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if redirection_token(token) {
            if matches!(token.as_str(), ">" | ">>" | "<" | "<<" | "0>" | "1>" | "2>") {
                if index + 1 >= tokens.len() {
                    return None;
                }
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        arguments.push(token.clone());
        index += 1;
    }
    Some(arguments)
}

/// `_operand_is_dynamic` (:492-495).
fn operand_is_dynamic(value: &str) -> bool {
    if value.is_empty()
        || value.contains('\0')
        || (value.starts_with('~') && !value.starts_with("~/"))
    {
        return true;
    }
    value
        .chars()
        .any(|c| matches!(c, '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}' | '<' | '>'))
}

/// `resolve_directory_operand` (:498-538) → `(resolved, identity, proof, reason)`.
pub fn resolve_directory_operand(
    value: &str,
    current_cwd: &Path,
    workspace_root: &Path,
    home_dir: Option<&Path>,
) -> (
    Option<PathBuf>,
    Option<ShellPathIdentity>,
    Option<ShellPathProof>,
    Option<&'static str>,
) {
    let candidate: PathBuf = if let Some(rest) = value.strip_prefix("~/") {
        match home_dir {
            None => return (None, None, None, Some(SHELL_CWD_UNRESOLVED_EXPRESSION)),
            Some(h) => h.join(rest),
        }
    } else {
        PathBuf::from(value)
    };
    let candidate = if candidate.is_absolute() {
        candidate
    } else {
        current_cwd.join(candidate)
    };
    let lexical_candidate = abspath(&candidate);
    let resolved = match std::fs::canonicalize(&candidate) {
        Ok(r) => r,
        Err(e) => {
            use std::io::ErrorKind::*;
            let reason = match e.kind() {
                NotFound | NotADirectory => SHELL_CWD_MISSING_DIRECTORY,
                _ => SHELL_CWD_UNREADABLE_DIRECTORY,
            };
            return (None, None, None, Some(reason));
        }
    };
    let value_stat = match std::fs::metadata(&resolved) {
        Ok(m) => m,
        Err(_) => return (None, None, None, Some(SHELL_CWD_UNREADABLE_DIRECTORY)),
    };
    if !value_stat.is_dir() {
        return (None, None, None, Some(SHELL_CWD_NOT_DIRECTORY));
    }
    if !directory_is_readable(&resolved, stat_mode(&value_stat)) {
        return (None, None, None, Some(SHELL_CWD_UNREADABLE_DIRECTORY));
    }
    if !is_within(&resolved, workspace_root) {
        let reason = if is_within(&lexical_candidate, workspace_root)
            && path_contains_symlink(&lexical_candidate, workspace_root)
        {
            SHELL_CWD_SYMLINK_ESCAPE
        } else {
            SHELL_CWD_WORKSPACE_ESCAPE
        };
        return (None, None, None, Some(reason));
    }
    let identity = ShellPathIdentity::from_stat(&value_stat);
    let proof = ShellPathProof {
        lexical_path: lexical_candidate,
        resolved_path: resolved.clone(),
        identity: identity.clone(),
    };
    (Some(resolved), Some(identity), Some(proof), None)
}

/// `os.path.abspath` — join to cwd + lexical normalize, no symlink resolution.
fn abspath(p: &Path) -> PathBuf {
    let s = if p.is_absolute() {
        p.to_string_lossy().into_owned()
    } else {
        std::env::current_dir()
            .map(|c| c.join(p).to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };
    PathBuf::from(crate::home_path_text::normalize_path(&s, None))
}

/// `existing_directory` (:541-556) → `(resolved, identity, reason)`.
pub fn existing_directory(
    path: &Path,
) -> (
    Option<PathBuf>,
    Option<ShellPathIdentity>,
    Option<&'static str>,
) {
    // `path.expanduser()` — Rust Path doesn't expand ~; callers pass expanded.
    let resolved = match std::fs::canonicalize(path) {
        Ok(r) => r,
        Err(e) => {
            use std::io::ErrorKind::*;
            let reason = match e.kind() {
                NotFound | NotADirectory => SHELL_CWD_MISSING_DIRECTORY,
                _ => SHELL_CWD_UNREADABLE_DIRECTORY,
            };
            return (None, None, Some(reason));
        }
    };
    let value_stat = match std::fs::metadata(&resolved) {
        Ok(m) => m,
        Err(_) => return (None, None, Some(SHELL_CWD_UNREADABLE_DIRECTORY)),
    };
    if !value_stat.is_dir() {
        return (None, None, Some(SHELL_CWD_NOT_DIRECTORY));
    }
    if !directory_is_readable(&resolved, stat_mode(&value_stat)) {
        return (None, None, Some(SHELL_CWD_UNREADABLE_DIRECTORY));
    }
    (
        Some(resolved),
        Some(ShellPathIdentity::from_stat(&value_stat)),
        None,
    )
}

/// `_directory_is_readable` (:559-565).
fn directory_is_readable(path: &Path, mode: u32) -> bool {
    #[cfg(unix)]
    if mode & 0o444 == 0 || mode & 0o111 == 0 {
        return false;
    }
    #[cfg(not(unix))]
    let _ = mode;
    // `os.access(path, R_OK|X_OK, effective_ids=True)` — eaccess equivalent.
    check_eaccess(path)
}

#[cfg(unix)]
fn check_eaccess(path: &Path) -> bool {
    // `os.access(R_OK|X_OK, effective_ids=True)` — opening a directory for
    // listing requires read+execute on it; `read_dir` is the std check.
    std::fs::read_dir(path).is_ok()
}
#[cfg(not(unix))]
fn check_eaccess(_path: &Path) -> bool {
    true
}

/// `_path_contains_symlink` (:568-583).
fn path_contains_symlink(path: &Path, workspace_root: &Path) -> bool {
    let relative = path.strip_prefix(workspace_root).unwrap_or(path);
    let mut current = if relative.is_absolute() {
        PathBuf::from("/")
    } else {
        workspace_root.to_path_buf()
    };
    for part in relative.iter() {
        let s = part.to_string_lossy();
        if s == "/" || s.is_empty() || s == "." || s == ".." {
            continue;
        }
        current = current.join(part);
        match std::fs::symlink_metadata(&current) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return true;
                }
            }
            Err(_) => return true,
        }
    }
    false
}

/// `is_within` (:586-591).
pub fn is_within(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok()
}

/// `last_flow_operator` (:594-595).
pub fn last_flow_operator(controls: &[String]) -> Option<&String> {
    controls
        .iter()
        .rev()
        .find(|c| flow_operators().contains(&c.as_str()))
}
