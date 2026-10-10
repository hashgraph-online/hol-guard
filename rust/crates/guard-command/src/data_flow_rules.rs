//! Rust port of `runtime/data_flow_rules.py` — data-flow exfiltration rules
//! for Guard runtime shell actions.
//!
//! Unported Python dependencies are modeled locally with byte-parity:
//!   - `data_flow.{extract_command_segments,extract_pipes,extract_input_redirects}`
//!     — reused from `crate::data_flow`.
//!   - `shell_structure.extract_command_substitutions` — reused.
//!   - `data_flow.{extract_urls,extract_url_ranges}` — local ports.
//!   - `secret_sensitivity.{classify_secret_path,SecretPathMatch}` — reused
//!     from `crate::shell_secret_read_support`.
//!   - `data_flow_variables.*` — local ports.
//!   - `secret_sources.{secret_path_matches_in_command,strip_shell_token}` —
//!     local ports.
//!   - `shell_commands.*` — local ports (shlex via `command_launcher_floors`).
//!   - `temp_files.{temp_write_targets,chmod_temp_targets}` — local ports.
//!   - `signals.{RiskSignalV2,RiskSignalCategory}` — `guard_contracts`.
//!   - `actions.GuardActionEnvelope` — `GuardActionEnvelopeView` seam.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use guard_contracts::{
    RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel, RiskSignalCategory, RiskSignalV2,
};
use regex::Regex;

use crate::command_launcher_floors::shlex_split;
use crate::data_flow::{
    extract_command_segments, extract_input_redirects, extract_pipes, ShellPipe,
};
use crate::npm_source_spec::split_url;
use crate::shell_secret_read_support::{classify_secret_path, SecretPathMatch};
use crate::shell_structure::extract_command_substitutions;

/// Minimal view of `GuardActionEnvelope` consumed by
/// `detect_data_flow_exfiltration` (`action_type` + `command`).
pub struct GuardActionEnvelopeView<'a> {
    pub action_type: &'a str,
    pub command: Option<&'a str>,
}

// ---------------------------------------------------------------------------
// Compiled patterns (:37-104).
// ---------------------------------------------------------------------------

pub static CURL_DATA_FILE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b.*?(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@|--upload-file(?:=|\s+)|-T\s*)(?P<path>\"[^\"]+\"|'[^']+'|[^\s;&|]+)"#,
    )
    .expect("CURL_DATA_FILE_PATTERN")
});

#[allow(clippy::invalid_regex)]
static CURL_DATA_STDIN_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r#"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?(?:(?:--data(?:-binary|-raw|-urlencode)?|-d)\s*@-|(?:--form|-F)(?:=|\s*)[^\s;&|]*@[.-](?=$|[\s;&|])|--upload-file(?:=|\s+)[.-](?=$|[\s;&|])|-T\s*[.-](?=$|[\s;&|]))"#,
    )
    .expect("CURL_DATA_STDIN_PATTERN")
});

static CURL_DATA_VALUE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?s)(?:^|[\s;&|])(?i:curl|curl\.exe)\b[^\r\n;&|]*?(?:--data(?:-binary|-raw|-urlencode)?|-d)(?:=|\s*)(?P<value>\"[^\"]+\"|'[^']+'|[^\s;&|]+)"#,
    )
    .expect("CURL_DATA_VALUE_PATTERN")
});

static PYTHON_SECRET_POST_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)\bpython(?:3)?\b.*?-c\s+.*?(?:requests\.post|urllib\.request|http\.client).*?open\(['\"](?P<path>[^'\"]+)['\"]"#,
    )
    .expect("PYTHON_SECRET_POST_PATTERN")
});

static NODE_SECRET_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)\bnode\b.*?-e\s+.*?(?:fetch|axios\.post|https\.request|http\.request).*?readFileSync\(['\"](?P<path>[^'\"]+)['\"]"#,
    )
    .expect("NODE_SECRET_FETCH_PATTERN")
});

static SCP_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)(?:^|[\s;&|])scp\b(?P<body>[^\r\n;&|]+)").expect("SCP_PATTERN")
});

static TOKEN_SOURCE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:NODE_AUTH_TOKEN|_authToken|npm[_-]?token)\b")
        .expect("TOKEN_SOURCE_PATTERN")
});

const CLIPBOARD_COMMANDS: &[&str] = &["pbcopy", "xclip", "xsel", "wl-copy", "clip", "clip.exe"];

static WEBHOOK_HOST_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"webhook\.site|hooks\.slack\.com|discord\.com|pastebin\.com|gist\.github\.com|transfer\.sh|requestbin")
        .expect("WEBHOOK_HOST_PATTERN")
});

const CURL_SHORT_FLAGS_WITH_VALUES: &[char] = &[
    'A', 'b', 'C', 'c', 'd', 'D', 'e', 'E', 'F', 'H', 'h', 'K', 'm', 'o', 'P', 'Q', 'r', 't', 'T',
    'u', 'U', 'w', 'x', 'X', 'y', 'Y', 'z',
];

static URL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s\"'<>)}\]]+"#).expect("URL_PATTERN"));

static SECRET_VARIABLE_ASSIGNMENT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\$\([^)]*\)|`[^`]*`|\"[^\"]*\"|'[^']*'|[^\s;&|]+)"#,
    )
    .expect("SECRET_VARIABLE_ASSIGNMENT_PATTERN")
});

static SHELL_VARIABLE_EXPANSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\$(?:(?P<name>[A-Za-z_][A-Za-z0-9_]*)|\{(?P<braced_name>[A-Za-z_][A-Za-z0-9_]*)\})",
    )
    .expect("SHELL_VARIABLE_EXPANSION_PATTERN")
});

#[allow(clippy::invalid_regex)]
static SECRET_PATH_TOKEN_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r"(?i)(?<![A-Za-z0-9_.-])(?P<path>\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|(?:~?/)?\.aws/credentials|(?:~?/)?\.ssh/id_(?:rsa|ed25519|ecdsa)|wallet\.key|private-key\.pem|terraform\.tfvars)(?![A-Za-z0-9_.-])",
    )
    .expect("SECRET_PATH_TOKEN_PATTERN")
});

static TEMP_SECRET_WRITE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)(?:(?:^|[^\d>])>{1,2}\s*(?P<redirect>/tmp/[^\s;&|]+)|tee\b(?P<tee>[^\r\n;&|]+))",
    )
    .expect("TEMP_SECRET_WRITE_PATTERN")
});

const SECRET_READ_COMMANDS: &[&str] = &[
    "awk", "base64", "cat", "cut", "grep", "head", "jq", "less", "more", "openssl", "rg", "sed",
    "tail", "xxd", "yq",
];

const SCP_OPTIONS_WITH_VALUES: &[&str] =
    &["-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"];

const GIT_OPTIONS_WITH_VALUES: &[&str] = &[
    "-C",
    "-c",
    "--config-env",
    "--exec-path",
    "--git-dir",
    "--work-tree",
];

const NPM_OPTIONS_WITH_VALUES: &[&str] = &[
    "-w",
    "--access",
    "--cache",
    "--otp",
    "--prefix",
    "--registry",
    "--tag",
    "--userconfig",
];

// ---------------------------------------------------------------------------
// data_flow.py URL helpers (:211-252).
// ---------------------------------------------------------------------------

fn strip_url_suffix(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';'])
}

fn extract_urls(command: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for m in URL_PATTERN.find_iter(command) {
        urls.push(strip_url_suffix(m.as_str()).to_string());
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for u in urls.into_iter().filter(|u| !u.is_empty()) {
        if seen.insert(u.clone()) {
            out.push(u);
        }
    }
    out
}

fn extract_url_ranges(command: &str) -> Vec<(usize, usize)> {
    URL_PATTERN
        .find_iter(command)
        .map(|m| {
            let start = command[..m.start()].chars().count();
            let len = strip_url_suffix(m.as_str()).chars().count();
            (start, start + len)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// shell_commands.py (:19-201).
// ---------------------------------------------------------------------------

fn shell_tokens(command: &str) -> Vec<String> {
    match shlex_split(command) {
        Ok(tokens) => tokens,
        Err(_) => command.split_whitespace().map(str::to_owned).collect(),
    }
}

fn char_isalpha(c: char) -> bool {
    c.is_alphabetic()
}

fn skip_spaces(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && chars[index].is_whitespace() {
        index += 1;
    }
    index
}

fn advance_parenthesized_assignment(chars: &[char], mut index: usize) -> usize {
    let mut depth = 1usize;
    let mut quote: Option<char> = None;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' {
            index += 2;
            continue;
        }
        if ch == '\'' || ch == '"' {
            if quote.is_none() {
                quote = Some(ch);
            } else if quote == Some(ch) {
                quote = None;
            }
            index += 1;
            continue;
        }
        if quote.is_none() && ch == '(' {
            depth += 1;
        } else if quote.is_none() && ch == ')' {
            depth -= 1;
            if depth == 0 {
                return index + 1;
            }
        }
        index += 1;
    }
    index
}

fn advance_quoted_assignment(chars: &[char], mut index: usize) -> usize {
    let quote = chars[index];
    index += 1;
    while index < chars.len() {
        if chars[index] == '\\' {
            index += 2;
            continue;
        }
        if chars[index] == quote {
            return index + 1;
        }
        index += 1;
    }
    index
}

fn advance_backtick_assignment(chars: &[char], mut index: usize) -> usize {
    index += 1;
    while index < chars.len() {
        if chars[index] == '\\' {
            index += 2;
            continue;
        }
        if chars[index] == '`' {
            return index + 1;
        }
        index += 1;
    }
    index
}

fn advance_assignment_value(chars: &[char], mut index: usize) -> usize {
    if index + 1 < chars.len() && chars[index] == '$' && chars[index + 1] == '(' {
        return advance_parenthesized_assignment(chars, index + 2);
    }
    if index < chars.len() && (chars[index] == '\'' || chars[index] == '"') {
        return advance_quoted_assignment(chars, index);
    }
    if index < chars.len() && chars[index] == '`' {
        return advance_backtick_assignment(chars, index);
    }
    while index < chars.len() && !chars[index].is_whitespace() {
        index += 1;
    }
    index
}

fn strip_env_assignment_prefix(command: &str) -> String {
    let chars: Vec<char> = command.chars().collect();
    let mut index = 0usize;
    loop {
        index = skip_spaces(&chars, index);
        let name_start = index;
        if index >= chars.len() || !(char_isalpha(chars[index]) || chars[index] == '_') {
            return chars[index..]
                .iter()
                .collect::<String>()
                .trim_start()
                .to_owned();
        }
        index += 1;
        while index < chars.len() && (chars[index].is_alphanumeric() || chars[index] == '_') {
            index += 1;
        }
        if index >= chars.len() || chars[index] != '=' {
            return chars[name_start..]
                .iter()
                .collect::<String>()
                .trim_start()
                .to_owned();
        }
        index = advance_assignment_value(&chars, index + 1);
    }
}

fn command_tokens_after_env_assignments(command: &str) -> Vec<String> {
    shell_tokens(&strip_env_assignment_prefix(command))
}

fn segment_executes_command(command: &str, names: &[&str]) -> bool {
    let tokens = command_tokens_after_env_assignments(command);
    !tokens.is_empty() && names.contains(&tokens[0].to_lowercase().as_str())
}

fn command_execution_segments(command: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    for segment in extract_command_segments(command) {
        segments.push(segment.clone());
        for pipe in extract_pipes(&segment) {
            segments.push(pipe.right);
        }
    }
    segments
}

fn scp_operands(body: &str) -> Vec<String> {
    let tokens = shell_tokens(body);
    let mut operands: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.is_empty() {
            index += 1;
            continue;
        }
        if SCP_OPTIONS_WITH_VALUES.contains(&token.as_str()) {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        operands.push(token.clone());
        index += 1;
    }
    operands
}

fn is_scp_remote_target(value: &str) -> bool {
    if value.starts_with("./") || value.starts_with("../") || value.starts_with('/') {
        return false;
    }
    let (host, separator_present) = match value.split_once(':') {
        Some((h, _)) => (h, true),
        None => (value, false),
    };
    if !separator_present || host.is_empty() || host.contains('/') {
        return false;
    }
    !host.chars().any(|c| c.is_whitespace())
}

fn advance_option(tokens: &[String], index: usize, options_with_values: &[&str]) -> usize {
    let token = &tokens[index];
    if !token.contains('=')
        && options_with_values.contains(&token.as_str())
        && index + 1 < tokens.len()
    {
        return index + 2;
    }
    index + 1
}

fn skip_options(tokens: &[String], mut index: usize, options_with_values: &[&str]) -> usize {
    while index < tokens.len() && tokens[index].starts_with('-') {
        index = advance_option(tokens, index, options_with_values);
    }
    index
}

fn git_remote_add_url_tokens(tokens: &[String]) -> Vec<String> {
    if tokens.is_empty() || tokens[0].to_lowercase() != "git" {
        return Vec::new();
    }
    let index = skip_options(tokens, 1, GIT_OPTIONS_WITH_VALUES);
    if tokens.len() <= index + 3 {
        return Vec::new();
    }
    let pair: Vec<String> = tokens[index..index + 2]
        .iter()
        .map(|t| t.to_lowercase())
        .collect();
    if pair != ["remote", "add"] {
        return Vec::new();
    }
    tokens[index + 3..].to_vec()
}

fn npm_publish_index(tokens: &[String]) -> Option<usize> {
    if tokens.is_empty() || tokens[0].to_lowercase() != "npm" {
        return None;
    }
    let mut index = 1usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.to_lowercase() == "publish" {
            return Some(index);
        }
        if token == "--" || !token.starts_with('-') {
            return None;
        }
        index = advance_option(tokens, index, NPM_OPTIONS_WITH_VALUES);
    }
    None
}

fn npm_publish_is_dry_run(tokens: &[String], publish_index: usize) -> bool {
    let mut dry_run = false;
    for token in &tokens[publish_index + 1..] {
        if token == "--dry-run" {
            dry_run = true;
            continue;
        }
        if token == "--no-dry-run" {
            dry_run = false;
            continue;
        }
        if let Some(value) = token.strip_prefix("--dry-run=") {
            let value = value.to_lowercase();
            dry_run = !matches!(value.as_str(), "false" | "0" | "no" | "off");
        }
    }
    dry_run
}

// ---------------------------------------------------------------------------
// secret_sources.py (:45-99).
// ---------------------------------------------------------------------------

fn strip_shell_token(value: &str) -> String {
    let stripped = value.trim().trim_matches(',');
    let chars: Vec<char> = stripped.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        return chars[1..chars.len() - 1].iter().collect();
    }
    stripped.to_owned()
}

fn secret_read_command_paths(command: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    let url_ranges = extract_url_ranges(command);
    for segment in command_execution_segments(command) {
        let tokens = command_tokens_after_env_assignments(&segment);
        if tokens.is_empty() || !SECRET_READ_COMMANDS.contains(&tokens[0].to_lowercase().as_str()) {
            continue;
        }
        for m in SECRET_PATH_TOKEN_PATTERN.captures_iter(&segment).flatten() {
            let path_group = m.name("path").expect("path group");
            let char_start = segment[..path_group.start()].chars().count();
            if url_ranges
                .iter()
                .any(|&(start, end)| start <= char_start && char_start < end)
            {
                continue;
            }
            paths.push(strip_shell_token(path_group.as_str()));
        }
    }
    paths
}

fn substitution_secret_paths(command: &str) -> Vec<String> {
    let mut paths = extract_input_redirects(command);
    paths.extend(secret_read_command_paths(command));
    paths
}

fn secret_path_matches(paths: &[String], workspace: Option<&Path>) -> Vec<SecretPathMatch> {
    let mut matches: Vec<SecretPathMatch> = Vec::new();
    for path in paths {
        if let Some(m) = classify_secret_path(path, workspace, None) {
            matches.push(m);
        }
    }
    matches
}

fn secret_path_matches_in_command(
    command: &str,
    workspace: Option<&Path>,
    extra_paths: &[String],
) -> Vec<SecretPathMatch> {
    let mut candidates = extract_input_redirects(command);
    candidates.extend(secret_read_command_paths(command));
    for substitution in extract_command_substitutions(command) {
        candidates.extend(substitution_secret_paths(&substitution));
    }
    candidates.extend(extra_paths.iter().cloned());
    secret_path_matches(&candidates, workspace)
}

// ---------------------------------------------------------------------------
// data_flow_variables.py (:29-108).
// ---------------------------------------------------------------------------

struct SecretVariableAssignment {
    name: String,
    encoded: bool,
}

fn is_single_quoted(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    chars.len() >= 2 && chars[0] == '\'' && chars[chars.len() - 1] == '\''
}

fn value_encodes_secret(value: &str) -> bool {
    let lowered = value.to_lowercase();
    lowered.contains("base64") || lowered.contains("openssl enc")
}

fn expanded_variable_name<'a>(m: &regex::Captures<'a>) -> &'a str {
    m.name("name")
        .or_else(|| m.name("braced_name"))
        .map(|g| g.as_str())
        .unwrap_or("")
}

fn value_uses_variable(value: &str, names: &HashSet<String>) -> bool {
    if is_single_quoted(value) {
        return false;
    }
    SHELL_VARIABLE_EXPANSION_PATTERN
        .captures_iter(value)
        .any(|m| names.contains(expanded_variable_name(&m)))
}

fn curl_segment_uses_variable(segment: &str, names: &HashSet<String>) -> bool {
    if !segment_executes_command(segment, &["curl", "curl.exe"]) || extract_urls(segment).is_empty()
    {
        return false;
    }
    CURL_DATA_VALUE_PATTERN
        .captures_iter(segment)
        .any(|m| value_uses_variable(m.name("value").map(|g| g.as_str()).unwrap_or(""), names))
}

fn segment_secret_variable_assignments(
    segment: &str,
    workspace: Option<&Path>,
) -> Vec<SecretVariableAssignment> {
    let mut normalized = segment.trim_start().to_owned();
    if normalized.starts_with("export ") {
        normalized = normalized[7..].trim_start().to_owned();
    }
    let chars: Vec<char> = normalized.chars().collect();
    let mut assignments: Vec<SecretVariableAssignment> = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        let byte_index: usize = chars[..index].iter().map(|c| c.len_utf8()).sum();
        let m = match SECRET_VARIABLE_ASSIGNMENT_PATTERN.captures(&normalized[byte_index..]) {
            Some(m) if m.get(0).map(|g| g.start() == 0).unwrap_or(false) => m,
            _ => break,
        };
        let value = m.name("value").map(|g| g.as_str()).unwrap_or("");
        if !secret_path_matches_in_command(value, workspace, &[]).is_empty() {
            assignments.push(SecretVariableAssignment {
                name: m.name("name").map(|g| g.as_str()).unwrap_or("").to_owned(),
                encoded: value_encodes_secret(value),
            });
        }
        index += m.get(0).map(|g| g.as_str().chars().count()).unwrap_or(0);
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
    }
    if index < chars.len() {
        return Vec::new();
    }
    assignments
}

fn secret_variable_assignments(
    command: &str,
    workspace: Option<&Path>,
) -> Vec<SecretVariableAssignment> {
    let mut assignments: Vec<SecretVariableAssignment> = Vec::new();
    for segment in extract_command_segments(command) {
        assignments.extend(segment_secret_variable_assignments(&segment, workspace));
    }
    assignments
}

fn curl_data_uses_secret_variable(command: &str, workspace: Option<&Path>) -> bool {
    let variables = secret_variable_assignments(command, workspace);
    if variables.is_empty() {
        return false;
    }
    let names: HashSet<String> = variables.iter().map(|a| a.name.clone()).collect();
    command_execution_segments(command)
        .iter()
        .any(|segment| curl_segment_uses_variable(segment, &names))
}

fn curl_data_uses_encoded_secret_variable(command: &str, workspace: Option<&Path>) -> bool {
    let variables = secret_variable_assignments(command, workspace);
    let encoded_names: HashSet<String> = variables
        .iter()
        .filter(|a| a.encoded)
        .map(|a| a.name.clone())
        .collect();
    if encoded_names.is_empty() {
        return false;
    }
    command_execution_segments(command)
        .iter()
        .any(|segment| curl_segment_uses_variable(segment, &encoded_names))
}

// ---------------------------------------------------------------------------
// temp_files.py (:16-57).
// ---------------------------------------------------------------------------

fn temp_strip_shell_token(value: &str) -> String {
    let stripped = value.trim().trim_matches(',');
    let chars: Vec<char> = stripped.chars().collect();
    if chars.len() >= 2
        && chars[0] == chars[chars.len() - 1]
        && (chars[0] == '\'' || chars[0] == '"')
    {
        return chars[1..chars.len() - 1].iter().collect();
    }
    stripped.to_owned()
}

fn tee_targets(body: &str) -> Vec<String> {
    shell_tokens(body)
        .into_iter()
        .filter(|token| !token.starts_with('-'))
        .map(|t| temp_strip_shell_token(&t))
        .collect()
}

fn temp_write_targets(segment: &str) -> Vec<String> {
    let mut targets: Vec<String> = Vec::new();
    for m in TEMP_SECRET_WRITE_PATTERN.captures_iter(segment) {
        if let Some(redirect) = m.name("redirect") {
            targets.push(temp_strip_shell_token(redirect.as_str()));
        }
        if let Some(tee_body) = m.name("tee") {
            targets.extend(tee_targets(tee_body.as_str()));
        }
    }
    targets
        .into_iter()
        .filter(|t| t.starts_with("/tmp/"))
        .collect()
}

fn chmod_mode_index(tokens: &[String]) -> Option<usize> {
    let mut index = 1usize;
    while index < tokens.len() && tokens[index].starts_with('-') {
        index += 1;
    }
    if index < tokens.len() {
        Some(index)
    } else {
        None
    }
}

fn chmod_temp_targets(command: &str) -> Vec<(String, String)> {
    let mut targets: Vec<(String, String)> = Vec::new();
    for segment in extract_command_segments(command) {
        let tokens = command_tokens_after_env_assignments(&segment);
        if tokens.len() < 3 || tokens[0].to_lowercase() != "chmod" {
            continue;
        }
        let mode_index = match chmod_mode_index(&tokens) {
            Some(i) => i,
            None => continue,
        };
        for path in &tokens[mode_index + 1..] {
            targets.push((temp_strip_shell_token(path), tokens[mode_index].clone()));
        }
    }
    targets
}

// ---------------------------------------------------------------------------
// data_flow_rules.py (:103-610).
// ---------------------------------------------------------------------------

/// `detect_data_flow_exfiltration` (:103-246).
pub fn detect_data_flow_exfiltration(
    action: &GuardActionEnvelopeView<'_>,
    workspace: Option<&Path>,
) -> Vec<RiskSignalV2> {
    if action.action_type != "shell_command" || action.command.is_none() {
        return Vec::new();
    }
    let command = action.command.unwrap();
    let mut findings: Vec<RiskSignalV2> = Vec::new();
    let secret_matches = data_flow_secret_path_matches_in_command(command, workspace);
    let pipes = extract_pipes(command);
    if has_secret_pipe_to_http_upload(&pipes, command, workspace) {
        findings.push(data_flow_signal(
            "secret-pipe-http",
            "Shell pipeline sends a local secret to a network host",
            "This command pipes a local secret into an HTTP upload.",
            "secret path and HTTP upload appear in the same pipe chain",
            RiskSignalCategory::Network,
        ));
    }
    if curl_uploads_secret_file(command, workspace) {
        findings.push(data_flow_signal(
            "curl-data-file",
            "Curl uploads a local secret file",
            "This command sends a local secret file as curl request data.",
            "curl data flag references a sensitive local path",
            RiskSignalCategory::Network,
        ));
    }
    if curl_data_uses_secret_variable(command, workspace) {
        findings.push(data_flow_signal(
            "shell-variable-secret-http",
            "Shell variable sends a local secret to a network host",
            "This command sends local secret to network host through a shell variable.",
            "shell variable is assigned from a sensitive path and later used as curl request data",
            RiskSignalCategory::Network,
        ));
    }
    if python_posts_secret(command, workspace) {
        findings.push(data_flow_signal(
            "python-secret-post",
            "Python posts a local secret",
            "This Python snippet reads a local secret and posts it to a network host.",
            "python -c combines a sensitive file read with an HTTP post",
            RiskSignalCategory::Network,
        ));
    }
    if node_fetches_secret(command, workspace) {
        findings.push(data_flow_signal(
            "node-secret-fetch",
            "Node sends a local secret",
            "This Node snippet reads a local secret and sends it to a network host.",
            "node -e combines fs.readFileSync on a sensitive path with fetch/request",
            RiskSignalCategory::Network,
        ));
    }
    if encoded_secret_send(command, &secret_matches, workspace) {
        findings.push(data_flow_signal(
            "encoded-secret-send",
            "Encoded local secret is sent to a network host",
            "This command encodes a local secret before sending it to a network host.",
            "base64 appears between a sensitive path and HTTP upload",
            RiskSignalCategory::Network,
        ));
    }
    if has_dns_exfil_hostname(command) {
        findings.push(data_flow_signal(
            "dns-exfil",
            "DNS query looks like encoded exfiltration",
            "This command sends an unusually long encoded-looking DNS label.",
            "DNS tool is called with a long encoded-looking label",
            RiskSignalCategory::Network,
        ));
    }
    if has_webhook_exfil(command, workspace) {
        findings.push(data_flow_signal(
            "webhook-sink",
            "Local secret is sent to a public collection endpoint",
            "This command targets a paste, gist, transfer, or webhook endpoint with local secret data.",
            "known collection host appears with local secret source",
            RiskSignalCategory::Network,
        ));
    }
    if scp_sends_secret(command, workspace) {
        findings.push(data_flow_signal(
            "scp-secret",
            "SCP sends a local secret file",
            "This command copies a local secret file to a remote host.",
            "scp command references a sensitive local source",
            RiskSignalCategory::Network,
        ));
    }
    if git_remote_adds_token_url(command) {
        findings.push(data_flow_signal(
            "git-remote-token",
            "Git remote URL contains an access token",
            "This command stores a token-bearing URL in git remote configuration.",
            "git remote add URL includes credentials before host",
            RiskSignalCategory::Secret,
        ));
    }
    if npm_publish_with_token_source(command, workspace) {
        findings.push(data_flow_signal(
            "npm-publish-token-source",
            "NPM publish uses local token material",
            "This command publishes a package while local npm token material is in scope.",
            "npm publish appears with npm token source evidence",
            RiskSignalCategory::Network,
        ));
    }
    if clipboard_receives_secret(&pipes, command, workspace) {
        findings.push(data_flow_signal(
            "clipboard-secret",
            "Clipboard receives a local secret",
            "This command copies local secret contents into the clipboard.",
            "clipboard command receives sensitive source through a pipe",
            RiskSignalCategory::Secret,
        ));
    }
    if world_readable_temp_secret(command, workspace) {
        findings.push(data_flow_signal(
            "world-readable-temp-secret",
            "Local secret is written to a world-readable temp file",
            "This command writes local secret contents to a world-readable temp file.",
            "sensitive source is redirected to /tmp and chmod makes it world-readable",
            RiskSignalCategory::Secret,
        ));
    }
    dedupe_signals(&findings)
}

/// `_secret_path_matches_in_command` (:247-250).
fn data_flow_secret_path_matches_in_command(
    command: &str,
    workspace: Option<&Path>,
) -> Vec<SecretPathMatch> {
    secret_path_matches_in_command(command, workspace, &curl_data_file_paths(command))
}

/// `_curl_data_file_paths` (:251-260).
fn curl_data_file_paths(command: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for segment in command_execution_segments(command) {
        let tokens = command_tokens_after_env_assignments(&segment);
        if tokens.is_empty() || !matches!(tokens[0].to_lowercase().as_str(), "curl" | "curl.exe") {
            continue;
        }
        paths.extend(curl_segment_data_file_paths(&tokens[1..]));
    }
    paths
}

/// `_curl_segment_data_file_paths` (:261-285).
fn curl_segment_data_file_paths(args: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            break;
        }
        if let Some((path, consumed)) = curl_long_flag_data_path(token, args, index) {
            if let Some(p) = path {
                paths.push(p);
            }
            index += consumed;
            continue;
        }
        if let Some((path, consumed)) = curl_short_flag_data_path(token, args, index) {
            if let Some(p) = path {
                paths.push(p);
            }
            index += consumed;
            continue;
        }
        index += 1;
    }
    paths
}

/// `_curl_long_flag_data_path` (:286-305).
fn curl_long_flag_data_path(
    token: &str,
    args: &[String],
    index: usize,
) -> Option<(Option<String>, usize)> {
    const LONG_FLAGS: &[&str] = &[
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--upload-file",
        "--form",
    ];
    if LONG_FLAGS.contains(&token) {
        let value = args.get(index + 1).cloned().unwrap_or_default();
        return Some((curl_option_data_path(token, &value), 2));
    }
    for flag in LONG_FLAGS {
        let prefix = format!("{flag}=");
        if let Some(rest) = token.strip_prefix(&prefix[..]) {
            return Some((curl_option_data_path(flag, rest), 1));
        }
    }
    None
}

/// `_curl_short_flag_data_path` (:306-326).
fn curl_short_flag_data_path(
    token: &str,
    args: &[String],
    index: usize,
) -> Option<(Option<String>, usize)> {
    if token == "-d" || token == "-T" || token == "-F" {
        let value = args.get(index + 1).cloned().unwrap_or_default();
        return Some((curl_option_data_path(token, &value), 2));
    }
    let chars: Vec<char> = token.chars().collect();
    if !token.starts_with('-') || token.starts_with("--") || chars.len() <= 2 {
        return None;
    }
    let cluster: String = chars[1..].iter().collect();
    let cluster_chars: Vec<char> = cluster.chars().collect();
    for (flag_index, flag) in cluster_chars.iter().enumerate() {
        let attached_value: String = cluster_chars[flag_index + 1..].iter().collect();
        if *flag != 'd' && *flag != 'T' && *flag != 'F' {
            if CURL_SHORT_FLAGS_WITH_VALUES.contains(flag) {
                return None;
            }
            continue;
        }
        let option = format!("-{flag}");
        if !attached_value.is_empty() {
            return Some((curl_option_data_path(&option, &attached_value), 1));
        }
        let value = args.get(index + 1).cloned().unwrap_or_default();
        return Some((curl_option_data_path(&option, &value), 2));
    }
    None
}

/// `_curl_option_data_path` (:327-351).
fn curl_option_data_path(flag: &str, value: &str) -> Option<String> {
    let normalized_value = strip_shell_token(value);
    if normalized_value.is_empty() || normalized_value.starts_with('-') {
        return None;
    }
    if matches!(flag, "--upload-file" | "-T") {
        return Some(normalized_value);
    }
    if matches!(flag, "--form" | "-F") {
        let field_value = match normalized_value.split_once('=') {
            Some((_, v)) => v.to_owned(),
            None => normalized_value.clone(),
        };
        let fv_chars: Vec<char> = field_value.chars().collect();
        if !field_value.is_empty() && (fv_chars[0] == '@' || fv_chars[0] == '<') {
            let rest: String = fv_chars[1..].iter().collect();
            return Some(
                rest.split(';')
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .to_owned(),
            );
        }
        return None;
    }
    if flag == "--data-urlencode" {
        if let Some(stripped) = normalized_value.strip_prefix('@') {
            return Some(stripped.to_owned());
        }
        if !normalized_value.contains('@') {
            return None;
        }
        let (name, file_candidate) = normalized_value.split_once('@')?;
        if name.contains('=') {
            return None;
        }
        return Some(file_candidate.to_owned());
    }
    if let Some(stripped) = normalized_value.strip_prefix('@') {
        return Some(stripped.to_owned());
    }
    None
}

/// `_has_secret_pipe_to_http_upload` (:352-362).
fn has_secret_pipe_to_http_upload(
    pipes: &[ShellPipe],
    command: &str,
    workspace: Option<&Path>,
) -> bool {
    if pipes.is_empty() || !has_http_upload(command) {
        return false;
    }
    extract_command_segments(command).iter().any(|segment| {
        !extract_pipes(segment).is_empty()
            && !data_flow_secret_path_matches_in_command(segment, workspace).is_empty()
            && contains_http_upload_sink(segment)
    })
}

/// `_has_http_upload` (:363-369).
fn has_http_upload(command: &str) -> bool {
    command_execution_segments(command).iter().any(|segment| {
        segment_executes_command(segment, &["curl", "curl.exe"])
            // A backtracking-limit error means the segment could not be ruled
            // out as an upload, so fail closed instead of dropping the signal.
            && CURL_DATA_STDIN_PATTERN.is_match(segment).unwrap_or(true)
    })
}

/// `_contains_http_upload_sink` (:370-373).
fn contains_http_upload_sink(command: &str) -> bool {
    !extract_urls(command).is_empty() && has_http_upload(command)
}

/// `_curl_uploads_secret_file` (:374-381).
fn curl_uploads_secret_file(command: &str, workspace: Option<&Path>) -> bool {
    let uploads = extract_command_segments(command).iter().any(|segment| {
        !extract_urls(segment).is_empty()
            && curl_data_file_paths(segment)
                .iter()
                .any(|path| classify_secret_path(path, workspace, None).is_some())
    });
    uploads || curl_data_substitution_reads_secret(command, workspace)
}

/// `_curl_data_substitution_reads_secret` (:382-398).
fn curl_data_substitution_reads_secret(command: &str, workspace: Option<&Path>) -> bool {
    for segment in command_execution_segments(command) {
        if !segment_executes_command(&segment, &["curl", "curl.exe"]) {
            continue;
        }
        if extract_urls(&segment).is_empty() {
            continue;
        }
        for m in CURL_DATA_VALUE_PATTERN.captures_iter(&segment) {
            let value = m.name("value").map(|g| g.as_str()).unwrap_or("");
            let reads_secret = extract_command_substitutions(value)
                .iter()
                .any(|substitution| {
                    !data_flow_secret_path_matches_in_command(substitution, workspace).is_empty()
                });
            if !reads_secret {
                continue;
            }
            return true;
        }
    }
    false
}

/// `_python_posts_secret` (:399-412).
fn python_posts_secret(command: &str, workspace: Option<&Path>) -> bool {
    for segment in extract_command_segments(command) {
        if segment_executes_command(&segment, &["python", "python3"])
            && !extract_urls(&segment).is_empty()
            && PYTHON_SECRET_POST_PATTERN.captures_iter(&segment).any(|m| {
                classify_secret_path(
                    m.name("path").map(|g| g.as_str()).unwrap_or(""),
                    workspace,
                    None,
                )
                .is_some()
            })
        {
            return true;
        }
    }
    false
}

/// `_node_fetches_secret` (:413-426).
fn node_fetches_secret(command: &str, workspace: Option<&Path>) -> bool {
    for segment in extract_command_segments(command) {
        if segment_executes_command(&segment, &["node"])
            && !extract_urls(&segment).is_empty()
            && NODE_SECRET_FETCH_PATTERN.captures_iter(&segment).any(|m| {
                classify_secret_path(
                    m.name("path").map(|g| g.as_str()).unwrap_or(""),
                    workspace,
                    None,
                )
                .is_some()
            })
        {
            return true;
        }
    }
    false
}

/// `_encoded_secret_send` (:427-440).
fn encoded_secret_send(
    command: &str,
    secret_matches: &[SecretPathMatch],
    workspace: Option<&Path>,
) -> bool {
    if secret_matches.is_empty() {
        return false;
    }
    if curl_data_uses_encoded_secret_variable(command, workspace) {
        return true;
    }
    extract_command_segments(command).iter().any(|segment| {
        !data_flow_secret_path_matches_in_command(segment, workspace).is_empty()
            && segment.to_lowercase().contains("base64")
            && has_http_upload(segment)
            && !extract_urls(segment).is_empty()
    })
}

/// `_has_dns_exfil_hostname` (:441-448).
fn has_dns_exfil_hostname(command: &str) -> bool {
    extract_command_segments(command).iter().any(|segment| {
        segment_executes_command(segment, &["dig", "nslookup", "host"])
            && dns_query_tokens(segment)
                .iter()
                .any(|token| has_long_encoded_label(token))
    })
}

/// `_dns_query_tokens` (:449-453).
fn dns_query_tokens(segment: &str) -> Vec<String> {
    let tokens = command_tokens_after_env_assignments(segment);
    if tokens.len() < 2 {
        return Vec::new();
    }
    tokens[1..]
        .iter()
        .filter(|token| {
            token.contains('.')
                && !token.starts_with('-')
                && !token.starts_with('+')
                && !token.starts_with('@')
        })
        .map(|token| token.trim_matches(|c| c == '\'' || c == '"').to_owned())
        .collect()
}

/// `_has_long_encoded_label` (:454-457).
fn has_long_encoded_label(host: &str) -> bool {
    host.split('.').any(|label| label.chars().count() >= 48)
}

/// `_has_webhook_sink` (:458-465).
fn has_webhook_sink(urls: &[String]) -> bool {
    urls.iter().any(|url| {
        let host = split_url(url).hostname.unwrap_or_default().to_lowercase();
        WEBHOOK_HOST_PATTERN.is_match(&host)
    })
}

/// `_has_webhook_exfil` (:466-478).
fn has_webhook_exfil(command: &str, workspace: Option<&Path>) -> bool {
    for segment in extract_command_segments(command) {
        if !has_webhook_sink(&extract_urls(&segment)) {
            continue;
        }
        if !data_flow_secret_path_matches_in_command(&segment, workspace).is_empty() {
            return true;
        }
        if curl_uploads_secret_file(&segment, workspace) {
            return true;
        }
        if has_secret_pipe_to_http_upload(&extract_pipes(&segment), &segment, workspace) {
            return true;
        }
    }
    false
}

/// `_scp_sends_secret` (:479-497).
fn scp_sends_secret(command: &str, workspace: Option<&Path>) -> bool {
    for segment in extract_command_segments(command) {
        if !segment_executes_command(&segment, &["scp"]) {
            continue;
        }
        let m = match SCP_PATTERN.captures(&segment) {
            Some(m) => m,
            None => continue,
        };
        let operands = scp_operands(m.name("body").map(|g| g.as_str()).unwrap_or(""));
        if operands.len() < 2 {
            continue;
        }
        let target = &operands[operands.len() - 1];
        let sources = &operands[..operands.len() - 1];
        if !is_scp_remote_target(target) {
            continue;
        }
        if sources.iter().any(|source| {
            !is_scp_remote_target(source) && classify_secret_path(source, workspace, None).is_some()
        }) {
            return true;
        }
    }
    false
}

/// `_git_remote_adds_token_url` (:498-512).
fn git_remote_adds_token_url(command: &str) -> bool {
    for segment in extract_command_segments(command) {
        let tokens = command_tokens_after_env_assignments(&segment);
        let url_tokens = git_remote_add_url_tokens(&tokens);
        if url_tokens.is_empty() {
            continue;
        }
        for url in extract_urls(&url_tokens.join(" ")) {
            let parsed = split_url(&url);
            if !parsed.username.is_empty() && looks_like_token(&parsed.username) {
                return true;
            }
            if !parsed.password.is_empty() && looks_like_token(&parsed.password) {
                return true;
            }
        }
    }
    false
}

/// `_looks_like_token` (:513-517).
fn looks_like_token(value: &str) -> bool {
    let lowered = value.to_lowercase();
    ["ghp_", "github_pat_", "glpat-", "x-access-token"]
        .iter()
        .any(|p| lowered.starts_with(p))
        || value.chars().count() >= 24
}

/// `_npm_publish_with_token_source` (:518-532).
fn npm_publish_with_token_source(command: &str, workspace: Option<&Path>) -> bool {
    extract_command_segments(command).iter().any(|segment| {
        let tokens = command_tokens_after_env_assignments(segment);
        let publish_index = match npm_publish_index(&tokens) {
            Some(i) => i,
            None => return false,
        };
        if npm_publish_is_dry_run(&tokens, publish_index) {
            return false;
        }
        if TOKEN_SOURCE_PATTERN.is_match(segment) {
            return true;
        }
        has_npm_secret_match(&data_flow_secret_path_matches_in_command(
            segment, workspace,
        ))
    })
}

/// `_has_npm_secret_match` (:533-536).
fn has_npm_secret_match(secret_matches: &[SecretPathMatch]) -> bool {
    secret_matches.iter().any(|m| {
        m.family.to_lowercase().contains("npm")
            || m.requested_path.to_lowercase().contains(".npmrc")
    })
}

/// `_clipboard_receives_secret` (:537-547).
fn clipboard_receives_secret(pipes: &[ShellPipe], command: &str, workspace: Option<&Path>) -> bool {
    if pipes.is_empty() {
        return false;
    }
    extract_command_segments(command).iter().any(|segment| {
        let segment_pipes = extract_pipes(segment);
        !segment_pipes.is_empty()
            && !data_flow_secret_path_matches_in_command(segment, workspace).is_empty()
            && segment_pipes
                .iter()
                .any(|pipe| segment_executes_command(&pipe.right, CLIPBOARD_COMMANDS))
    })
}

/// `_world_readable_temp_secret` (:548-561).
fn world_readable_temp_secret(command: &str, workspace: Option<&Path>) -> bool {
    let mut write_targets: HashSet<String> = HashSet::new();
    for segment in extract_command_segments(command) {
        if !data_flow_secret_path_matches_in_command(&segment, workspace).is_empty() {
            for target in temp_write_targets(&segment) {
                write_targets.insert(target);
            }
        }
    }
    if write_targets.is_empty() {
        return false;
    }
    chmod_temp_targets(command)
        .iter()
        .any(|(target, mode)| write_targets.contains(target) && mode_makes_world_readable(mode))
}

/// `_mode_makes_world_readable` (:562-577).
fn mode_makes_world_readable(mode: &str) -> bool {
    let normalized = mode.to_lowercase();
    if normalized.chars().all(|c| c.is_ascii_digit()) && !normalized.is_empty() {
        let last = normalized.chars().last().unwrap();
        return matches!(last, '4' | '5' | '6' | '7');
    }
    for clause in normalized.split(',') {
        if clause.contains("+r") {
            let who = clause.split('+').next().unwrap_or("");
            if who.is_empty() || who.contains('a') || who.contains('o') {
                return true;
            }
        }
        if clause.contains('=') {
            let (who, permissions) = clause.split_once('=').unwrap();
            if permissions.contains('r')
                && (who.is_empty() || who.contains('a') || who.contains('o'))
            {
                return true;
            }
        }
    }
    false
}

/// `_data_flow_signal` (:578-601).
fn data_flow_signal(
    signal_key: &str,
    title: &str,
    plain_reason: &str,
    technical_detail: &str,
    category: RiskSignalCategory,
) -> RiskSignalV2 {
    RiskSignalV2 {
        signal_id: format!("data-flow:{signal_key}"),
        category,
        severity: RiskSeverityLabel::Critical,
        confidence: RiskConfidenceLabel::Strong,
        detector: "data_flow.exfiltration".to_owned(),
        title: title.to_owned(),
        plain_reason: plain_reason.to_owned(),
        technical_detail: Some(technical_detail.to_owned()),
        evidence_ref: Some("command".to_owned()),
        redaction_level: RiskRedactionLevel::Summary,
        false_positive_hint: Some(
            "Allow only if this exact command intentionally moves non-sensitive local data."
                .to_owned(),
        ),
        advisory_id: None,
    }
}

/// `_dedupe_signals` (:602-610).
fn dedupe_signals(signals: &[RiskSignalV2]) -> Vec<RiskSignalV2> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut result: Vec<RiskSignalV2> = Vec::new();
    for signal in signals {
        if seen.insert(signal.signal_id.clone()) {
            result.push(signal.clone());
        }
    }
    result
}
