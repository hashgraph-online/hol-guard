//! Support helpers for Kubernetes runtime command detection
//! (`runtime/kubernetes_command_support.py`).

#![allow(dead_code)]

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

use crate::hook_adapter_pytext::{is_py_space, py_lower, py_strip};

/// Python `\s` (`str.isspace`) as a character class body.
const WS: &str = r"[\s\x1c-\x1f]";

static SENSITIVE_ENV_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[_-])(?:api[_-]?key|auth|credential|credentials|key|password|private[_-]?key|secret|token)(?:[_-]|$)")
        .expect("sensitive env name pattern")
});
static ENV_EXPANSION: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(
        r"(?<!\\)\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)[^}]*\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))",
    )
    .expect("env expansion pattern")
});
static LOOKUP_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let ws = WS;
    [
        format!(r#"(?i)os\.environ{ws}*\[{ws}*['"](?P<name>[^'"]+)['"]{ws}*\]"#),
        format!(r#"(?i)os\.environ{ws}*\[{ws}*(?P<name>[A-Za-z_][A-Za-z0-9_]*){ws}*\]"#),
        format!(r#"(?i)os\.environ\.get\({ws}*['"](?P<name>[^'"]+)['"]"#),
        format!(r#"(?i)os\.getenv\({ws}*['"](?P<name>[^'"]+)['"]"#),
        format!(
            r#"process\.env(?:\.{ws}*(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|\[{ws}*['"](?P<bracket>[^'"]+)['"]{ws}*\])"#
        ),
        format!(r#"ENV\[{ws}*['"](?P<name>[^'"]+)['"]{ws}*\]"#),
        format!(r#"(?i)System\.getenv\({ws}*['"](?P<name>[^'"]+)['"]{ws}*\)"#),
    ]
    .iter()
    .map(|pattern| Regex::new(pattern).expect("env lookup pattern"))
    .collect()
});
static ENV_DUMP_PATTERNS: LazyLock<Vec<FancyRegex>> = LazyLock::new(|| {
    let ws = WS;
    [
        format!(r"\bos\.environ\b(?!{ws}*(?:\[|\.get\b|\.setdefault\b))"),
        format!(r"\bos\.environ{ws}*\.{ws}*(?:items|keys|values|copy|update){ws}*\("),
        format!(r"\bprocess\.env\b(?!{ws}*[.\[])"),
        format!(r#"\bprocess\.env{ws}*\[{ws}*(?!['"])"#),
    ]
    .iter()
    .map(|pattern| FancyRegex::new(pattern).expect("env dump pattern"))
    .collect()
});
static RAW_SECRET_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A/(?:api/[^/]+|apis/[^/]+/[^/]+)/(?:watch/)?(?:namespaces/[^/]+/)?secrets?(?:/[^/?#]+)?\z",
    )
    .expect("raw secret path pattern")
});
static PROC_ENVIRON_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A/proc/(?:\d+|self)/environ\z").expect("proc environ pattern"));
static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[A-Za-z_][A-Za-z0-9_]*=").expect("assignment pattern"));

pub(crate) const OUTPUT_REDIRECT_TOKENS: &[&str] = &[">", "1>", "2>", ">>", "1>>", "2>>"];
const SERVICE_ACCOUNT_PATH_MARKERS: &[&str] = &[
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/secrets/kubernetes.io/serviceaccount",
];
const SECRET_VOLUME_PATH_MARKERS: &[&str] = &[
    "/etc/secrets",
    "/etc/secret",
    "/mnt/secrets-store",
    "/var/run/secrets",
    "/var/run/secrets-store",
    "/run/secrets",
    "/run/secrets-store",
];
pub(crate) const WRITE_ONLY_COMMANDS: &[&str] = &[
    "chmod", "chown", "echo", "install", "mkdir", "printf", "rm", "rmdir", "tee", "touch",
    "truncate",
];
pub(crate) const WRAPPER_COMMANDS: &[&str] =
    &["command", "env", "nice", "nohup", "stdbuf", "sudo", "time"];
pub(crate) use crate::sfrs_kubernetes_options::{
    EXEC_BOOLEAN_OPTIONS, EXEC_BOOLEAN_SHORT_CLUSTER, EXEC_OPTIONS_WITH_VALUES,
    KUBECTL_BOOLEAN_OPTIONS, KUBECTL_OPTIONS_WITH_VALUES, SHELL_EXECUTABLES,
};

/// `WRAPPER_OPTIONS_WITH_VALUES[command_name]`.
pub(crate) fn wrapper_options_with_values(command_name: &str) -> &'static [&'static str] {
    match command_name {
        "nice" => &["-n", "--adjustment"],
        "stdbuf" => &["-i", "--input", "-o", "--output", "-e", "--error"],
        "sudo" => &[
            "-C",
            "-D",
            "-R",
            "-T",
            "-g",
            "-h",
            "-p",
            "-r",
            "-t",
            "-u",
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--prompt",
            "--role",
            "--type",
            "--user",
        ],
        "time" => &["-f", "--format", "-o", "--output"],
        _ => &[],
    }
}

/// `ASSIGNMENT_PATTERN.match(token)`.
pub(crate) fn is_assignment(token: &str) -> bool {
    ASSIGNMENT.is_match(token)
}

/// `Path(token).name.lower()`.
pub(crate) fn path_name_lower(token: &str) -> String {
    let name = token
        .split('/')
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("");
    py_lower(name)
}

/// Option sets shared by the kubectl option walkers (the `base_*` and the
/// per-call `value_flags`/`boolean_flags`/`boolean_short_cluster` groups).
#[derive(Clone, Copy)]
pub(crate) struct OptionSets<'a> {
    pub(crate) value_flags: &'a [&'a [&'a str]],
    pub(crate) boolean_flags: &'a [&'a [&'a str]],
    pub(crate) short_cluster: &'a [&'a [char]],
}

pub(crate) const KUBECTL_OPTION_SETS: OptionSets<'static> = OptionSets {
    value_flags: &[KUBECTL_OPTIONS_WITH_VALUES],
    boolean_flags: &[KUBECTL_BOOLEAN_OPTIONS],
    short_cluster: &[EXEC_BOOLEAN_SHORT_CLUSTER],
};

fn any_flag(groups: &[&[&str]], predicate: impl Fn(&str) -> bool) -> bool {
    groups
        .iter()
        .any(|group| group.iter().any(|flag| predicate(flag)))
}

/// `kubernetes_option_tokens_consumed`.
pub(crate) fn kubernetes_option_tokens_consumed(
    tokens: &[String],
    index: usize,
    sets: OptionSets<'_>,
) -> Option<usize> {
    let token = tokens[index].as_str();
    if any_flag(sets.value_flags, |flag| flag == token) && index + 1 < tokens.len() {
        return Some(2);
    }
    let long_assigned = |flag: &str| {
        flag.starts_with("--")
            && token
                .strip_prefix(flag)
                .is_some_and(|rest| rest.starts_with('='))
    };
    if any_flag(sets.value_flags, long_assigned) {
        return Some(1);
    }
    if any_flag(sets.boolean_flags, |flag| flag == token) {
        return Some(1);
    }
    if any_flag(sets.boolean_flags, long_assigned) {
        return Some(1);
    }
    if any_flag(sets.value_flags, |flag| {
        flag.starts_with('-') && token.starts_with(flag) && token != flag
    }) {
        return Some(1);
    }
    if token.starts_with('-')
        && !token.starts_with("--")
        && token
            .chars()
            .skip(1)
            .all(|c| sets.short_cluster.iter().any(|group| group.contains(&c)))
    {
        return Some(1);
    }
    None
}

/// `exec_remote_tokens_after_resource`.
pub(crate) fn exec_remote_tokens_after_resource(tokens: &[String]) -> Vec<String> {
    let sets = OptionSets {
        value_flags: &[KUBECTL_OPTIONS_WITH_VALUES, EXEC_OPTIONS_WITH_VALUES],
        boolean_flags: &[KUBECTL_BOOLEAN_OPTIONS, EXEC_BOOLEAN_OPTIONS],
        short_cluster: &[EXEC_BOOLEAN_SHORT_CLUSTER],
    };
    let mut resource_seen = false;
    let mut index = 0;
    while index < tokens.len() {
        if tokens[index] == "--" {
            return tokens[index + 1..].to_vec();
        }
        if let Some(consumed) = kubernetes_option_tokens_consumed(tokens, index, sets) {
            index += consumed;
            continue;
        }
        if !resource_seen {
            resource_seen = true;
            index += 1;
            continue;
        }
        return tokens[index..].to_vec();
    }
    Vec::new()
}

/// `shell_command_script`: the script of a shell's `-c` option.
pub(crate) fn shell_command_script(tokens: &[String]) -> Option<String> {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            return None;
        }
        if index + 1 < tokens.len() {
            if token == "-c" {
                return Some(tokens[index + 1].clone());
            }
            if token.starts_with('-') && !token.starts_with("--") && token[1..].contains('c') {
                return Some(tokens[index + 1].clone());
            }
        }
        index += 1;
    }
    None
}

/// `skip_kubectl_options` bound to the kubectl global option sets.
pub(crate) fn skip_kubectl_options(tokens: &[String], mut index: usize) -> usize {
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            return index + 1;
        }
        if !token.starts_with('-') {
            return index;
        }
        index += kubernetes_option_tokens_consumed(tokens, index, KUBECTL_OPTION_SETS).unwrap_or(1);
    }
    index
}

/// `is_output_redirect_target`.
pub(crate) fn is_output_redirect_target(token: &str, previous_token: Option<&str>) -> bool {
    token.starts_with(['>'])
        || token.starts_with("1>")
        || token.starts_with("2>")
        || previous_token.is_some_and(|previous| OUTPUT_REDIRECT_TOKENS.contains(&previous))
}

/// `_path_candidates`.
pub(crate) fn path_candidates(path: &str) -> Vec<String> {
    let normalized = py_lower(py_strip(path).trim_matches(['\'', '"']));
    if normalized.is_empty() {
        return Vec::new();
    }
    let mut candidates = vec![normalized.clone()];
    if !normalized.starts_with('=') {
        if let Some((_, value)) = normalized.split_once('=') {
            let value = py_strip(value).trim_matches(['\'', '"']);
            if !value.is_empty() && !candidates.iter().any(|known| known == value) {
                candidates.push(value.to_owned());
            }
        }
    }
    candidates
}

/// `is_proc_environ_path`.
pub(crate) fn is_proc_environ_path(path: &str) -> bool {
    path_candidates(path)
        .iter()
        .any(|candidate| PROC_ENVIRON_PATH.is_match(candidate))
}

/// `is_secret_volume_path`.
pub(crate) fn is_secret_volume_path(path: &str) -> bool {
    path_candidates(path).iter().any(|candidate| {
        SERVICE_ACCOUNT_PATH_MARKERS
            .iter()
            .chain(SECRET_VOLUME_PATH_MARKERS)
            .any(|marker| {
                candidate == marker
                    || candidate
                        .strip_prefix(marker)
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    })
}

/// `is_sensitive_env_name`.
pub(crate) fn is_sensitive_env_name(name: &str) -> bool {
    SENSITIVE_ENV_NAME.is_match(py_strip(name))
}

/// `raw_secret_api_path`.
pub(crate) fn raw_secret_api_path(path: &str) -> bool {
    let normalized = py_lower(py_strip(path).trim_matches(['\'', '"']));
    let base = normalized.split('#').next().unwrap_or("");
    let base = base.split('?').next().unwrap_or("");
    RAW_SECRET_PATH.is_match(base)
}

/// `remote_cp_path`.
pub(crate) fn remote_cp_path(value: &str) -> Option<&str> {
    if value.contains("://") {
        return None;
    }
    let (prefix, path) = value.split_once(':')?;
    if prefix.is_empty() || path.is_empty() {
        return None;
    }
    Some(path)
}

/// `resource_token_includes_secret`.
pub(crate) fn resource_token_includes_secret(token: &str) -> bool {
    py_lower(token).split(',').any(|item| {
        let resource = item.split('/').next().unwrap_or("");
        let resource = resource.split('.').next().unwrap_or("");
        resource == "secret" || resource == "secrets"
    })
}

/// `script_dumps_process_environment`.
pub(crate) fn script_dumps_process_environment(script: &str) -> bool {
    ENV_DUMP_PATTERNS
        .iter()
        .any(|pattern| pattern.is_match(script).unwrap_or(false))
}

/// `script_reads_sensitive_env`.
pub(crate) fn script_reads_sensitive_env(script: &str) -> bool {
    if script_dumps_process_environment(script) {
        return true;
    }
    for captures in ENV_EXPANSION.captures_iter(script).flatten() {
        let name = captures
            .name("braced")
            .or_else(|| captures.name("plain"))
            .map_or("", |found| found.as_str());
        if is_sensitive_env_name(name) {
            return true;
        }
    }
    LOOKUP_PATTERNS.iter().any(|pattern| {
        pattern.captures_iter(script).any(|captures| {
            ["name", "dot", "bracket"]
                .iter()
                .filter_map(|group| captures.name(group))
                .any(|found| !found.as_str().is_empty() && is_sensitive_env_name(found.as_str()))
        })
    })
}

/// `matching_source_arguments` over `tokens[1:]`.
pub(crate) fn matching_source_arguments(
    tokens: &[String],
    predicate: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut sources: Vec<String> = Vec::new();
    let mut previous: Option<&str> = None;
    for token in tokens.iter().skip(1) {
        if OUTPUT_REDIRECT_TOKENS.contains(&token.as_str()) {
            previous = Some(token);
            continue;
        }
        let normalized = secret_volume_argument_value(token);
        if token.starts_with('-') && !token.contains('=') {
            previous = Some(token);
            continue;
        }
        if !predicate(&normalized) {
            previous = Some(token);
            continue;
        }
        if is_output_redirect_target(token, previous) {
            previous = Some(token);
            continue;
        }
        if !sources.contains(&normalized) {
            sources.push(normalized);
        }
        previous = Some(token);
    }
    sources
}

/// `secret_volume_argument_value`.
pub(crate) fn secret_volume_argument_value(token: &str) -> String {
    let normalized = strip_redirect_prefix(token);
    if normalized.starts_with('-') {
        if let Some((_, value)) = normalized.split_once('=') {
            return value.to_owned();
        }
    }
    normalized.to_owned()
}

/// `strip_redirect_prefix`.
pub(crate) fn strip_redirect_prefix(token: &str) -> &str {
    for prefix in [">>", "1>>", "2>>", ">", "1>", "2>", "<", "0<"] {
        if let Some(rest) = token.strip_prefix(prefix) {
            return rest;
        }
    }
    token
}

/// `_interpreter_inline_script`.
pub(crate) fn interpreter_inline_script(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let token = args[index].as_str();
        if (token == "-c" || token == "-e") && index + 1 < args.len() {
            return Some(args[index + 1].clone());
        }
        for flag in ["-c", "-e"] {
            if let Some(rest) = token.strip_prefix(flag) {
                if !rest.is_empty() {
                    return Some(rest.to_owned());
                }
            }
        }
        index += 1;
    }
    None
}

/// `_is_inline_interpreter_command`.
pub(crate) fn is_inline_interpreter_command(command_name: &str) -> bool {
    command_name.starts_with("python")
        || matches!(command_name, "node" | "nodejs" | "perl" | "php" | "ruby")
}

/// `interpreter_reads_sensitive_env`.
pub(crate) fn interpreter_reads_sensitive_env(command_name: &str, args: &[String]) -> bool {
    if !is_inline_interpreter_command(command_name) {
        return false;
    }
    if let Some(script) = interpreter_inline_script(args) {
        return script_reads_sensitive_env(&script);
    }
    let joined = args.join(" ");
    args.iter().any(|token| token == "-")
        && args.iter().any(|token| token.starts_with("<<"))
        && script_reads_sensitive_env(&joined)
}

/// Python `str.split()` (whitespace runs, no empty parts).
pub(crate) fn py_split_whitespace(text: &str) -> Vec<String> {
    text.split(is_py_space)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

static SAFE_JSONPATH_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A\{?\.?(?:items(?:\[-?\d+\]|\[\*\])?\.)?(?:metadata\.(?:name|namespace|uid)|status\.phase)\}?\z",
    )
    .expect("safe jsonpath field pattern")
});

/// A `{range …}` selector: a dotted path with optional list indices.
///
/// The selector chooses which objects the loop walks. It renders nothing
/// itself, so it is screened only for shape -- a name that could carry shell
/// metacharacters or another brace group is refused.
static JSONPATH_RANGE_SELECTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A\.?[A-Za-z0-9_\-]+(?:\[(?:\*|-?\d+)\])?(?:\.[A-Za-z0-9_\-]+(?:\[(?:\*|-?\d+)\])?)*\z",
    )
    .expect("jsonpath range selector pattern")
});

/// The brace groups of a `jsonpath` template, or `None` when anything renders
/// outside them.
///
/// Text between groups is emitted verbatim, so a template that carries any is
/// refused rather than screened character by character.
fn jsonpath_brace_groups(template: &str) -> Option<Vec<String>> {
    let mut groups = Vec::new();
    let mut rest = template;
    loop {
        let Some(open) = rest.find('{') else {
            return rest.trim().is_empty().then_some(groups);
        };
        if !rest[..open].trim().is_empty() {
            return None;
        }
        let body = &rest[open + 1..];
        let close = body.find('}')?;
        groups.push(body[..close].trim().to_owned());
        rest = &body[close + 1..];
    }
}

/// Whether a brace group is a quoted separator such as `{"\n"}`.
fn jsonpath_string_literal(group: &str) -> bool {
    let mut characters = group.chars();
    let Some(quote) = characters
        .next()
        .filter(|first| *first == '"' || *first == '\'')
    else {
        return false;
    };
    group.len() >= 2
        && group.ends_with(quote)
        && !group[1..group.len() - 1].contains(['{', '}', '$', '`', quote])
}

/// Whether a `jsonpath` template renders names and separators alone.
///
/// A `kubectl` template may loop: `{range …}{.name}{"\n"}{end}` walks a list
/// and prints one field for each entry it reaches. The `range` selector picks
/// the objects the loop visits and prints nothing itself, so what the template
/// renders is decided entirely by the groups inside the loop. A body that emits
/// a name field and quoted separators cannot print a value, whatever the
/// selector reached -- `{.value}` beside it would, and is refused.
pub(crate) fn jsonpath_renders_only_names(template: &str) -> bool {
    let groups = jsonpath_brace_groups(template).unwrap_or_default();
    let Some(first) = groups.first() else {
        return false;
    };
    let Some(selector) = first.strip_prefix("range ") else {
        return false;
    };
    if groups.last().map(String::as_str) != Some("end")
        || !JSONPATH_RANGE_SELECTOR.is_match(selector.trim())
    {
        return false;
    }
    let body = &groups[1..groups.len() - 1];
    let renders_a_name =
        |group: &String| group == ".name" || SAFE_JSONPATH_FIELD.is_match(group.as_str());
    body.iter().any(renders_a_name)
        && body
            .iter()
            .all(|group| renders_a_name(group) || jsonpath_string_literal(group))
}

/// Whether a `jsonpath` template is one bare safe field such as
/// `{.metadata.name}`.
pub(crate) fn safe_jsonpath_field(template: &str) -> bool {
    SAFE_JSONPATH_FIELD.is_match(template)
}

/// `value` with every names-only `jsonpath` template payload removed.
///
/// A credential-location screen reads raw command text, where a selector such
/// as `…containers[*].env[*]` looks like a dotenv path. The selector names a
/// container's environment list, and a template that renders names alone
/// cannot print what that list holds, so only those payloads are dropped --
/// a template carrying `{.value}` keeps its text and its screen.
pub(crate) fn without_names_only_jsonpath_templates(value: &str) -> String {
    const KINDS: [&str; 2] = ["jsonpath-as-json=", "jsonpath="];
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find("jsonpath") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(kind) = KINDS.iter().find(|kind| tail.starts_with(**kind)) else {
            out.push_str("jsonpath");
            rest = &tail["jsonpath".len()..];
            continue;
        };
        out.push_str(kind);
        let after = &tail[kind.len()..];
        let (payload, consumed) = jsonpath_payload(value, at, after);
        if !jsonpath_renders_only_names(payload) {
            out.push_str(&after[..consumed]);
        }
        rest = &after[consumed..];
    }
    out.push_str(rest);
    out
}

/// The template an argument carries, and how much of `after` it occupies.
///
/// A template holds blanks, so an unquoted one ends at the first blank while a
/// quoted one runs to its closing quote.
fn jsonpath_payload<'a>(value: &str, at: usize, after: &'a str) -> (&'a str, usize) {
    let quote = value[..at]
        .chars()
        .next_back()
        .filter(|character| *character == '\'' || *character == '"');
    if let Some(quote) = quote {
        if let Some(end) = after.find(quote) {
            return (&after[..end], end + quote.len_utf8());
        }
    }
    let end = after.find(char::is_whitespace).unwrap_or(after.len());
    (&after[..end], end)
}
