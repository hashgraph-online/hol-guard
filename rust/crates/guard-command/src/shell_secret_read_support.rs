//! Private parsing and path helpers for shell secret-read assessment
//! (`runtime/_shell_secret_read_support.py`, 486 lines — verbatim, plus the
//! minimal slices of `secret_sensitivity`, `interpreter_options`,
//! `local_read_operands`, `read_only_filters`, `pytest_config_safety`,
//! `interpreter_observers`, `constants_core`, `false_positive_rules` they
//! import).

#![cfg_attr(windows, allow(dead_code))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

use crate::command_model::CanonicalCommand;
use crate::home_path_text::{expand_home, normalize_path};
use crate::runtime_read_paths::path_is_relative_to;
use crate::shell_execution_context_support::{
    split_shell_tokens, SHELL_CWD_MISSING_DIRECTORY, SHELL_CWD_NOT_DIRECTORY,
    SHELL_CWD_UNREADABLE_DIRECTORY,
};

// `_SHELLS` (:17), `_SCRIPT_SUFFIXES` (:18-31), `_OTHER_READERS` (:32-48),
// limits (:49-52).
pub(crate) const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "source", ".",
];
pub(crate) const SCRIPT_SUFFIXES: &[&str] = &[
    ".sh", ".bash", ".zsh", ".ksh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
];
pub(crate) const OTHER_READERS: &[&str] = &[
    "base64", "xxd", "od", "hexdump", "strings", "tac", "less", "more", "sort", "uniq", "wc", "ag",
    "ack",
];
pub(crate) const MAX_SCRIPTS: usize = 16;
pub(crate) const MAX_DEPTH: usize = 4;
pub(crate) const MAX_TOTAL_BYTES: usize = 128 * 1024;
pub(crate) const MAX_INLINE_SCRIPT_BYTES: usize = 64 * 1024;

fn python_executable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$").expect("python executable")
    })
}
fn literal_read_re() -> &'static FancyRegex {
    static RE: OnceLock<FancyRegex> = OnceLock::new();
    RE.get_or_init(|| {
        FancyRegex::new(
            r#"(?:\bopen|\breadFile(?:Sync)?|\bcreateReadStream|\bBun\.file|\bload_dotenv)\s*\(\s*(['"])([^'"\n\x00]{1,4096})\1"#,
        )
        .expect("literal read")
    })
}
fn path_read_re() -> &'static FancyRegex {
    static RE: OnceLock<FancyRegex> = OnceLock::new();
    RE.get_or_init(|| {
        FancyRegex::new(
            r#"\bPath\s*\(\s*(['"])([^'"\n\x00]{1,4096})\1\s*\)\s*\.\s*(?:read_text|read_bytes|open)\s*\("#,
        )
        .expect("path read")
    })
}

const SHORT_CIRCUITING_CD_FAILURES: &[&str] = &[
    SHELL_CWD_MISSING_DIRECTORY,
    SHELL_CWD_NOT_DIRECTORY,
    SHELL_CWD_UNREADABLE_DIRECTORY,
];
pub(crate) const FLOW_OPERATORS: &[&str] = &["&&", "||", "|", ";", "&"];

/// `_literal_read_paths` (:68-71).
///
/// The patterns are `fancy_regex` (backreference on the quote), whose matcher
/// can fail at run time (backtrack limit). A scan error must never read as "no
/// literal read here": that would silently drop a secret read. It is treated
/// as a match instead, by emitting [`FAIL_CLOSED_SENSITIVE_READ`], which the
/// callers classify as a sensitive path like any other literal.
pub(crate) fn literal_read_paths(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for re in [literal_read_re(), path_read_re()] {
        collect_literal_reads(
            re.captures_iter(source)
                .map(|captures| captures.map(|c| c.get(2).map(|path| path.as_str().to_owned()))),
            &mut out,
        );
    }
    out
}

fn collect_literal_reads(
    matches: impl Iterator<Item = Result<Option<String>, fancy_regex::Error>>,
    out: &mut Vec<String>,
) {
    for found in matches {
        match found {
            Ok(Some(path)) => out.push(path),
            Ok(None) => {}
            Err(_) => {
                out.push(FAIL_CLOSED_SENSITIVE_READ.to_owned());
                return;
            }
        }
    }
}

/// Stand-in literal reported when a read-scan regex errors. `.env` is always
/// classified as a sensitive local file, so the failure surfaces as a
/// secret-read finding rather than a silent allow.
pub(crate) const FAIL_CLOSED_SENSITIVE_READ: &str = ".env";

/// `_python_executable` (:74-75). `re.IGNORECASE` is folded by lowercasing
/// the candidate name; the Python pattern is unanchored `re.match`-style
/// (`$` suffix only), so anchor with `^` here.
pub(crate) fn python_executable(name: &str) -> bool {
    let lower = name.to_lowercase();
    python_executable_re().is_match(&lower)
}

// ---------------------------------------------------------------------------
// secret_sensitivity.py `classify_secret_path` (:221-288) + tables (:10-105).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const SECRET_PATH_TEXT_MARKERS: &[(&str, &str)] = &[
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "Python package credentials"),
    (".aws/credentials", "AWS shared credentials file"),
    (".ssh/", "SSH private key"),
    (".gnupg/", "GnuPG key material"),
    (".docker/config.json", "Docker client config"),
    (".kube/config", "Kubernetes config"),
    ("terraform.tfvars", "Terraform variable secrets"),
    (".git-credentials", "Git credential store"),
];

fn sensitive_basename_labels() -> &'static BTreeMap<&'static str, &'static str> {
    static M: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    M.get_or_init(|| {
        [
            (".npmrc", "npm registry credentials"),
            (".pypirc", "Python package credentials"),
            (".netrc", "netrc credentials"),
            (".git-credentials", "Git credential store"),
            (".terraform.tfvars", "Terraform variable secrets"),
            ("terraform.tfvars", "Terraform variable secrets"),
            ("private-key.pem", "wallet/private-key file"),
            ("private.key", "wallet/private-key file"),
            ("wallet.key", "wallet/private-key file"),
            (".wallet", "wallet/private-key file"),
            ("wallet.dat", "wallet/private-key file"),
            ("id_rsa", "SSH private key"),
            ("id_ed25519", "SSH private key"),
            ("id_ecdsa", "SSH private key"),
        ]
        .into_iter()
        .collect()
    })
}
fn sensitive_basename_keywords() -> &'static [&'static str] {
    &[
        "private_key",
        "private-key",
        "privatekey",
        "wallet_key",
        "wallet-key",
    ]
}
fn redacted_basename_labels() -> &'static BTreeMap<&'static str, &'static str> {
    static M: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    M.get_or_init(|| {
        [
            ("id_rsa", "SSH private key"),
            ("id_ed25519", "SSH private key"),
            ("id_ecdsa", "SSH private key"),
        ]
        .into_iter()
        .collect()
    })
}
fn sensitive_directory_labels() -> &'static BTreeMap<&'static str, &'static str> {
    static M: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    M.get_or_init(|| [(".gnupg", "GnuPG key material")].into_iter().collect())
}
fn sensitive_suffix_labels() -> &'static BTreeMap<&'static [&'static str], &'static str> {
    static M: OnceLock<BTreeMap<&'static [&'static str], &'static str>> = OnceLock::new();
    M.get_or_init(|| {
        [
            (&[".aws", "credentials"][..], "AWS shared credentials file"),
            (&[".aws", "config"][..], "AWS shared config file"),
            (&[".docker", "config.json"][..], "Docker client config"),
            (&[".kube", "config"][..], "Kubernetes config"),
            (&[".ssh", "id_rsa"][..], "SSH private key"),
            (&[".ssh", "id_ed25519"][..], "SSH private key"),
            (&[".ssh", "id_ecdsa"][..], "SSH private key"),
            (&[".ssh", "config"][..], "SSH client config"),
        ]
        .into_iter()
        .collect()
    })
}
fn sensitive_path_reason(family: &str) -> &'static str {
    match family {
        "local .env file" => {
            "Guard treats .env files as sensitive because they commonly store local secrets."
        }
        "npm registry credentials" => {
            "Guard treats .npmrc as sensitive because it may contain registry tokens."
        }
        "Python package credentials" => {
            "Guard treats .pypirc as sensitive because it may contain package credentials."
        }
        "netrc credentials" => "Guard treats .netrc as sensitive because it may contain login secrets.",
        "Git credential store" => {
            "Guard treats .git-credentials as sensitive because it may contain repository credentials."
        }
        "AWS shared credentials file" => {
            "Guard treats AWS shared credentials as sensitive because they contain cloud access keys."
        }
        "AWS shared config file" => {
            "Guard treats AWS shared config as sensitive because it may contain credential profiles."
        }
        "Docker client config" => {
            "Guard treats Docker client config as sensitive because it may contain registry auth."
        }
        "Kubernetes config" => {
            "Guard treats Kubernetes config as sensitive because it may include cluster credentials."
        }
        "SSH private key" => {
            "Guard treats SSH private keys as sensitive because they provide direct host access."
        }
        "SSH client config" => {
            "Guard treats SSH config as sensitive because it may reveal or shape host credentials."
        }
        "GnuPG key material" => {
            "Guard treats GnuPG key material as sensitive because it can unlock encrypted assets."
        }
        "Terraform variable secrets" => {
            "Guard treats Terraform variable files as sensitive because they often contain secrets."
        }
        "wallet/private-key file" => {
            "Guard treats wallet and private-key files as sensitive because they can authorize account control."
        }
        _ => "",
    }
}

/// `SecretPathMatch` (:197-211).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct SecretPathMatch {
    pub family: String,
    pub path: String,
    pub sensitivity: &'static str,
    pub reason: &'static str,
    pub requested_path: String,
}

fn make_match(
    requested_path: &str,
    normalized_path: &str,
    family: &str,
    sensitivity: &'static str,
) -> SecretPathMatch {
    SecretPathMatch {
        family: family.to_owned(),
        path: normalized_path.to_owned(),
        sensitivity,
        reason: sensitive_path_reason(family),
        requested_path: requested_path.to_owned(),
    }
}

/// `classify_secret_path` (:221-288).
pub(crate) fn classify_secret_path(
    path: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<SecretPathMatch> {
    let requested_path = path.trim().trim_matches('\'').trim_matches('"');
    if requested_path.is_empty() {
        return None;
    }
    let expanded_home = expand_home(requested_path, home_dir);
    let normalized_path = normalize_path(&expanded_home, cwd);
    let lowered_segments: Vec<String> = normalized_path
        .replace('\\', "/")
        .to_lowercase()
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    if lowered_segments.is_empty() {
        return None;
    }
    let basename = lowered_segments.last().unwrap().clone();
    if basename == ".env" || basename.starts_with(".env.") {
        return Some(make_match(
            requested_path,
            &normalized_path,
            "local .env file",
            "critical",
        ));
    }
    if let Some(family) = sensitive_basename_labels().get(basename.as_str()) {
        let sensitivity = if *family == "wallet/private-key file" {
            "critical"
        } else {
            "high"
        };
        return Some(make_match(
            requested_path,
            &normalized_path,
            family,
            sensitivity,
        ));
    }
    if sensitive_basename_keywords()
        .iter()
        .any(|kw| basename.contains(kw))
    {
        return Some(make_match(
            requested_path,
            &normalized_path,
            "wallet/private-key file",
            "critical",
        ));
    }
    if lowered_segments.iter().any(|s| s == "...")
        && redacted_basename_labels().contains_key(basename.as_str())
    {
        let family = redacted_basename_labels()[basename.as_str()];
        let sensitivity = if family == "SSH private key" {
            "critical"
        } else {
            "high"
        };
        return Some(make_match(
            requested_path,
            &normalized_path,
            family,
            sensitivity,
        ));
    }
    for (directory, family) in sensitive_directory_labels() {
        if lowered_segments.iter().any(|s| s == directory) {
            return Some(make_match(requested_path, &normalized_path, family, "high"));
        }
    }
    for (suffix, family) in sensitive_suffix_labels() {
        let n = suffix.len();
        if lowered_segments.len() >= n
            && lowered_segments[lowered_segments.len() - n..]
                .iter()
                .map(String::as_str)
                .eq(suffix.iter().copied())
        {
            let sensitivity = if *family == "SSH private key" {
                "critical"
            } else {
                "high"
            };
            return Some(make_match(
                requested_path,
                &normalized_path,
                family,
                sensitivity,
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// interpreter_options.py `shell_interpreter_command_payload` (:19-56).
// ---------------------------------------------------------------------------

const LONG_OPTIONS_WITH_VALUES: &[&str] = &["--init-file", "--rcfile"];

/// `InterpreterFlagPayload` (:9-13).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct InterpreterFlagPayload {
    pub script_text: String,
    pub tokens_consumed: usize,
}

/// `_short_shell_option_cluster` (:59-69). `(has_command_flag, consumes_next)`.
fn short_shell_option_cluster(token: &str) -> (bool, bool) {
    let flag_text = &token[1..];
    if flag_text.is_empty() || !flag_text.chars().all(|c| c.is_ascii_alphabetic()) {
        return (false, false);
    }
    let mut has_command = false;
    let mut consumes_next = false;
    for flag in flag_text.chars() {
        if flag == 'c' {
            has_command = true;
        } else if flag == 'o' || flag == 'O' {
            consumes_next = true;
        }
    }
    (has_command, consumes_next)
}

/// `shell_interpreter_command_payload` (:19-56).
pub(crate) fn shell_interpreter_command_payload(
    parts: &[String],
    command_index: usize,
) -> Option<InterpreterFlagPayload> {
    let mut index = command_index + 1;
    while index < parts.len() {
        let token = parts[index]
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_owned();
        if token.is_empty() {
            index += 1;
            continue;
        }
        if token == "-" || token == "--" {
            return None;
        }
        if token.starts_with("--") {
            let option_name = token.split('=').next().unwrap_or("");
            let has_sep = token.contains('=');
            if LONG_OPTIONS_WITH_VALUES.contains(&option_name) && !has_sep {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if !token.starts_with('-') && !token.starts_with('+') {
            return None;
        }
        let (has_command_flag, consumes_next_value) = short_shell_option_cluster(&token);
        let script_index = index + 1 + usize::from(consumes_next_value);
        if has_command_flag {
            if script_index >= parts.len() {
                return None;
            }
            let script_text = parts[script_index].trim().to_owned();
            if script_text.is_empty() {
                return None;
            }
            return Some(InterpreterFlagPayload {
                script_text,
                tokens_consumed: script_index - command_index,
            });
        }
        index += 1 + usize::from(consumes_next_value);
    }
    None
}

// ---------------------------------------------------------------------------
// false_positive_rules.py slices: SOURCE_INSPECTION tables,
// `target_is_known_skill_doc_path` (:119-160), `_path_has_symlink_component`
// (:184-197).
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) const SOURCE_INSPECTION_SENSITIVE_PARTS: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "credentials",
];
#[allow(dead_code)]
pub(crate) const SOURCE_INSPECTION_BENIGN_DOTFILES: &[&str] = &[".nvmrc"];
#[allow(dead_code)]
const SOURCE_INSPECTION_PARTS: &[&str] = &[
    "docs",
    "doc",
    "documentation",
    "readme",
    "changelog",
    "examples",
    "example",
    "test",
    "tests",
    "spec",
    "specs",
    "fixtures",
    "fixture",
    "samples",
    "sample",
];
#[allow(dead_code)]
const SOURCE_INSPECTION_EXTENSIONS: &[&str] = &[
    ".c", ".cc", ".cpp", ".css", ".go", ".h", ".hpp", ".html", ".java", ".js", ".jsx", ".json",
    ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".ts", ".tsx", ".yaml", ".yml",
];
#[allow(dead_code)]
const KNOWN_SKILL_DOC_ROOT_SUFFIXES: &[&str] = &[
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
];

/// `os.path.normpath` on `/`-separated text (POSIX-only semantics).
#[allow(dead_code)]
fn os_normpath(value: &str) -> String {
    let absolute = value.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|p| *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            _ => parts.push(part),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `_path_has_symlink_component` (:184-197).
#[allow(dead_code)]
fn path_has_symlink_component(normalized_target: &str, root: &str) -> bool {
    if Path::new(root).is_symlink() {
        return true;
    }
    if normalized_target == root {
        return false;
    }
    let relative = normalized_target
        .strip_prefix(&format!("{root}/"))
        .unwrap_or(normalized_target);
    let mut current = root.to_owned();
    for part in relative.split('/') {
        if part.is_empty() {
            return true;
        }
        current = format!("{current}/{part}");
        if Path::new(&current).is_symlink() {
            return true;
        }
    }
    false
}

/// `target_is_known_skill_doc_path` (:119-160).
#[allow(dead_code)]
fn target_is_known_skill_doc_path(target: &str, home_dir: Option<&Path>) -> bool {
    if target
        .chars()
        .any(|c| matches!(c, '$' | '`' | '<' | '>' | '|' | ';' | '&'))
    {
        return false;
    }
    if let Some(rest) = target.strip_prefix("skill://") {
        let skill_name_raw = rest.trim().trim_matches('\'').trim_matches('"');
        if !skill_name_raw.is_empty() {
            let skill_name = os_normpath(skill_name_raw).replace('\\', "/");
            if skill_name.is_empty()
                || skill_name.starts_with("..")
                || skill_name == "."
                || skill_name.starts_with('/')
            {
                return false;
            }
            let home = home_dir
                .map(|h| h.to_path_buf())
                .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
                .unwrap_or_default();
            let home = os_normpath(&home.to_string_lossy()).replace('\\', "/");
            for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES {
                let root = format!("{home}/{suffix}");
                let candidate_dir = format!("{root}/{skill_name}");
                let candidate_file = format!("{candidate_dir}/SKILL.md");
                if !Path::new(&candidate_file).is_file() {
                    continue;
                }
                let real_candidate = std::fs::canonicalize(&candidate_dir)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let real_file = std::fs::canonicalize(&candidate_file)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if real_file.starts_with(&format!("{real_candidate}/")) {
                    return true;
                }
            }
        }
        return false;
    }
    let expanded = if target == "~" || target.starts_with("~/") {
        let home = home_dir
            .map(|h| h.to_path_buf())
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_default();
        format!("{}{}", home.to_string_lossy(), &target[1..])
    } else {
        expand_home(target, home_dir)
    };
    let normalized = os_normpath(&expanded).replace('\\', "/");
    let home = home_dir
        .map(|h| h.to_path_buf())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_default();
    let home = os_normpath(&home.to_string_lossy()).replace('\\', "/");
    for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES {
        let root = format!("{home}/{suffix}");
        if normalized != root && !normalized.starts_with(&format!("{root}/")) {
            continue;
        }
        if Path::new(&root).is_symlink() {
            continue;
        }
        if !path_has_symlink_component(&normalized, &root) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// read_only_filters.py `_read_only_lookup_target_is_safe` (:376-400).
// ---------------------------------------------------------------------------

/// `_read_only_lookup_target_is_safe` (:376-400).
#[allow(dead_code)]
fn read_only_lookup_target_is_safe(
    target: &str,
    allow_dirs: bool,
    home_dir: Option<&Path>,
) -> bool {
    let stripped = target.trim().trim_matches('\'').trim_matches('"');
    if stripped.is_empty() || stripped == "." {
        return allow_dirs;
    }
    if stripped == "-" {
        return false;
    }
    if stripped
        .chars()
        .any(|c| matches!(c, '$' | '`' | '<' | '>' | '|' | ';' | '&'))
    {
        return false;
    }
    let normalized = stripped.replace('\\', "/");
    let parts: Vec<&str> = Path::new(&normalized)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    let lowered_parts: Vec<String> = parts.iter().map(|p| p.to_lowercase()).collect();
    if parts.is_empty() {
        return allow_dirs;
    }
    if parts.contains(&"..")
        || stripped
            .chars()
            .any(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        return false;
    }
    if lowered_parts
        .iter()
        .any(|p| SOURCE_INSPECTION_SENSITIVE_PARTS.contains(&p.as_str()))
    {
        return false;
    }
    if target_is_known_skill_doc_path(stripped, home_dir) {
        return true;
    }
    let hidden_parts: Vec<&String> = lowered_parts
        .iter()
        .filter(|p| p.starts_with('.'))
        .collect();
    if !hidden_parts.is_empty()
        && !hidden_parts
            .iter()
            .all(|p| SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&p.as_str()))
    {
        return false;
    }
    if lowered_parts
        .iter()
        .any(|p| SOURCE_INSPECTION_PARTS.contains(&p.as_str()))
    {
        return true;
    }
    let suffix = Path::new(&normalized)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if SOURCE_INSPECTION_EXTENSIONS.contains(&suffix.as_str()) {
        return true;
    }
    allow_dirs
}

// ---------------------------------------------------------------------------
// local_read_operands.py (459 lines): operand extraction + containment.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const RG_SHORT_OPTIONS_WITH_VALUE: &[char] = &[
    'A', 'B', 'C', 'E', 'd', 'e', 'f', 'g', 'j', 'm', 'M', 'r', 'T', 't',
];
#[allow(dead_code)]
const RG_LONG_OPTIONS_WITH_VALUE: &[&str] = &[
    "--after-context",
    "--before-context",
    "--context",
    "--encoding",
    "--file",
    "--glob",
    "--iglob",
    "--max-columns",
    "--max-count",
    "--max-depth",
    "--max-filesize",
    "--regexp",
    "--replace",
    "--threads",
    "--type",
    "--type-not",
];

/// `_ripgrep_args_expand_hidden_files` (:36-58).
#[allow(dead_code)]
fn ripgrep_args_expand_hidden_files(args: &[String]) -> bool {
    let mut expect_value = false;
    for arg in args {
        if expect_value {
            expect_value = false;
            continue;
        }
        if arg == "--" {
            break;
        }
        if arg == "--hidden" || arg == "--unrestricted" {
            return true;
        }
        if arg.starts_with("--") {
            expect_value = !arg.contains('=') && RG_LONG_OPTIONS_WITH_VALUE.contains(&arg.as_str());
            continue;
        }
        if !arg.starts_with('-') || arg == "-" {
            continue;
        }
        let cluster: Vec<char> = arg[1..].chars().collect();
        for (index, option) in cluster.iter().enumerate() {
            if *option == 'u' || *option == '.' {
                return true;
            }
            if RG_SHORT_OPTIONS_WITH_VALUE.contains(option) {
                expect_value = index == cluster.len() - 1;
                break;
            }
        }
    }
    false
}

/// `_shell_segment_file_operand_tokens` (:61-74).
pub(crate) fn shell_segment_file_operand_tokens(segment: &[String]) -> Vec<String> {
    if segment.is_empty() {
        return Vec::new();
    }
    let command_name = basename_lower(&segment[0]);
    let args = &segment[1..];
    if command_name == "cat" {
        return cat_file_operand_tokens(args);
    }
    if command_name == "head" || command_name == "tail" {
        return plain_file_operand_tokens(args);
    }
    if command_name == "sed" {
        return sed_file_operand_tokens(args);
    }
    if ["grep", "egrep", "fgrep", "rg"].contains(&command_name.as_str()) {
        return search_file_operand_tokens(&command_name, args);
    }
    Vec::new()
}

/// `_local_read_operands_resolve_safely` (:77-136).
#[allow(dead_code)]
pub(crate) fn local_read_operands_resolve_safely(
    command_name: &str,
    args: &[String],
    cwd: &Path,
    root: &Path,
) -> bool {
    let allow_dirs = ["grep", "egrep", "fgrep", "rg"].contains(&command_name);
    let resolved_root = match root.canonicalize() {
        Ok(r) => r,
        Err(_) => return false,
    };
    if command_name == "rg" && ripgrep_args_expand_hidden_files(args) {
        return false;
    }
    let mut all_args: Vec<String> = vec![command_name.to_owned()];
    all_args.extend(args.iter().cloned());
    let operand_roles: Vec<(String, bool)> =
        if ["grep", "egrep", "fgrep", "rg"].contains(&command_name) {
            search_file_operand_roles(command_name, args)
        } else {
            shell_segment_file_operand_tokens(&all_args)
                .into_iter()
                .map(|o| (o, false))
                .collect()
        };
    for (operand, is_search_glob) in operand_roles {
        let stripped = operand.trim().trim_matches('\'').trim_matches('"');
        if stripped.is_empty() || stripped == "-" {
            continue;
        }
        if is_search_glob {
            if !search_glob_pattern_is_safe(stripped, Some(root)) {
                return false;
            }
            continue;
        }
        let has_glob_metacharacter = stripped.chars().any(|c| matches!(c, '*' | '?' | '['));
        let mut candidate = PathBuf::from(stripped);
        if !candidate.is_absolute() {
            candidate = cwd.join(&candidate);
        }
        if has_glob_metacharacter {
            if !bounded_local_read_glob_is_safe(&candidate, root, allow_dirs) {
                return false;
            }
            continue;
        }
        let lexical = PathBuf::from(normalize_path(&candidate.to_string_lossy(), None));
        let resolved = match candidate.canonicalize() {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        let relative = match resolved.strip_prefix(&resolved_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => return false,
        };
        let safe_git_pointer = command_name == "cat" && relative.as_os_str() == ".git";
        if resolved != lexical
            || (!safe_git_pointer
                && !read_only_lookup_target_is_safe(
                    &relative.to_string_lossy(),
                    allow_dirs && resolved.is_dir(),
                    Some(root),
                ))
        {
            return false;
        }
    }
    true
}

/// `_bounded_local_read_glob_is_safe` (:139-212). `glob.glob` semantics —
/// `*`/`?`/`[seq]` per component; no `**` (guarded by
/// `search_glob_pattern_is_safe` upstream / globbing here is per-segment).
#[allow(dead_code)]
fn bounded_local_read_glob_is_safe(candidate: &Path, root: &Path, allow_dirs: bool) -> bool {
    let candidate_str = candidate.to_string_lossy();
    // Python glob with a metachar pattern walks the parent and fnmatches each
    // entry; recursive `**` is already excluded.  Model a single-level match
    // against the parent directory.
    let (parent, pattern) = match candidate_str.rfind('/') {
        Some(index) => (&candidate_str[..index], &candidate_str[index + 1..]),
        None => (".", candidate_str.as_ref()),
    };
    let parent = if parent.is_empty() { "/" } else { parent };
    if pattern.contains('/') {
        return false;
    }
    let dir = match std::fs::read_dir(parent) {
        Ok(d) => d,
        Err(_) => return false,
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !fnmatchcase(pattern, &name) {
            continue;
        }
        let resolved = match entry.path().canonicalize() {
            Ok(r) => r,
            Err(_) => return false,
        };
        let lexical = PathBuf::from(normalize_path(&entry.path().to_string_lossy(), None));
        let relative = match resolved.strip_prefix(root.canonicalize().unwrap_or_default()) {
            Ok(r) => r.to_path_buf(),
            Err(_) => return false,
        };
        let mut lookup_target = relative.to_string_lossy().into_owned();
        let literal_fallback = resolved != lexical;
        if literal_fallback {
            lookup_target = lookup_target.replace(['[', ']'], "");
        }
        if resolved != lexical
            || lookup_target.is_empty()
            || !read_only_lookup_target_is_safe(
                &lookup_target,
                allow_dirs && resolved.is_dir(),
                Some(root),
            )
        {
            return false;
        }
    }
    true
}

/// `fnmatch.fnmatchcase` (POSIX `*`/`?`/`[seq]`, no path separator semantics).
#[allow(dead_code)]
fn fnmatchcase(pattern: &str, name: &str) -> bool {
    fn rec(pat: &[char], text: &[char]) -> bool {
        if pat.is_empty() {
            return text.is_empty();
        }
        match pat[0] {
            '*' => (0..=text.len()).any(|i| rec(&pat[1..], &text[i..])),
            '?' => !text.is_empty() && rec(&pat[1..], &text[1..]),
            '[' => {
                if text.is_empty() {
                    return false;
                }
                let mut index = 1;
                let negate = pat.get(1) == Some(&'!') || pat.get(1) == Some(&'^');
                if negate {
                    index += 1;
                }
                let mut matched = false;
                let mut prev: Option<char> = None;
                let mut i = index;
                while i < pat.len() && pat[i] != ']' {
                    if pat[i] == '-' && prev.is_some() && i + 1 < pat.len() && pat[i + 1] != ']' {
                        let lo = prev.unwrap();
                        let hi = pat[i + 1];
                        if lo <= text[0] && text[0] <= hi {
                            matched = true;
                        }
                        i += 1;
                    } else {
                        if pat[i] == text[0] {
                            matched = true;
                        }
                        prev = Some(pat[i]);
                    }
                    i += 1;
                }
                if i >= pat.len() {
                    // Unclosed class: `[` is literal.
                    return text[0] == '[' && rec(&pat[1..], &text[1..]);
                }
                if matched != negate {
                    rec(&pat[i + 1..], &text[1..])
                } else {
                    false
                }
            }
            c => !text.is_empty() && text[0] == c && rec(&pat[1..], &text[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = name.chars().collect();
    rec(&p, &t)
}

/// `_cat_file_operand_tokens` (:214-230).
fn cat_file_operand_tokens(args: &[String]) -> Vec<String> {
    let mut operands = Vec::new();
    let mut after_options = false;
    for arg in args {
        if after_options {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg == "-" {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        operands.push(arg.clone());
    }
    operands
}

/// `_plain_file_operand_tokens` (:232-255).
fn plain_file_operand_tokens(args: &[String]) -> Vec<String> {
    let mut operands = Vec::new();
    let mut skip_next = false;
    let mut after_options = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if after_options {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if ["-n", "--lines", "-c", "--bytes"].contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--lines=") || arg.starts_with("--bytes=") {
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            continue;
        }
        operands.push(arg.clone());
    }
    operands
}

/// `_sed_file_operand_tokens` (:257-290).
fn sed_file_operand_tokens(args: &[String]) -> Vec<String> {
    let mut operands = Vec::new();
    let mut scripts_seen = 0usize;
    let mut skip_script = false;
    let mut after_options = false;
    for arg in args {
        if skip_script {
            skip_script = false;
            scripts_seen += 1;
            continue;
        }
        if after_options {
            operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if ["-n", "--quiet", "--silent"].contains(&arg.as_str()) {
            continue;
        }
        if arg == "-e" || arg == "--expression" {
            skip_script = true;
            continue;
        }
        if arg.starts_with("-e") && arg.len() > 2 {
            scripts_seen += 1;
            continue;
        }
        if arg.starts_with("--expression=") {
            scripts_seen += 1;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        if scripts_seen == 0 {
            scripts_seen += 1;
            continue;
        }
        operands.push(arg.clone());
    }
    operands
}

/// `_search_file_operand_tokens` (:293-295).
fn search_file_operand_tokens(command_name: &str, args: &[String]) -> Vec<String> {
    search_file_operand_roles(command_name, args)
        .into_iter()
        .map(|(o, _)| o)
        .collect()
}

/// `_search_concrete_file_operand_tokens` (:297-301).
#[allow(dead_code)]
pub(crate) fn search_concrete_file_operand_tokens(
    command_name: &str,
    args: &[String],
) -> Vec<String> {
    search_file_operand_roles(command_name, args)
        .into_iter()
        .filter(|(_, glob)| !*glob)
        .map(|(o, _)| o)
        .collect()
}

/// `search_operands_are_safe` (:303-317).
#[allow(dead_code)]
pub(crate) fn search_operands_are_safe(
    command_name: &str,
    args: &[String],
    root: Option<&Path>,
) -> bool {
    let roles = search_file_operand_roles(command_name, args);
    roles.iter().all(|(operand, is_search_glob)| {
        if *is_search_glob {
            search_glob_pattern_is_safe(operand, root)
        } else {
            read_only_lookup_target_is_safe(operand, true, root)
        }
    })
}

const SEARCH_VALUE_OPTIONS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-e",
    "-f",
    "-g",
    "-m",
    "-t",
    "--after-context",
    "--before-context",
    "--context",
    "--exclude",
    "--exclude-dir",
    "--file",
    "--glob",
    "--iglob",
    "--include",
    "--max-count",
    "--max-depth",
    "--max-filesize",
    "--regexp",
    "--type",
    "--type-not",
];

/// `_search_file_operand_roles` (:319-413). `(operand, is_search_glob)`.
fn search_file_operand_roles(command_name: &str, args: &[String]) -> Vec<(String, bool)> {
    let mut operands: Vec<(String, bool)> = Vec::new();
    let mut pattern_seen = search_command_has_no_pattern(command_name, args);
    let mut skip_next = false;
    let mut skip_next_is_operand = false;
    let mut after_options = false;
    for arg in args {
        if skip_next {
            if skip_next_is_operand {
                operands.push((arg.clone(), true));
            }
            skip_next = false;
            skip_next_is_operand = false;
            continue;
        }
        if after_options {
            operands.push((arg.clone(), false));
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if SEARCH_VALUE_OPTIONS.contains(&arg.as_str()) {
            skip_next = true;
            skip_next_is_operand = (["grep", "egrep", "fgrep"].contains(&command_name)
                && arg == "--include")
                || (command_name == "rg" && ["-g", "--glob", "--iglob"].contains(&arg.as_str()));
            if arg == "-e" || arg == "--regexp" || arg == "-f" || arg == "--file" {
                pattern_seen = true;
            }
            continue;
        }
        if let Some((prefix, value)) = arg.split_once('=') {
            if arg.starts_with("--") {
                if ["--include", "--glob", "--iglob"].contains(&prefix) {
                    let is_search_glob = (["grep", "egrep", "fgrep"].contains(&command_name)
                        && prefix == "--include")
                        || (command_name == "rg" && ["--glob", "--iglob"].contains(&prefix));
                    operands.push((value.to_owned(), is_search_glob));
                    continue;
                }
                if arg.starts_with("--regexp=") || arg.starts_with("--file=") {
                    pattern_seen = true;
                }
                continue;
            }
        }
        let option_value_prefixes = ["-A", "-B", "-C", "-m"];
        if option_value_prefixes
            .iter()
            .any(|p| arg.starts_with(p) && arg.len() > p.len())
        {
            continue;
        }
        if command_name == "rg" && arg.starts_with("-g") && arg.len() > 2 {
            operands.push((arg[2..].to_owned(), true));
            continue;
        }
        if arg.starts_with("-e") && arg.len() > 2 {
            pattern_seen = true;
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        if !pattern_seen {
            pattern_seen = true;
            continue;
        }
        operands.push((arg.clone(), false));
    }
    operands
}

/// `_search_command_has_no_pattern` (:415-417).
fn search_command_has_no_pattern(command_name: &str, args: &[String]) -> bool {
    command_name == "rg" && args.iter().any(|a| a == "--files")
}

/// `_search_glob_pattern_is_safe` (:419-445).
#[allow(dead_code)]
fn search_glob_pattern_is_safe(pattern: &str, root: Option<&Path>) -> bool {
    let is_exclusion = pattern.starts_with('!');
    let effective_pattern = if is_exclusion { &pattern[1..] } else { pattern };
    if effective_pattern.is_empty()
        || effective_pattern.len() > 4096
        || effective_pattern.contains('\n')
        || effective_pattern.contains('\x00')
        || effective_pattern
            .chars()
            .any(|c| matches!(c, '{') || effective_pattern.contains("**") || c == '!')
        || Path::new(effective_pattern).is_absolute()
        || Path::new(effective_pattern).components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return false;
    }
    let _ = root;
    if is_exclusion {
        return true;
    }
    for component in Path::new(effective_pattern).components() {
        let std::path::Component::Normal(raw) = component else {
            return false;
        };
        let folded = raw.to_string_lossy().to_lowercase();
        if folded.starts_with('.') && !SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&folded.as_str())
        {
            return false;
        }
        for sensitive in SOURCE_INSPECTION_SENSITIVE_PARTS {
            let sensitive_folded = sensitive.to_lowercase();
            if fnmatchcase(&sensitive_folded, &folded)
                || fnmatchcase(
                    &format!("{sensitive_folded}.guard-sensitive-probe"),
                    &folded,
                )
            {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// constants_core.py + pytest_config_safety.py + interpreter_observers.py
// slices.
// ---------------------------------------------------------------------------

const SAFE_PYTHON_MODULE_COMMANDS: &[&str] = &["pytest", "ruff"];
const PYTHON_INTERPRETER_OPTIONS_WITH_VALUES: &[&str] = &["--check-hash-based-pycs", "-W", "-X"];

fn safe_python_module_shadow_paths(module_root: &str) -> &'static [&'static str] {
    match module_root {
        "pytest" => &[
            "pytest.py",
            "pytest.pyc",
            "pytest/__init__.py",
            "pytest/__init__.pyc",
            "pytest/__main__.py",
            "pytest/__main__.pyc",
        ],
        "ruff" => &[
            "ruff.py",
            "ruff.pyc",
            "ruff/__init__.py",
            "ruff/__init__.pyc",
            "ruff/__main__.py",
            "ruff/__main__.pyc",
        ],
        _ => &[],
    }
}

/// `_python_module_root_from_args` (:29-51 pytest_config_safety).
fn python_module_root_from_args(args: &[String]) -> Option<String> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return None;
        }
        if arg == "-c"
            || arg == "--command"
            || arg.starts_with("-c")
            || arg.starts_with("--command=")
        {
            return None;
        }
        if arg == "-m" {
            let module = args.get(index + 1).cloned().unwrap_or_default();
            return Some(module.split('.').next().unwrap_or("").to_owned())
                .filter(|s| !s.is_empty());
        }
        if arg.starts_with("-m") && arg.len() > 2 {
            return arg[2..]
                .split('.')
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
            .iter()
            .any(|option| arg.starts_with(option) && arg.len() > option.len())
        {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return None;
        }
        index += 1;
    }
    None
}

/// `_pytest_local_entry_point_metadata_exists` (:348-356 interpreter_observers).
fn pytest_local_entry_point_metadata_exists(cwd: &Path) -> bool {
    match std::fs::read_dir(cwd) {
        Ok(entries) => entries.flatten().any(|child| {
            let name = child.file_name().to_string_lossy().into_owned();
            child.path().is_dir()
                && (name.ends_with(".dist-info") || name.ends_with(".egg-info"))
                && child.path().join("entry_points.txt").exists()
        }),
        Err(_) => true,
    }
}

/// `_python_module_may_be_shadowed` (:327-345 interpreter_observers).
fn python_module_may_be_shadowed(module_root: &str, cwd: Option<&Path>) -> bool {
    let Some(cwd) = cwd else { return true };
    python_module_may_be_shadowed_in_search_roots(module_root, &[cwd.to_path_buf()])
}

/// `_python_module_may_be_shadowed_in_search_roots` (:331-345).
fn python_module_may_be_shadowed_in_search_roots(
    module_root: &str,
    search_roots: &[PathBuf],
) -> bool {
    let shadow_paths = safe_python_module_shadow_paths(module_root);
    if shadow_paths.is_empty() {
        return true;
    }
    for search_root in search_roots {
        if module_root == "pytest" && pytest_local_entry_point_metadata_exists(search_root) {
            return true;
        }
        for shadow_path in shadow_paths {
            if search_root.join(shadow_path).exists() {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// _shell_secret_read_support.py public surface (:78-486).
// ---------------------------------------------------------------------------

/// `"." if token == "." else Path(token).name.lower()` (shared helper).
pub(crate) fn command_name_for(token: &str) -> String {
    if token == "." {
        ".".to_owned()
    } else {
        basename_lower(token)
    }
}

pub(crate) fn basename_lower(value: &str) -> String {
    Path::new(value)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// `_command_may_need_read_assessment` (:78-125).
pub(crate) fn command_may_need_read_assessment(
    command_text: &str,
    cwd: Option<&Path>,
    cwd_shadow: bool,
) -> bool {
    let tokens = match split_shell_tokens(command_text) {
        Ok(t) => t,
        Err(_) => return true,
    };
    let interesting: Vec<&str> = {
        let mut v: Vec<&str> = Vec::new();
        v.extend(SHELLS);
        v.extend(OTHER_READERS);
        v.extend([
            "cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "read", "command",
            "exec", "node", "bun", "ruby", "perl",
        ]);
        v
    };
    for token in &tokens {
        if token.contains('<') {
            return true;
        }
        let normalized = token.trim();
        if normalized.is_empty() {
            continue;
        }
        let name = if normalized == "." {
            ".".to_owned()
        } else {
            basename_lower(normalized)
        };
        if interesting.contains(&name.as_str()) || python_executable(&name) {
            return true;
        }
        if unresolved_local_script_launch(normalized) {
            return true;
        }
        if cwd_shadow && cwd_shadowed_executable(normalized, cwd) {
            return true;
        }
    }
    false
}

/// `_sensitive_path` (:128-145).
pub(crate) fn sensitive_path(
    value: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<String> {
    if let Some(m) = classify_secret_path(value, cwd, home_dir) {
        return Some(m.path);
    }
    let lexical = PathBuf::from(normalize_path(&expand_home(value, home_dir), cwd));
    let roots: Vec<&Path> = [cwd, home_dir].into_iter().flatten().collect();
    if !lexical.is_absolute() || !roots.iter().any(|r| path_is_relative_to(&lexical, r)) {
        return None;
    }
    let resolved = match lexical.canonicalize() {
        Ok(r) => r,
        Err(_) => return None,
    };
    classify_secret_path(&resolved.to_string_lossy(), cwd, home_dir).map(|m| m.path)
}

/// `_unwrap_execution_builtin` (:148-198). `(argv0, args, ambiguous)`.
pub(crate) fn unwrap_execution_builtin(
    executable: &str,
    args: &[String],
) -> (Option<String>, Vec<String>, bool) {
    let name = basename_lower(executable);
    if name == "command" {
        let mut index = 0;
        let mut lookup_only = false;
        while index < args.len() {
            let arg = &args[index];
            if arg == "--" {
                index += 1;
                break;
            }
            if let Some(flags) = arg.strip_prefix('-') {
                if flags.is_empty() || flags.chars().any(|f| !"pVv".contains(f)) {
                    return (None, Vec::new(), true);
                }
                lookup_only = lookup_only || flags.contains('v') || flags.contains('V');
                index += 1;
                continue;
            }
            break;
        }
        if lookup_only {
            return (None, Vec::new(), false);
        }
        if index >= args.len() {
            return (None, Vec::new(), false);
        }
        return (Some(args[index].clone()), args[index + 1..].to_vec(), false);
    }
    if name == "exec" {
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if arg == "--" {
                index += 1;
                break;
            }
            if arg == "-a" {
                if index + 1 >= args.len() {
                    return (None, Vec::new(), true);
                }
                index += 2;
                continue;
            }
            if arg == "-c" || arg == "-l" {
                index += 1;
                continue;
            }
            if arg.starts_with('-') {
                return (None, Vec::new(), true);
            }
            break;
        }
        if index >= args.len() {
            return (None, Vec::new(), true);
        }
        return (Some(args[index].clone()), args[index + 1..].to_vec(), false);
    }
    (Some(executable.to_owned()), args.to_vec(), false)
}

/// `_direct_secret_read_paths_from_tokens` (:200-233). Recovers direct
/// reader operands when the full command exceeds parser bounds.
pub(crate) fn direct_secret_read_paths_from_tokens(
    tokens: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let (executable, args, ambiguous) = unwrap_execution_builtin(&tokens[0], &tokens[1..]);
    if ambiguous {
        return Vec::new();
    }
    let Some(executable) = executable else {
        return Vec::new();
    };
    let name = if executable == "." {
        ".".to_owned()
    } else {
        basename_lower(&executable)
    };
    let args_list: Vec<String> = args.to_vec();
    let mut candidates = shell_segment_file_operand_tokens(
        &std::iter::once(name.clone())
            .chain(args_list.iter().cloned())
            .collect::<Vec<String>>(),
    );
    if OTHER_READERS.contains(&name.as_str()) {
        candidates.extend(args_list.iter().filter(|a| !a.starts_with('-')).cloned());
    }
    if name == "source" || name == "." {
        candidates.extend(args_list.iter().take(1).cloned());
    }
    for index in 0..args_list.len().saturating_sub(1) {
        let token = &args_list[index];
        if redirect_operand_re().is_match(token) {
            candidates.push(args_list[index + 1].clone());
        }
    }
    for token in &args_list {
        if let Some(m) = redirect_embedded_re().captures(token) {
            // emulate the Python (?!<) lookahead: reject `<<` embedded forms.
            let captured = &m[1];
            if !captured.starts_with('<') {
                candidates.push(captured.to_owned());
            }
        }
    }
    let mut deduped: Vec<String> = Vec::new();
    for value in candidates {
        if let Some(path) = sensitive_path(&value, cwd, home_dir) {
            if !deduped.contains(&path) {
                deduped.push(path);
            }
        }
    }
    deduped
}

fn redirect_operand_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d*<>|^\d*<$").expect("redirect operand"))
}

fn redirect_embedded_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\d*<(.+)$").expect("redirect embedded"))
}

/// `direct_secret_read_paths` (:236-274).
pub(crate) fn direct_secret_read_paths(
    command: &CanonicalCommand,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    for segment in &command.segments {
        let (executable, args, ambiguous) = unwrap_execution_builtin(
            segment.executable.as_deref().unwrap_or(""),
            &segment.arguments,
        );
        if ambiguous || executable.is_none() {
            continue;
        }
        let executable = executable.unwrap();
        let name = if executable == "." {
            ".".to_owned()
        } else {
            basename_lower(&executable)
        };
        let mut argv: Vec<String> = vec![name.clone()];
        argv.extend(args.iter().cloned());
        candidates.extend(shell_segment_file_operand_tokens(&argv));
        if OTHER_READERS.contains(&name.as_str()) {
            candidates.extend(args.iter().filter(|a| !a.starts_with('-')).cloned());
        }
        if name == "source" || name == "." {
            candidates.extend(args.iter().take(1).cloned());
        }
        if ["node", "bun", "ruby", "perl"].contains(&name.as_str()) || python_executable(&name) {
            // `args_list[:-1]` — the scan needs a following operand or `=`.
            let last = args.len().saturating_sub(1);
            for index in 0..last {
                let arg = &args[index];
                if ["-c", "-e", "--eval", "-p", "--print"].contains(&arg.as_str()) {
                    candidates.extend(literal_read_paths(&args[index + 1]));
                } else if arg.starts_with("--eval=") || arg.starts_with("--print=") {
                    candidates.extend(literal_read_paths(
                        arg.split_once('=').map(|x| x.1).unwrap_or(""),
                    ));
                }
            }
            // `--eval=`/`--print=` on the final arg are missed by `[:-1]`? No —
            // Python slices `args_list[:-1]`, so the last arg is genuinely skipped.
        }
    }
    for redirect in &command.redirects {
        if ["<", "<>"].contains(
            &redirect
                .operator
                .trim_start_matches(|c: char| c.is_ascii_digit()),
        ) {
            candidates.push(redirect.target.clone());
        }
    }
    let mut out: Vec<String> = Vec::new();
    for value in candidates {
        if let Some(path) = sensitive_path(&value, cwd, home_dir) {
            if !out.contains(&path) {
                out.push(path);
            }
        }
    }
    out
}

/// `_shell_command_string` (:277-305). `(script, requested)`.
pub(crate) fn shell_command_string(executable: &str, args: &[String]) -> (Option<String>, bool) {
    let name = if executable == "." {
        ".".to_owned()
    } else {
        basename_lower(executable)
    };
    if !SHELLS.contains(&name.as_str()) {
        return (None, false);
    }
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return (None, false);
        }
        if arg == "--command" {
            return (args.get(index + 1).cloned(), true);
        }
        if let Some(value) = arg.strip_prefix("--command=") {
            return (Some(value.to_owned()), true);
        }
        if arg == "-s" {
            return (None, false);
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c') {
            let mut parts = vec![executable.to_owned()];
            parts.extend(args.iter().cloned());
            let parsed = shell_interpreter_command_payload(&parts, 0);
            return (parsed.map(|p| p.script_text), true);
        }
        if ["-o", "-O", "+o", "+O", "--rcfile", "--init-file"].contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if !arg.starts_with('-') && !arg.starts_with('+') {
            return (None, false);
        }
        index += 1;
    }
    (None, false)
}

/// `_script_operand` (:308-356). `(operand, is_shell)`.
///
/// Mirrors the retired Python exactly: an option scan that stops at `--`
/// (the operand after it is still the script), the Python value-taking
/// options, a `bun <script>` launch, and a path-qualified script executable.
pub(crate) fn script_operand(executable: &str, args: &[String]) -> Option<(String, bool)> {
    let name = if executable == "." {
        ".".to_owned()
    } else {
        basename_lower(executable)
    };
    let is_shell = SHELLS.contains(&name.as_str());
    let is_python = python_executable(&name);
    let is_interpreter = ["node", "ruby", "perl"].contains(&name.as_str()) || is_python;
    if is_shell || is_interpreter {
        let mut index = 0;
        while index < args.len() {
            let arg = args[index].as_str();
            if ["-c", "-e", "--eval", "-m", "--command"].contains(&arg)
                || (is_shell && arg == "-s")
                || (is_shell
                    && arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..].contains('c'))
            {
                return None;
            }
            if arg == "--" {
                index += 1;
                break;
            }
            if ["-o", "-O", "+o", "+O", "--rcfile", "--init-file"].contains(&arg) {
                index += 2;
                continue;
            }
            if is_interpreter && is_python {
                if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg) {
                    if index + 1 >= args.len() {
                        return None;
                    }
                    index += 2;
                    continue;
                }
                if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
                    .iter()
                    .any(|option| arg.starts_with(option) && arg.len() > option.len())
                {
                    index += 1;
                    continue;
                }
            }
            if !arg.starts_with('-') && !arg.starts_with('+') {
                break;
            }
            index += 1;
        }
        if index < args.len() && args[index] != "-" {
            let operand = &args[index];
            if is_shell || is_python || script_like_operand(operand) {
                return Some((operand.clone(), is_shell));
            }
            return None;
        }
    }
    if name == "bun" && args.first().is_some_and(|arg| ends_with_script_suffix(arg)) {
        return Some((args[0].clone(), false));
    }
    if ends_with_script_suffix(executable)
        && (executable.contains('/') || executable.starts_with('.'))
    {
        let is_shell_script = [".sh", ".bash", ".zsh", ".ksh", ".fish"]
            .iter()
            .any(|suffix| executable.ends_with(suffix));
        return Some((executable.to_owned(), is_shell_script));
    }
    None
}

/// Case-sensitive `str.endswith(_SCRIPT_SUFFIXES)`.
fn ends_with_script_suffix(value: &str) -> bool {
    SCRIPT_SUFFIXES.iter().any(|suffix| value.ends_with(suffix))
}

/// `_known_python_module_launch` (:359-370).
pub(crate) fn known_python_module_launch(
    executable: &str,
    args: &[String],
    cwd: Option<&Path>,
) -> bool {
    let name = basename_lower(executable);
    if !python_executable(&name) {
        return false;
    }
    let module_root = python_module_root_from_args(args);
    match module_root {
        Some(root) => {
            SAFE_PYTHON_MODULE_COMMANDS.contains(&root.as_str())
                && !python_module_may_be_shadowed(&root, cwd)
        }
        None => false,
    }
}

/// `_python_module_launch` (:373-401).
pub(crate) fn python_module_launch(executable: &str, args: &[String], cwd: Option<&Path>) -> bool {
    let name = basename_lower(executable);
    if !python_executable(&name) {
        return false;
    }
    if known_python_module_launch(executable, args, cwd) {
        return false;
    }
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            return false;
        }
        if arg == "-m" || (arg.starts_with("-m") && arg.len() > 2) {
            return true;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES.contains(&arg.as_str()) {
            if index + 1 >= args.len() {
                return false;
            }
            index += 2;
            continue;
        }
        if PYTHON_INTERPRETER_OPTIONS_WITH_VALUES
            .iter()
            .any(|option| arg.starts_with(option) && arg.len() > option.len())
        {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

/// `_interpreter_stdin_launch` (:404-413).
pub(crate) fn interpreter_stdin_launch(executable: &str, args: &[String]) -> bool {
    let name = basename_lower(executable);
    if !["node", "bun", "ruby", "perl"].contains(&name.as_str()) && !python_executable(&name) {
        return false;
    }
    let inline_flags = ["-c", "-e", "--eval", "-p", "--print"];
    if args.iter().any(|a| {
        inline_flags.contains(&a.as_str()) || a.starts_with("--eval=") || a.starts_with("--print=")
    }) {
        return false;
    }
    args.iter().any(|a| a == "-")
}

/// `_interpreter_inline_launch` (:416-429).
pub(crate) fn interpreter_inline_launch(executable: &str, args: &[String]) -> bool {
    let name = basename_lower(executable);
    if !["node", "bun", "ruby", "perl"].contains(&name.as_str()) && !python_executable(&name) {
        return false;
    }
    for arg in args {
        if arg == "--" {
            return false;
        }
        if ["-c", "-e", "--eval", "-p", "--print"].contains(&arg.as_str())
            || arg.starts_with("--eval=")
            || arg.starts_with("--print=")
        {
            return true;
        }
        if !arg.starts_with('-') {
            return false;
        }
    }
    false
}

/// `_path_qualified` (:432-434).
pub(crate) fn path_qualified(executable: &str) -> bool {
    !executable.is_empty()
        && (executable.contains('/') || executable.contains('\\') || executable.starts_with('.'))
}

/// `_script_like_operand` (:436-443).
fn script_like_operand(operand: &str) -> bool {
    if operand.is_empty() || operand == "-" {
        return false;
    }
    if operand.to_lowercase().ends_with_any(SCRIPT_SUFFIXES) {
        return true;
    }
    unresolved_local_script_launch(operand)
}

/// `_unresolved_local_script_launch` (:446-458).
pub(crate) fn unresolved_local_script_launch(executable: &str) -> bool {
    if executable.is_empty() {
        return false;
    }
    if executable.starts_with("./")
        || executable.starts_with("../")
        || executable.starts_with(".\\")
        || executable.starts_with("..\\")
    {
        return true;
    }
    if !(executable.contains('/') || executable.contains('\\')) {
        return false;
    }
    if !executable.starts_with('/') {
        return true;
    }
    executable.to_lowercase().ends_with_any(SCRIPT_SUFFIXES)
}

trait EndsWithAny {
    fn ends_with_any(&self, suffixes: &[&str]) -> bool;
}
impl EndsWithAny for String {
    fn ends_with_any(&self, suffixes: &[&str]) -> bool {
        suffixes.iter().any(|s| self.ends_with(s))
    }
}

/// `_cwd_shadowed_executable` (:461-469).
pub(crate) fn cwd_shadowed_executable(executable: &str, cwd: Option<&Path>) -> bool {
    let Some(cwd) = cwd else { return false };
    if executable.is_empty() || path_qualified(executable) {
        return false;
    }
    cwd.join(executable).is_file()
}

/// `_local_executable_operand` (:472-486).
pub(crate) fn local_executable_operand(
    executable: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    roots: &[PathBuf],
) -> Option<String> {
    if !path_qualified(executable) {
        return None;
    }
    let lexical = PathBuf::from(normalize_path(&expand_home(executable, home_dir), cwd));
    if !lexical.is_absolute() || !roots.iter().any(|r| path_is_relative_to(&lexical, r)) {
        return None;
    }
    Some(executable.to_owned())
}

/// `_SHORT_CIRCUITING_CD_FAILURES` (:54-60).
pub(crate) fn short_circuiting_cd_failures() -> &'static [&'static str] {
    SHORT_CIRCUITING_CD_FAILURES
}

#[cfg(test)]
mod launch_parity_tests {
    use super::*;

    #[test]
    fn unresolved_local_script_launch_matches_python_oracle() {
        for (executable, expected) in [
            ("", false),
            ("./run", true),
            ("../run", true),
            (".\\run", true),
            ("bin/run", true),
            ("/usr/bin/stripe.exe", false),
            ("/opt/tool/run.sh", true),
            ("/opt/tool/RUN.PY", true),
            ("git", false),
            ("deploy.sh", false),
        ] {
            assert_eq!(
                unresolved_local_script_launch(executable),
                expected,
                "{executable}"
            );
        }
    }

    #[test]
    fn literal_read_paths_capture_quoted_reads() {
        let source = "print(open(\".env\").read()); Path('a/b').read_text()";
        assert_eq!(literal_read_paths(source), vec![".env", "a/b"]);
    }

    #[test]
    fn literal_read_scan_error_fails_closed() {
        use fancy_regex::{Error, RuntimeError};
        let mut out = Vec::new();
        collect_literal_reads(
            vec![
                Ok(Some("a/b".to_owned())),
                Err(Error::RuntimeError(RuntimeError::BacktrackLimitExceeded)),
                Ok(Some("c".to_owned())),
            ]
            .into_iter(),
            &mut out,
        );
        assert_eq!(out, vec!["a/b", FAIL_CLOSED_SENSITIVE_READ]);
        assert!(classify_secret_path(FAIL_CLOSED_SENSITIVE_READ, None, None).is_some());
    }
}
