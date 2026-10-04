//! Rust port of `runtime/false_positive_rules.py` — false-positive
//! classification rules for Guard runtime detectors.
//!
//! The `classify_*` functions return plain booleans / optional tool names
//! (matching the Python signatures) plus a `SourceSearchClassification`
//! dataclass-equivalent for `classify_source_search_command`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;
use regex::Regex;

use crate::command_launcher_floors::shlex_split;
use crate::home_path_text::expand_home;

const SOURCE_SEARCH_TOOLS: &[&str] = &[
    "rg", "ripgrep", "grep", "egrep", "fgrep", "fd", "find", "ls",
];
const READ_ONLY_INLINE_TOOLS: &[&str] = &["jq", "yq", "awk", "sed"];

pub const SOURCE_INSPECTION_PARTS: &[&str] = &[
    "__tests__",
    "app",
    "constants",
    "dashboard",
    "docs",
    "lib",
    "packages",
    "scripts",
    "src",
    "test",
    "tests",
    "workers",
];
pub const SOURCE_INSPECTION_EXTENSIONS: &[&str] = &[
    ".c", ".cc", ".cpp", ".css", ".go", ".h", ".hpp", ".html", ".java", ".js", ".jsx", ".json",
    ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".ts", ".tsx", ".yaml", ".yml",
];
pub const SOURCE_INSPECTION_SENSITIVE_PARTS: &[&str] = &[
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
pub const SOURCE_INSPECTION_BENIGN_DOTFILES: &[&str] = &[".nvmrc"];
const KNOWN_SKILL_DOC_ROOT_SUFFIXES: &[&str] = &[
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
];
pub const KNOWN_AGENT_DOC_SUFFIXES: &[&str] = &[
    ".codex/docs/harness-engineering.md",
    ".codex/docs/token-discipline.md",
];
const FD_OPTION_VALUE_FLAGS: &[&str] = &[
    "-d",
    "--max-depth",
    "-E",
    "--exclude",
    "-e",
    "--extension",
    "-t",
    "--type",
    "-S",
    "--size",
    "-o",
    "--owner",
    "--changed-before",
    "--changed-within",
    "--changed-after",
    "-j",
    "--threads",
    "--path-separator",
];

#[allow(clippy::invalid_regex)]
static SECRET_FILE_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?<![A-Za-z0-9_.-])(?:\.env(?:\.[A-Za-z0-9_-]+)?|\.npmrc|\.pypirc|\.netrc|\.git-credentials|id_rsa|id_ed25519|id_ecdsa|credentials|wallet\.key|private[_-]?key\.pem|terraform\.tfvars)(?![A-Za-z0-9_.-])",
    )
    .expect("SECRET_FILE_NAMES")
});

static PIPE_TO_EXFIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[|;]\s*(?:curl|wget|nc|ncat|netcat|scp|rsync|aws\s+s3|gsutil|gcloud)\b")
        .expect("PIPE_TO_EXFIL")
});

static FIND_MUTATING_FLAGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s])-(?:delete|exec\s+rm|exec\s+unlink|exec\s+shred|execdir\s+rm)\b|(?:^|[\s])-exec\s+\S+[^\r\n;&|]{0,100}\{.*\}\s*(?:\\;|;|\+)",
    )
    .expect("FIND_MUTATING_FLAGS")
});

static OUTPUT_REDIRECT_TO_EXFIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)>\s*(?:/proc/\S+|/dev/tcp/|/dev/udp/)").expect("OUTPUT_REDIRECT_TO_EXFIL")
});

#[allow(clippy::invalid_regex)]
static SHELL_CHAINING_PATTERN: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(r"&&|\|\||(?<!<);|(?:^|[\s])&(?![&|])(?:[\s]|$)")
        .expect("SHELL_CHAINING_PATTERN")
});

#[allow(clippy::invalid_regex)]
static OUTPUT_REDIRECT_TO_LOCAL_FILE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(r"(?i)(?:^|[\s;&|])(?:\d+)?>>?\s*(?!&?\d\b|/dev/null(?:\s|$))\S+")
        .expect("OUTPUT_REDIRECT_TO_LOCAL_FILE")
});

static CLIPBOARD_PIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[|;]\s*(?:pbcopy|xclip|xsel|wl-copy|clip)\b").expect("CLIPBOARD_PIPE")
});

static LOCALHOST_HEALTH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(?:^|[\s;&|])(?:curl|wget|fetch|http\.get|requests\.get)\b[^\r\n;&|]{0,80}(?:localhost|127\.0\.0\.1|::1|\[::1\]|0\.0\.0\.0)(?::\d{1,5})?(?:/(?:healthz?|readiness|ready|liveness|live|ping|status|metrics|info|version))?(?:\s|$|[;&|'\"])"#,
    )
    .expect("LOCALHOST_HEALTH_PATTERN")
});

static CURL_READ_ONLY_HTTP_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s;&|])(?P<tool>curl|curl\.exe)\b[^\r\n;&|]*https?://")
        .expect("CURL_READ_ONLY_HTTP_FETCH_PATTERN")
});

#[allow(clippy::invalid_regex)]
static WGET_READ_ONLY_HTTP_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?P<tool>wget)\b(?=[^\r\n;&|]*(?<!\S)--spider\b)[^\r\n;&|]*https?://",
    )
    .expect("WGET_READ_ONLY_HTTP_FETCH_PATTERN")
});

static NODE_READ_ONLY_HTTP_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s;&|])(?P<tool>node)\b(?s:.*?)(?:\bfetch\s*\(|\bhttps?\.get\s*\()")
        .expect("NODE_READ_ONLY_HTTP_FETCH_PATTERN")
});

static PYTHON_READ_ONLY_HTTP_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?P<tool>python|python3)\b(?s:.*?)(?:\brequests\.get\s*\(|\burllib\.request\.urlopen\s*\()",
    )
    .expect("PYTHON_READ_ONLY_HTTP_FETCH_PATTERN")
});

fn read_only_http_fetch_patterns() -> [&'static Regex; 4] {
    [
        &CURL_READ_ONLY_HTTP_FETCH_PATTERN,
        &WGET_READ_ONLY_HTTP_FETCH_PATTERN,
        &NODE_READ_ONLY_HTTP_FETCH_PATTERN,
        &PYTHON_READ_ONLY_HTTP_FETCH_PATTERN,
    ]
}

static MUTATING_HTTP_FETCH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:POST|PUT|PATCH|DELETE)\b|\bmethod\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|(?:^|[\s;&|])(?:--request|-X)\s*(?:POST|PUT|PATCH|DELETE)\b|(?:^|[\s;&|])(?:--data(?:-binary|-raw|-urlencode)?(?:[=\s]|$)|-d(?:\S|\s|$)|--form(?:[=\s]|$)|-F(?:\S|\s|$)|--json(?:[=\s]|$)|--upload-file(?:[=\s]|$)|-T(?:\S|\s|$)|--header(?:[=\s]|$)|-H(?:\S|\s|$)|--config(?:[=\s]|$)|-K(?:\S|\s|$)|--cookie(?:[=\s]|$)|-b(?:\S|\s|$))|\b(?:body|data)\s*:"#,
    )
    .expect("MUTATING_HTTP_FETCH_PATTERN")
});

static HTTP_FETCH_FILE_WRITE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|[\s;&|])(?:--output(?:[=\s]|$)|-o(?:\S|\s|$)|--remote-name(?:[=\s]|$)|-[A-Za-z]*O[A-Za-z]*|--output-document(?:[=\s]|$)|--remote-header-name(?:[=\s]|$)|--dump-header(?:[=\s]|$)|-D(?:\S|\s|$)|--trace(?:-ascii|-ids|-time)?(?:[=\s]|$)|--stderr(?:[=\s]|$)|--cookie-jar(?:[=\s]|$)|-c(?:\S|\s|$))",
    )
    .expect("HTTP_FETCH_FILE_WRITE_PATTERN")
});

const CURL_LONG_AUTH_FLAGS: &[&str] = &[
    "--anyauth",
    "--aws-sigv4",
    "--basic",
    "--digest",
    "--negotiate",
    "--netrc",
    "--netrc-file",
    "--netrc-optional",
    "--ntlm",
    "--ntlm-wb",
    "--oauth2-bearer",
    "--proxy-user",
    "--user",
];

static LOCAL_FILE_READ_IN_HTTP_SCRIPT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:readFileSync|open|createReadStream)\s*\(|\bPath\s*\([^)]{0,240}\)\s*\.\s*(?:read_text|read_bytes|open)\s*\(|\bcat\s+",
    )
    .expect("LOCAL_FILE_READ_IN_HTTP_SCRIPT_PATTERN")
});

static LOCAL_FILE_WRITE_IN_HTTP_SCRIPT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:writeFileSync|appendFileSync|createWriteStream)\s*\(|\bPath\s*\([^)]{0,240}\)\s*\.\s*(?:write_text|write_bytes)\s*\(",
    )
    .expect("LOCAL_FILE_WRITE_IN_HTTP_SCRIPT_PATTERN")
});

static PROCESS_EXECUTION_IN_HTTP_SCRIPT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:require\s*\(\s*['\"]child_process['\"]\s*\)\s*\.\s*(?:exec|execFile|execFileSync|execSync|fork|spawn|spawnSync)|child_process\s*\.\s*(?:exec|execFile|execFileSync|execSync|fork|spawn|spawnSync)|subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output)|os\.system)\s*\("#,
    )
    .expect("PROCESS_EXECUTION_IN_HTTP_SCRIPT_PATTERN")
});

static PIPE_TO_LOCAL_FILE_WRITE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[|;]\s*(?:tee|dd)\b").expect("PIPE_TO_LOCAL_FILE_WRITE_PATTERN")
});

static PIPE_SEGMENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\|&?|;)\s*([^\r\n;&|]+)").expect("PIPE_SEGMENT_PATTERN"));

static ENV_ASSIGNMENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").expect("ENV_ASSIGNMENT_PATTERN"));

const EXECUTION_TOOLS: &[&str] = &[
    ".",
    "bash",
    "chmod",
    "cmd",
    "csh",
    "dash",
    "fish",
    "install",
    "ksh",
    "mksh",
    "node",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "ruby",
    "sh",
    "source",
    "tcsh",
    "zsh",
];

const SUDO_ARG_FLAGS: &[&str] = &["-u", "-g", "-h", "-p", "-C", "-T"];
const SUDO_ARG_LONG_FLAGS: &[&str] = &[
    "--chdir",
    "--group",
    "--host",
    "--login-class",
    "--prompt",
    "--role",
    "--type",
    "--user",
];

static FAKE_CREDENTIAL_PATTERN_A: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:your[_-]?api[_-]?key|example[_-]?token|fake[_-]?(?:secret|token|key|credential)|placeholder|<[A-Z_]{2,}(?:[_-][A-Z]+)*>|x{4,}|\b1234(?:5678)?\b|test[_-]?token|dummy[_-]?(?:key|secret|token)|replace[_-]?me|insert[_-]?(?:your|token)|changeme|secret123|password123|\babc123\b|my[_-]?(?:secret|key|token|api[_-]?key)|sample[_-]?(?:key|token|credential))",
    )
    .expect("FAKE_CREDENTIAL_PATTERN_A")
});
static FAKE_CREDENTIAL_PATTERN_B: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:todo|fixme|hack|stub|mock|fake|demo|sample|example)\b.*?(?:key|token|secret|credential)",
    )
    .expect("FAKE_CREDENTIAL_PATTERN_B")
});
fn fake_credential_patterns() -> [&'static Regex; 2] {
    [&FAKE_CREDENTIAL_PATTERN_A, &FAKE_CREDENTIAL_PATTERN_B]
}

static DOCS_EXAMPLE_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:README|CHANGELOG|CONTRIBUTING|SECURITY|LICENSE|NOTICE|\.md|\.rst|\.txt|\.adoc)|(?:example|demo|tutorial|sample|docs?/|documentation/|spec/|test/fixtures?/)",
    )
    .expect("DOCS_EXAMPLE_CONTEXT")
});

#[allow(clippy::invalid_regex)]
static VERSION_FILE_NAMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?<![A-Za-z0-9_.-])(?:\.nvmrc|\.node-version|\.python-version|\.ruby-version|\.tool-versions|\.java-version)(?![A-Za-z0-9_.-])",
    )
    .expect("VERSION_FILE_NAMES")
});

#[allow(clippy::invalid_regex)]
static PACKAGE_METADATA_FILES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?<![A-Za-z0-9_.-])(?:package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|setup\.py|setup\.cfg|pyproject\.toml|Pipfile(?:\.lock)?|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|composer\.json|Gemfile(?:\.lock)?)(?![A-Za-z0-9_.-])",
    )
    .expect("PACKAGE_METADATA_FILES")
});

static HEREDOC_SCRIPT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*(?:node|python|python3)\b[^\r\n]*<<").expect("HEREDOC_SCRIPT_PATTERN")
});
static NEWLINE_COMMAND_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\n\s*\S+").expect("NEWLINE_COMMAND_PATTERN"));
static HEREDOC_DELIMITER_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?"#).expect("HEREDOC_DELIMITER_PATTERN")
});

/// `SourceSearchClassification` (:487-494).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSearchClassification {
    pub is_source_search: bool,
    pub reason: Option<&'static str>,
    pub tool: Option<String>,
}

fn home_text(home_dir: Option<&Path>) -> String {
    home_dir
        .map(|h| h.to_string_lossy().into_owned())
        .or_else(|| std::env::var_os("HOME").map(|h| h.to_string_lossy().into_owned()))
        .unwrap_or_else(|| ".".to_owned())
}

fn normpath_text(value: &str) -> String {
    crate::home_path_text::normalize_path(value, None).replace('\\', "/")
}

fn realpath_text(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| normpath_text(path))
}

fn is_link(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// `target_is_known_skill_doc_path` (:119-183).
pub fn target_is_known_skill_doc_path(target: &str, home_dir: Option<&Path>) -> bool {
    if ["$", "`", "<", ">", "|", ";", "&"]
        .iter()
        .any(|marker| target.contains(marker))
    {
        return false;
    }
    if let Some(rest) = target.strip_prefix("skill://") {
        let skill_name_raw = rest
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_owned();
        if !skill_name_raw.is_empty() {
            let skill_name = normpath_text(&skill_name_raw);
            if skill_name.is_empty()
                || skill_name.starts_with("..")
                || skill_name == "."
                || skill_name.starts_with('/')
            {
                return false;
            }
            let home = normpath_text(&home_text(home_dir));
            for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES {
                let root = format!("{home}/{suffix}");
                let candidate_dir = format!("{root}/{skill_name}");
                let candidate_file = format!("{candidate_dir}/SKILL.md");
                if !Path::new(&candidate_file).is_file() {
                    continue;
                }
                // Skill directories are often symlinks managed by the harness
                // (e.g. ~/.claude/skills/foo -> /project/.agents/skills/foo).
                // Require SKILL.md to exist and not be a symlink escaping its dir.
                let real_candidate = realpath_text(&candidate_dir);
                let real_file = realpath_text(&candidate_file);
                if real_file != real_candidate
                    && !real_file.starts_with(&format!("{real_candidate}/"))
                {
                    continue;
                }
                return true;
            }
        }
        return false;
    }
    let expanded = if target == "~" || target.starts_with("~/") {
        format!("{}{}", home_text(home_dir), &target[1..])
    } else {
        expand_home(target, home_dir)
    };
    let normalized = normpath_text(&expanded);
    let home = normpath_text(&home_text(home_dir));
    for suffix in KNOWN_SKILL_DOC_ROOT_SUFFIXES {
        let root = format!("{home}/{suffix}");
        if normalized != root && !normalized.starts_with(&format!("{root}/")) {
            continue;
        }
        if is_link(&root) {
            continue;
        }
        if !path_has_symlink_component(&normalized, &root) {
            return true;
        }
        let relative = normalized[root.len() + 1..].to_owned();
        let relative_parts: Vec<&str> = relative.split('/').collect();
        if relative_parts.len() != 2 || relative_parts[1] != "SKILL.md" {
            continue;
        }
        let candidate_dir = format!("{root}/{}", relative_parts[0]);
        let candidate_file = format!("{candidate_dir}/SKILL.md");
        if !Path::new(&candidate_file).is_file() {
            continue;
        }
        let real_candidate = realpath_text(&candidate_dir);
        let real_file = realpath_text(&candidate_file);
        if real_file != real_candidate && !real_file.starts_with(&format!("{real_candidate}/")) {
            continue;
        }
        return true;
    }
    false
}

/// `_path_has_symlink_component` (:184-199).
fn path_has_symlink_component(normalized_target: &str, root: &str) -> bool {
    if is_link(root) {
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
        if is_link(&current) {
            return true;
        }
    }
    false
}

/// `fd_arg_requests_exec` (:200-213).
pub fn fd_arg_requests_exec(arg: &str) -> bool {
    if matches!(arg, "-x" | "-X" | "--exec" | "--exec-batch")
        || arg.starts_with("-x")
        || arg.starts_with("-X")
        || arg.starts_with("--exec=")
        || arg.starts_with("--exec-batch=")
    {
        return true;
    }
    if !arg.starts_with('-') || arg.starts_with("--") {
        return false;
    }
    let cluster = &arg[1..];
    for flag in cluster.chars() {
        if matches!(flag, 'd' | 'E' | 'e' | 'j' | 'o' | 'S' | 't') {
            return false;
        }
        if matches!(flag, 'x' | 'X') {
            return true;
        }
    }
    false
}

/// `fd_args_follow_symlinks` (:214-236).
pub fn fd_args_follow_symlinks(args: &[String]) -> bool {
    let mut after_options = false;
    for arg in args {
        if after_options {
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg == "--follow" {
            return true;
        }
        if arg.starts_with("--") {
            continue;
        }
        if !arg.starts_with('-') || arg == "-" {
            continue;
        }
        let cluster = &arg[1..];
        for flag in cluster.chars() {
            if matches!(
                flag,
                'c' | 'd' | 'E' | 'e' | 'j' | 'o' | 'S' | 't' | 'x' | 'X'
            ) {
                break;
            }
            if flag == 'L' {
                return true;
            }
        }
    }
    false
}

/// `split_fd_args_and_exec` (:237-261). `None` mirrors Python's `None`.
pub fn split_fd_args_and_exec(args: &[String]) -> Option<(Vec<String>, Vec<String>)> {
    for (index, arg) in args.iter().enumerate() {
        if arg == "-X"
            || arg.starts_with("-X")
            || arg == "--exec-batch"
            || arg.starts_with("--exec=")
            || arg.starts_with("--exec-batch=")
        {
            return None;
        }
        if arg == "-x" || arg == "--exec" {
            return Some((args[..index].to_vec(), args[index + 1..].to_vec()));
        }
        if let Some(exec_token) = arg.strip_prefix("-x") {
            let exec_token = exec_token.to_owned();
            if exec_token.is_empty() {
                return None;
            }
            let mut exec_parts = vec![exec_token];
            exec_parts.extend(args[index + 1..].iter().cloned());
            return Some((args[..index].to_vec(), exec_parts));
        }
        if arg.starts_with('-') && !arg.starts_with("--") {
            let cluster: Vec<char> = arg[1..].chars().collect();
            for (flag_index, flag) in cluster.iter().enumerate() {
                if matches!(flag, 'd' | 'E' | 'e' | 'j' | 'o' | 'S' | 't') {
                    break;
                }
                if *flag == 'X' {
                    return None;
                }
                if *flag == 'x' {
                    let exec_token: String = cluster[flag_index + 1..].iter().collect();
                    let mut exec_parts: Vec<String> = Vec::new();
                    if !exec_token.is_empty() {
                        exec_parts.push(exec_token);
                    }
                    exec_parts.extend(args[index + 1..].iter().cloned());
                    return Some((args[..index].to_vec(), exec_parts));
                }
            }
        }
    }
    None
}

/// `fd_exec_token_is_plain_sed` (:262-266).
pub fn fd_exec_token_is_plain_sed(token: &str) -> bool {
    let shell_markers = ['/', '\\', ';', '&', '|', '<', '>', '`', '$'];
    Path::new(token).file_name().and_then(|n| n.to_str()) == Some("sed")
        && !token.chars().any(|c| shell_markers.contains(&c))
}

/// `fd_search_targets` (:267-300). `None` mirrors Python's `None`; `Some(vec![])`
/// mirrors the empty tuple `()`.
pub fn fd_search_targets(args: &[String]) -> Option<Vec<String>> {
    let parsed = split_fd_args_and_exec(args);
    let fd_args: &[String] = match &parsed {
        Some((fd_args, _)) => fd_args,
        None => args,
    };
    let mut positional: Vec<String> = Vec::new();
    let mut search_paths: Vec<String> = Vec::new();
    let mut skip_next = false;
    for (index, arg) in fd_args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--base-directory" || arg.starts_with("--base-directory=") {
            return None;
        }
        if arg == "--search-path" {
            if index + 1 >= fd_args.len() {
                return None;
            }
            search_paths.push(fd_args[index + 1].clone());
            skip_next = true;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--search-path=") {
            search_paths.push(value.to_owned());
            continue;
        }
        if FD_OPTION_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        if FD_OPTION_VALUE_FLAGS
            .iter()
            .filter(|flag| flag.starts_with("--"))
            .any(|flag| arg.starts_with(&format!("{flag}=")))
        {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        positional.push(arg.clone());
    }
    if !search_paths.is_empty() {
        return Some(search_paths);
    }
    if positional.len() >= 2 {
        return Some(positional[1..].to_vec());
    }
    Some(Vec::new())
}

/// `classify_source_search_command` (:497-565).
pub fn classify_source_search_command(command: &str) -> SourceSearchClassification {
    let stripped = command.trim();
    if stripped.is_empty() {
        return SourceSearchClassification {
            is_source_search: false,
            reason: None,
            tool: None,
        };
    }
    let parts: Vec<String> = stripped.split_whitespace().map(str::to_owned).collect();
    if parts.is_empty() {
        return SourceSearchClassification {
            is_source_search: false,
            reason: None,
            tool: None,
        };
    }
    let tool = match leading_tool(&parts) {
        Some(t) => t,
        None => {
            return SourceSearchClassification {
                is_source_search: false,
                reason: None,
                tool: None,
            }
        }
    };
    if PIPE_TO_EXFIL.is_match(command) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("piped to network tool"),
            tool: Some(tool.clone()),
        };
    }
    if OUTPUT_REDIRECT_TO_EXFIL.is_match(command) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("output redirected to device/proc"),
            tool: Some(tool.clone()),
        };
    }
    if CLIPBOARD_PIPE.is_match(command) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("piped to clipboard"),
            tool: Some(tool.clone()),
        };
    }
    if SECRET_FILE_NAMES.is_match(command) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("targets secret file"),
            tool: Some(tool.clone()),
        };
    }
    if tool == "find" && FIND_MUTATING_FLAGS.is_match(command) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("find with mutating action flag"),
            tool: Some(tool.clone()),
        };
    }
    if tool == "fd" && fd_args_follow_symlinks(&parts[1..]) {
        return SourceSearchClassification {
            is_source_search: false,
            reason: Some("fd follows symlinks"),
            tool: Some(tool.clone()),
        };
    }
    SourceSearchClassification {
        is_source_search: true,
        reason: Some("read-only code/filesystem search"),
        tool: Some(tool),
    }
}

/// `classify_fake_credential_pattern` (:566-570).
pub fn classify_fake_credential_pattern(text: &str) -> bool {
    fake_credential_patterns()
        .iter()
        .any(|pattern| pattern.is_match(text))
}

/// `classify_health_endpoint_fetch` (:571-575).
pub fn classify_health_endpoint_fetch(command: &str) -> bool {
    LOCALHOST_HEALTH_PATTERN.is_match(command)
}

/// `classify_read_only_http_fetch` (:576-618).
pub fn classify_read_only_http_fetch(command: &str) -> Option<&'static str> {
    let mut tool: Option<String> = None;
    for pattern in read_only_http_fetch_patterns() {
        if let Some(m) = pattern.captures(command) {
            if let Some(g) = m.name("tool") {
                tool = Some(g.as_str().to_lowercase());
                break;
            }
        }
    }
    let tool = tool?;
    if MUTATING_HTTP_FETCH_PATTERN.is_match(command) {
        return None;
    }
    if has_shell_chaining(command) {
        return None;
    }
    if HTTP_FETCH_FILE_WRITE_PATTERN.is_match(command) {
        return None;
    }
    if matches!(tool.as_str(), "curl.exe" | "curl") && curl_http_fetch_uses_auth(command) {
        return None;
    }
    if PIPE_TO_EXFIL.is_match(command) {
        return None;
    }
    if pipes_to_execution(command) {
        return None;
    }
    if OUTPUT_REDIRECT_TO_EXFIL.is_match(command) {
        return None;
    }
    if OUTPUT_REDIRECT_TO_LOCAL_FILE
        .is_match(command)
        .unwrap_or(false)
    {
        return None;
    }
    if SECRET_FILE_NAMES.is_match(command) {
        return None;
    }
    if LOCAL_FILE_READ_IN_HTTP_SCRIPT_PATTERN.is_match(command) {
        return None;
    }
    if LOCAL_FILE_WRITE_IN_HTTP_SCRIPT_PATTERN.is_match(command) {
        return None;
    }
    if PROCESS_EXECUTION_IN_HTTP_SCRIPT_PATTERN.is_match(command) {
        return None;
    }
    if PIPE_TO_LOCAL_FILE_WRITE_PATTERN.is_match(command) {
        return None;
    }
    if matches!(tool.as_str(), "curl.exe" | "curl") {
        return Some("curl");
    }
    if matches!(tool.as_str(), "python3" | "python") {
        return Some("python");
    }
    match tool.as_str() {
        "wget" => Some("wget"),
        "node" => Some("node"),
        _ => None,
    }
}

/// `_curl_http_fetch_uses_auth` (:619-645).
fn curl_http_fetch_uses_auth(command: &str) -> bool {
    let tokens = shlex_split(command)
        .unwrap_or_else(|_| command.split_whitespace().map(str::to_owned).collect());
    let mut saw_curl = false;
    for token in &tokens {
        let base = strip_path_prefix(token).to_lowercase();
        if !saw_curl {
            if base == "curl" || base == "curl.exe" {
                saw_curl = true;
            }
            continue;
        }
        if token == "--" {
            break;
        }
        let lower = token.to_lowercase();
        if CURL_LONG_AUTH_FLAGS.contains(&lower.as_str()) {
            return true;
        }
        if CURL_LONG_AUTH_FLAGS
            .iter()
            .any(|flag| lower.starts_with(&format!("{flag}=")))
        {
            return true;
        }
        if token.starts_with('-') && !token.starts_with("--") {
            let cluster = &token[1..];
            if cluster.contains('u') || cluster.contains('U') || cluster.contains('n') {
                return true;
            }
        }
    }
    false
}

/// `classify_docs_example_source` (:646-650).
pub fn classify_docs_example_source(source_hint: &str) -> bool {
    DOCS_EXAMPLE_CONTEXT.is_match(source_hint)
}

/// `classify_version_file_access` (:651-657).
pub fn classify_version_file_access(paths: &[String]) -> bool {
    if paths.is_empty() {
        return false;
    }
    paths.iter().all(|p| VERSION_FILE_NAMES.is_match(p))
}

/// `classify_package_metadata_access` (:658-664).
pub fn classify_package_metadata_access(paths: &[String]) -> bool {
    if paths.is_empty() {
        return false;
    }
    paths.iter().all(|p| PACKAGE_METADATA_FILES.is_match(p))
}

/// `_leading_tool` (:665-676).
fn leading_tool(parts: &[String]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    let base = strip_path_prefix(&parts[0]).to_lowercase();
    if SOURCE_SEARCH_TOOLS.contains(&base.as_str()) {
        return Some(base);
    }
    if READ_ONLY_INLINE_TOOLS.contains(&base.as_str()) && has_no_write_flags(parts) {
        return Some(base);
    }
    None
}

/// `_strip_path_prefix` (:677-680).
fn strip_path_prefix(token: &str) -> &str {
    token
        .rsplit('/')
        .next()
        .unwrap_or(token)
        .rsplit('\\')
        .next()
        .unwrap_or(token)
}

/// `_pipes_to_execution` (:681-694).
fn pipes_to_execution(command: &str) -> bool {
    for m in PIPE_SEGMENT_PATTERN.captures_iter(command) {
        let segment = m.get(1).map(|g| g.as_str()).unwrap_or("").trim().to_owned();
        if segment.is_empty() {
            continue;
        }
        let tokens = shlex_split(&segment)
            .unwrap_or_else(|_| segment.split_whitespace().map(str::to_owned).collect());
        if tokens_start_execution(&tokens) {
            return true;
        }
    }
    false
}

/// `_tokens_start_execution` (:695-727).
fn tokens_start_execution(tokens: &[String]) -> bool {
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let base = strip_path_prefix(token);
        let base_lower = base.to_lowercase();
        if base_lower == "sudo" || base_lower == "doas" {
            index += 1;
            while index < tokens.len() && tokens[index].starts_with('-') {
                let flag = &tokens[index];
                index += 1;
                if flag == "--" {
                    break;
                }
                if (SUDO_ARG_FLAGS.contains(&flag.as_str())
                    || SUDO_ARG_LONG_FLAGS.contains(&flag.as_str()))
                    && index < tokens.len()
                {
                    index += 1;
                }
            }
            continue;
        }
        if base_lower == "command" {
            index += 1;
            continue;
        }
        if base_lower == "env" {
            index += 1;
            while index < tokens.len() && tokens[index].starts_with('-') {
                index += 1;
            }
            continue;
        }
        if ENV_ASSIGNMENT_PATTERN.is_match(token) {
            index += 1;
            continue;
        }
        if base == "NODE" && tokens.len() == 1 {
            return false;
        }
        return EXECUTION_TOOLS.contains(&base_lower.as_str());
    }
    false
}

/// `_looks_like_heredoc_script` (:728-731).
fn looks_like_heredoc_script(command: &str) -> bool {
    HEREDOC_SCRIPT_PATTERN.is_match(command)
}

/// `_has_shell_chaining` (:732-737).
fn has_shell_chaining(command: &str) -> bool {
    if looks_like_heredoc_script(command) {
        return has_heredoc_follow_on_command(command);
    }
    SHELL_CHAINING_PATTERN.is_match(command).unwrap_or(false)
        || NEWLINE_COMMAND_PATTERN.is_match(command)
}

/// `_has_heredoc_follow_on_command` (:738-752).
fn has_heredoc_follow_on_command(command: &str) -> bool {
    let first_line = command.lines().next().unwrap_or("");
    if SHELL_CHAINING_PATTERN.is_match(first_line).unwrap_or(false) {
        return true;
    }
    let delimiter = match HEREDOC_DELIMITER_PATTERN.captures(first_line) {
        Some(c) => c.get(1).map(|g| g.as_str()).unwrap_or("").to_owned(),
        None => return true,
    };
    let lines: Vec<&str> = command.lines().skip(1).collect();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == delimiter {
            return lines[index + 1..]
                .iter()
                .any(|rest| !rest.trim().is_empty());
        }
    }
    true
}

/// `_has_no_write_flags` (:753-766).
fn has_no_write_flags(parts: &[String]) -> bool {
    let write_flags: HashSet<&str> = ["--in-place", "-w", "--write"].into_iter().collect();
    for p in &parts[1..] {
        let tok = p.split('=').next().unwrap_or("");
        if write_flags.contains(tok) {
            return false;
        }
        let bytes = tok.as_bytes();
        if bytes.len() >= 2 && bytes[0] == b'-' && bytes[1] != b'-' && tok[1..].contains('i') {
            return false;
        }
    }
    true
}
