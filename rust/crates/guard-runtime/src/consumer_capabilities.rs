//! Capability normalization and delta scoring for the consumer projection op.
//!
//! The artifact's declared capabilities are reduced to stable typed fields
//! (network hosts and schemes, filesystem paths, secret classes, subprocess,
//! interpreter and shell-wrapper evidence, publisher, transport). A delta
//! against the previously stored snapshot drives the scoring evidence the
//! current-action composition reads, so extraction is deliberately generous
//! and every uncertain input is treated as a capability, never dropped.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::consumer_url::{url_hostname, url_scheme};
use crate::context_digest_local_cli::python_path_name;

static URL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)https?://[^\s'"`]+"#).expect("url pattern"));
static HOST_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b").expect("host pattern"));
static MEDIA_TYPE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:application|audio|font|image|message|model|multipart|text|video)/[a-z0-9!#$&^_.+-]+",
    )
    .expect("media type pattern")
});
static PATH_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(~?/[\p{L}\p{N}_./-]+|\.[/\\][\p{L}\p{N}_./\\-]+)").expect("path pattern")
});

const NON_NETWORK_SUFFIXES: [&str; 16] = [
    "md", "json", "toml", "yaml", "yml", "txt", "py", "js", "ts", "sh", "cfg", "conf", "log",
    "tmp", "bak", "bin",
];
const SCRIPT_INTERPRETERS: [&str; 7] = [
    "node",
    "perl",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "ruby",
];
const SHELL_COMMANDS: [&str; 6] = ["bash", "cmd", "powershell", "pwsh", "sh", "zsh"];
const SHELL_FLAGS: [&str; 3] = ["-c", "-lc", "/c"];
const SUBPROCESS_TOKENS: [&str; 9] = [
    "subprocess",
    "os.system",
    "child_process",
    "spawn(",
    "exec(",
    "bash -c",
    "sh -c",
    "zsh -c",
    "powershell -command",
];
const SECRET_HINTS: [(&str, &str); 9] = [
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "python package credentials"),
    (".aws/credentials", "aws shared credentials"),
    (".ssh/", "ssh material"),
    (".gnupg/", "gpg material"),
    (".docker/config.json", "docker credentials"),
    (".kube/config", "kubeconfig"),
    (".git-credentials", "git credential store"),
];
const SECRET_ENV_TOKENS: [&str; 6] = ["token", "secret", "password", "key", "credential", "auth"];

/// `str(value or "")` for JSON metadata values.
fn python_text(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::Null | Value::Bool(false) => Ok(String::new()),
        Value::Bool(true) => Ok("True".to_owned()),
        Value::String(text) => Ok(text.clone()),
        Value::Number(number) => Ok(match number.as_f64() {
            Some(0.0) => String::new(),
            _ => number.to_string(),
        }),
        Value::Array(items) if items.is_empty() => Ok(String::new()),
        Value::Object(items) if items.is_empty() => Ok(String::new()),
        _ => Err("native_consumer_artifact_project_metadata_unsupported"),
    }
}

/// The capability-relevant projection of one artifact.
pub(crate) struct CapabilityArtifact {
    name: String,
    command: Option<String>,
    url: Option<String>,
    args: Vec<String>,
    publisher: Option<String>,
    transport: Option<String>,
    summaries: [String; 3],
    env_keys: Vec<String>,
}

impl CapabilityArtifact {
    /// Read the artifact input. Metadata summaries follow Python's
    /// `str(value or "")`; a non-empty container has no faithful text, so the
    /// whole query is refused rather than guessed.
    pub(crate) fn from_value(value: &Value) -> Result<Self, &'static str> {
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
        let metadata = value.get("metadata").unwrap_or(&Value::Null);
        // Non-string summaries arrive pre-rendered (Python's `str(value or "")`) under
        // their own key so launch and incident logic never sees them as strings.
        let summary = |key: &str| match metadata
            .get("capability_text_summaries")
            .and_then(|rendered| rendered.get(key))
            .and_then(Value::as_str)
        {
            Some(text) => Ok(text.to_owned()),
            None => python_text(metadata.get(key).unwrap_or(&Value::Null)),
        };
        let strings = |source: &Value, key: &str| -> Vec<String> {
            source
                .get(key)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        Ok(Self {
            name: text("name").unwrap_or_default(),
            command: text("command"),
            url: text("url"),
            args: strings(value, "args"),
            publisher: text("publisher"),
            transport: text("transport"),
            summaries: [
                summary("request_summary")?,
                summary("runtime_request_summary")?,
                summary("prompt_summary")?,
            ],
            env_keys: strings(metadata, "env_keys"),
        })
    }

    fn combined_text(&self) -> String {
        let mut values: Vec<&str> = vec![
            &self.name,
            self.command.as_deref().unwrap_or(""),
            self.url.as_deref().unwrap_or(""),
        ];
        let joined_args = self.args.join(" ");
        values.push(&joined_args);
        values.extend(self.summaries.iter().map(String::as_str));
        values.extend(self.env_keys.iter().map(String::as_str));
        values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn command_name(&self) -> String {
        python_path_name(self.command.as_deref().unwrap_or("")).to_lowercase()
    }
}

fn candidate_urls<'a>(text: &'a str, url: Option<&'a str>) -> Vec<&'a str> {
    let mut candidates: Vec<&str> = URL_PATTERN
        .find_iter(text)
        .map(|found| found.as_str())
        .collect();
    if let Some(url) = url.filter(|url| !url.is_empty()) {
        candidates.push(url);
    }
    candidates
}

fn network_hosts(text: &str, url: Option<&str>) -> BTreeSet<String> {
    let mut hosts: BTreeSet<String> = candidate_urls(text, url)
        .into_iter()
        .filter_map(url_hostname)
        .collect();
    let media_spans: Vec<(usize, usize)> = MEDIA_TYPE_PATTERN
        .find_iter(text)
        .map(|found| (found.start(), found.end()))
        .collect();
    for found in HOST_PATTERN.find_iter(text) {
        if media_spans
            .iter()
            .any(|(start, end)| *start <= found.start() && found.end() <= *end)
        {
            continue;
        }
        let lowered = found.as_str().to_lowercase();
        let suffix = lowered.rsplit('.').next().unwrap_or("");
        if NON_NETWORK_SUFFIXES.contains(&suffix) {
            continue;
        }
        hosts.insert(lowered);
    }
    hosts
}

fn network_schemes(text: &str, url: Option<&str>) -> BTreeSet<String> {
    let mut schemes: BTreeSet<String> = candidate_urls(text, url)
        .into_iter()
        .filter_map(url_scheme)
        .collect();
    let lowered = text.to_lowercase();
    if lowered.contains("ssh ") || lowered.contains("scp ") {
        schemes.insert("ssh".to_owned());
    }
    schemes
}

fn secret_classes(text: &str, artifact: &CapabilityArtifact) -> BTreeSet<String> {
    let lowered = text.to_lowercase();
    let mut classes: BTreeSet<String> = SECRET_HINTS
        .iter()
        .filter(|(hint, _)| lowered.contains(hint))
        .map(|(_, label)| (*label).to_owned())
        .collect();
    let sensitive_key = artifact.env_keys.iter().any(|key| {
        let key = key.to_lowercase();
        SECRET_ENV_TOKENS.iter().any(|token| key.contains(token))
    });
    if sensitive_key {
        classes.insert("sensitive environment key".to_owned());
    }
    classes
}

fn interpreters(artifact: &CapabilityArtifact, text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let command_name = artifact.command_name();
    if SCRIPT_INTERPRETERS.contains(&command_name.as_str()) {
        found.insert(command_name);
    }
    let lowered = text.to_lowercase();
    for candidate in SCRIPT_INTERPRETERS {
        if [" ", "-", "("]
            .iter()
            .any(|suffix| lowered.contains(&format!("{candidate}{suffix}")))
        {
            found.insert(candidate.to_owned());
        }
    }
    found
}

fn shell_wrappers(artifact: &CapabilityArtifact) -> BTreeSet<String> {
    let mut wrappers = BTreeSet::new();
    let command_name = artifact.command_name();
    if SHELL_COMMANDS.contains(&command_name.as_str()) {
        wrappers.insert(command_name.clone());
    }
    for arg in artifact
        .args
        .iter()
        .filter(|arg| SHELL_FLAGS.contains(&arg.as_str()))
    {
        if command_name.is_empty() {
            wrappers.insert(arg.clone());
        } else {
            wrappers.insert(format!("{command_name}:{arg}"));
        }
    }
    wrappers
}

fn subprocess_intent(text: &str, artifact: &CapabilityArtifact) -> bool {
    let lowered = text.to_lowercase();
    SUBPROCESS_TOKENS
        .iter()
        .any(|token| lowered.contains(token))
        || (SHELL_COMMANDS.contains(&artifact.command_name().as_str())
            && artifact
                .args
                .iter()
                .any(|arg| SHELL_FLAGS.contains(&arg.as_str())))
}

fn transport(artifact: &CapabilityArtifact) -> &'static str {
    let declared = artifact.transport.as_deref().unwrap_or("").to_lowercase();
    if ["http", "https", "ws", "wss", "sse", "remote"].contains(&declared.as_str()) {
        return "remote";
    }
    if ["hybrid", "bridge"].contains(&declared.as_str()) {
        return "hybrid";
    }
    match artifact.url.as_deref() {
        Some(url) if url.starts_with("http://") || url.starts_with("https://") => "remote",
        _ => "local",
    }
}

/// Normalize the artifact's capabilities into the stored snapshot shape.
pub(crate) fn normalize(artifact: &CapabilityArtifact) -> Value {
    let combined = artifact.combined_text();
    let url = artifact.url.as_deref();
    let paths: BTreeSet<&str> = PATH_PATTERN
        .find_iter(&combined)
        .map(|found| found.as_str())
        .collect();
    json!({
        "network_hosts": network_hosts(&combined, url),
        "network_schemes": network_schemes(&combined, url),
        "filesystem_paths": paths,
        "secret_classes": secret_classes(&combined, artifact),
        "subprocess_invocation": subprocess_intent(&combined, artifact),
        "interpreters": interpreters(artifact, &combined),
        "shell_wrappers": shell_wrappers(artifact),
        "publisher": artifact.publisher,
        "transport": transport(artifact),
    })
}
