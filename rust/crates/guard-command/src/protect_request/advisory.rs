//! Cached-advisory matching for `evaluate_protect_request`.

use std::path::Path;

use super::*;

pub(super) fn severity_rank(advisory: &Map<String, Value>) -> u8 {
    match advisory.get("severity").and_then(Value::as_str) {
        Some("low") => 0,
        Some("high") => 2,
        Some("critical") => 3,
        _ => 1,
    }
}

pub(super) fn advisory_action(advisory: &Map<String, Value>) -> &'static str {
    match advisory.get("action").and_then(Value::as_str) {
        Some("allow") => "allow",
        Some("review") => "review",
        Some("block") => "block",
        _ if severity_rank(advisory) >= 2 => "block",
        _ => "review",
    }
}

pub(super) fn advisory_headline(advisory: &Map<String, Value>) -> String {
    if let Some(headline) = advisory.get("headline").and_then(Value::as_str) {
        let stripped = python_strip(headline);
        if !stripped.is_empty() {
            return stripped.to_owned();
        }
    }
    let artifact = ["package", "name", "artifact_id"]
        .iter()
        .filter_map(|key| advisory.get(*key))
        .find(|value| py_truthy(value))
        .map_or_else(|| "Artifact".to_owned(), py_str);
    format!("{artifact} matched a Guard advisory.")
}

/// A launched script that names a credential store and uses the network.
const SCRIPT_EXFILTRATES: &str = "runs a script that reads a credential store and uses the network";
/// An argument to a launched script that names a secret file.
const SCRIPT_SECRET_ARGUMENT: &str = "passes a secret file to a script";

/// For a custom command that launches a readable script, the signals of what
/// that script does: the arguments after it are its data, so prose that
/// merely mentions a secret is not one. `None` keeps the command-line scan:
/// any other command, or a script that cannot be read whole.
fn launched_script_signals(request: &ProtectRequest, cwd: Option<&Path>) -> Option<Vec<String>> {
    if request.install_kind != "custom" {
        return None;
    }
    let crate::pretool::ArgvScript::Read {
        exfiltrates,
        arguments,
    } = crate::pretool::argv_script(&request.command, cwd)
    else {
        return None;
    };
    let mut signals = Vec::new();
    if exfiltrates {
        signals.push(SCRIPT_EXFILTRATES.to_owned());
    }
    if arguments
        .iter()
        .any(|argument| names_secret_path(argument, cwd))
    {
        signals.push(SCRIPT_SECRET_ARGUMENT.to_owned());
    }
    Some(signals)
}

/// Whether `argument` is a secret path, or a command string (a script may
/// hand one to a shell) with a path token under a credential store. Only a
/// token that spells a path counts: a bare word in prose is data.
fn names_secret_path(argument: &str, cwd: Option<&Path>) -> bool {
    let secret = |text: &str| crate::secret_path_probe::is_request_secret_path(text, cwd, None);
    secret(argument)
        || argument
            .split_whitespace()
            .map(|token| {
                token.trim_matches(|c| {
                    matches!(c, '"' | '\'' | ';' | '|' | '&' | '(' | ')' | '<' | '>')
                })
            })
            .any(|token| (token.contains('/') || token.starts_with('~')) && secret(token))
}

pub(super) fn request_risk_signals(request: &ProtectRequest, cwd: Option<&Path>) -> Vec<String> {
    if let Some(signals) = launched_script_signals(request, cwd) {
        return signals;
    }
    let joined = request.command.join(" ").to_lowercase();
    let mentions = |needles: &[&str]| needles.iter().any(|needle| joined.contains(needle));
    let mut signals: Vec<&str> = Vec::new();
    if request.install_kind == "harness_registration" {
        if request.targets.iter().any(|t| t.source_url.is_some()) {
            signals.push("registers a remote server endpoint");
        }
        if request
            .targets
            .iter()
            .any(|t| matches!(t.artifact_type.as_str(), "extension" | "plugin" | "skill"))
        {
            signals.push("registers executable harness code");
        }
        if mentions(&["http://", "https://", "curl ", "wget "]) {
            signals.push("can fetch or talk to a remote server during registration");
        }
    }
    if mentions(&[".env", "printenv", "process.env", "os.environ", "getenv("]) {
        signals.push("references local environment secrets");
    }
    if mentions(&[
        ".ssh",
        ".npmrc",
        ".pypirc",
        ".gitconfig",
        "id_rsa",
        "credentials",
    ]) {
        signals.push("mentions sensitive local files");
    }
    if mentions(&[
        "bash -c",
        "bash -lc",
        "sh -c",
        "zsh -c",
        "powershell -command",
    ]) {
        signals.push("runs through a shell wrapper");
    }
    for target in &request.targets {
        if target.artifact_type == "custom_command" {
            continue;
        }
        let spec = target.raw_spec.as_deref().unwrap_or("");
        if starts_with_url(spec)
            || spec.starts_with("./")
            || spec.starts_with("../")
            || spec.starts_with('/')
        {
            signals.push("installs from a non-registry source");
        }
    }
    let mut deduped: Vec<String> = Vec::new();
    for signal in signals {
        if !deduped.iter().any(|seen| seen == signal) {
            deduped.push(signal.to_owned());
        }
    }
    deduped
}

/// `evaluate_protect_request` over the cached advisory rows (each the
/// `list_cached_advisories` dict), without a working directory.
pub fn evaluate_protect_request(request: &ProtectRequest, advisories: &[Value]) -> ProtectVerdict {
    evaluate_protect_request_in(request, advisories, None)
}

/// `evaluate_protect_request` for a command that runs in `cwd`, where a
/// custom command's relative script can be read.
pub fn evaluate_protect_request_in(
    request: &ProtectRequest,
    advisories: &[Value],
    cwd: Option<&Path>,
) -> ProtectVerdict {
    let risk_signals = request_risk_signals(request, cwd);
    let identities: Vec<Value> = request
        .targets
        .iter()
        .map(ProtectTarget::identity)
        .collect();
    let mut matched: Vec<usize> = advisories
        .iter()
        .enumerate()
        .filter(|(_, advisory)| {
            identities
                .iter()
                .any(|identity| advisory_matches_target(advisory, identity))
        })
        .map(|(index, _)| index)
        .collect();
    let row = |index: usize| {
        advisories[index]
            .as_object()
            .expect("matched rows are objects")
    };
    matched.sort_by_key(|index| std::cmp::Reverse(severity_rank(row(*index))));
    let first_with = |action: &str| {
        matched
            .iter()
            .copied()
            .find(|index| advisory_action(row(*index)) == action)
    };
    if let Some(index) = first_with("block") {
        return ProtectVerdict {
            action: "block",
            reason: format!(
                "{} Guard blocked the install before the artifact landed locally.",
                advisory_headline(row(index))
            ),
            risk_signals,
            matched,
        };
    }
    // The same rule the hooks apply to a launched script.
    if risk_signals
        .iter()
        .any(|signal| signal == SCRIPT_EXFILTRATES)
    {
        return ProtectVerdict {
            action: "block",
            reason:
                "HOL Guard blocked a script that reads a credential store and uses the network."
                    .to_owned(),
            risk_signals,
            matched,
        };
    }
    let review = first_with("review");
    if !risk_signals.is_empty() || review.is_some() {
        let reason = if let Some(index) = review {
            format!(
                "{} Guard paused this install for review.",
                advisory_headline(row(index))
            )
        } else if risk_signals
            .iter()
            .any(|s| s == "registers a remote server endpoint")
        {
            "This request registers a remote server endpoint. Guard paused it until you review the target.".to_owned()
        } else if risk_signals
            .iter()
            .any(|s| s == "installs from a non-registry source")
        {
            "This request pulls code from a non-registry source. Guard paused it for review before install.".to_owned()
        } else {
            "Guard found install-time risk signals that should be reviewed before this command runs."
                .to_owned()
        };
        return ProtectVerdict {
            action: "review",
            reason,
            risk_signals,
            matched,
        };
    }
    ProtectVerdict {
        action: "allow",
        reason: "Guard found no blocking advisory or risky install signal for this request."
            .to_owned(),
        risk_signals,
        matched,
    }
}
