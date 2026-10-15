//! `secrets-cli --stdin`: the scanning and pre-commit authority behind
//! `hol-guard secrets`.
//!
//! The Python CLI parses arguments, sends one request, and renders the
//! public result. Detection, Git index/history reads, bounds and hook
//! installation all run here through `guard-scanner`. A scan or hook failure
//! that Python surfaced as `OSError`/`ValueError` comes back as
//! `{"ok": false, "error": <message>}` with the same message text.

use std::path::Path;

use guard_scanner::precommit::{install_precommit_hook, uninstall_precommit_hook};
use guard_scanner::repository_scanner::{scan_repository_secrets, RepositoryScanOptions};
use guard_scanner::staged_scanner::{scan_staged_secrets, StagedScanOptions};
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) const COMMAND: &str = "secrets-cli";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "command")]
pub(crate) enum SecretsRequest {
    Scan(ScanRequest),
    InstallHook(HookRequest),
    UninstallHook(HookRequest),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ScanScope {
    Working,
    Staged,
    History,
}

/// A zero or missing bound selects the scanner default, as in Python.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanRequest {
    target: String,
    scope: ScanScope,
    #[serde(default)]
    max_commits: usize,
    #[serde(default)]
    max_files: usize,
    #[serde(default)]
    max_file_bytes: usize,
    #[serde(default)]
    max_total_bytes: usize,
    #[serde(default)]
    max_findings: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookRequest {
    target: String,
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: SecretsRequest =
        serde_json::from_slice(bytes).map_err(|_| "secrets_cli_request_invalid".to_owned())?;
    Ok(respond(&request))
}

pub(crate) fn respond(request: &SecretsRequest) -> Value {
    let outcome = match request {
        SecretsRequest::Scan(scan) => run_scan(scan),
        SecretsRequest::InstallHook(hook) => install_precommit_hook(Path::new(&hook.target))
            .map(|result| result.to_public_dict())
            .map_err(|error| error.to_string()),
        SecretsRequest::UninstallHook(hook) => uninstall_precommit_hook(Path::new(&hook.target))
            .map(|result| result.to_public_dict())
            .map_err(|error| error.to_string()),
    };
    match outcome {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn run_scan(request: &ScanRequest) -> Result<Value, String> {
    let target = Path::new(&request.target);
    let result = if request.scope == ScanScope::Staged {
        let options = StagedScanOptions {
            max_files: request.max_files,
            max_file_bytes: request.max_file_bytes,
            max_total_bytes: request.max_total_bytes,
            max_findings: request.max_findings,
        };
        scan_staged_secrets(target, &options).map_err(|error| error.to_string())?
    } else {
        let options = RepositoryScanOptions {
            include_history: request.scope == ScanScope::History,
            max_commits: request.max_commits,
            max_files: request.max_files,
            max_file_bytes: request.max_file_bytes,
            max_total_bytes: request.max_total_bytes,
            max_findings: request.max_findings,
        };
        scan_repository_secrets(target, &options).map_err(|error| error.to_string())?
    };
    let public = result
        .to_public_dict()
        .map_err(|_| "secrets_cli_result_encode_failed".to_owned())?;
    serde_json::to_value(public).map_err(|_| "secrets_cli_result_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "secrets_cli_vectors_tests.rs"]
mod vectors_tests;
