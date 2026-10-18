//! `workspace-contained-grant-v1`: the workspace plan widened by one local
//! CLI grant this device allowed.
//!
//! The grant adds what the CLI needs to run and nothing more: execution of
//! its program file and its script interpreter's (never the directories they
//! sit in), and per enabled capability its state directory (`~/.<name>`) for
//! reading or writing and loopback-only network. Every denial of the base profile stays, and the
//! credential denials still close the Seatbelt profile, so a capability can
//! never reopen a secret. A capability this host's sandbox cannot bound is
//! left out of the plan, which keeps its denial.
use super::workspace_grant_launch::Reach;
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) const GRANT_PROFILE: &str = "workspace-contained-grant-v1";
/// Every capability a grant may turn on, in their canonical order.
pub const GRANT_CAPABILITIES: [&str; 3] = ["loopback-network", "state-dir-read", "state-dir-write"];
const LOOPBACK: &str = "loopback-network";
const STATE_READ: &str = "state-dir-read";
const STATE_WRITE: &str = "state-dir-write";
/// Home directories other tools share or keep credentials in; a CLI whose
/// name would make one of these its state directory gets no state grant.
const SHARED_HOME_NAMES: &[&str] = &[
    "android",
    "aws",
    "azure",
    "bun",
    "bundle",
    "cache",
    "cargo",
    "claude",
    "codex",
    "config",
    "cursor",
    "deno",
    "docker",
    "gem",
    "git",
    "gnupg",
    "gradle",
    "hol-guard",
    "hol-support",
    "ivy2",
    "kube",
    "local",
    "m2",
    "netrc",
    "npm",
    "nuget",
    "nvm",
    "oci",
    "password-store",
    "pki",
    "pyenv",
    "rustup",
    "ssh",
    "subversion",
    "terraform",
    "vault",
    "volta",
    "vscode",
    "yarn",
    "zcode",
];

/// The grant a plan is widened by, as the resident decided it.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct GrantInput {
    pub(super) identity_hash: String,
    pub(super) name: String,
    pub(super) capabilities: Vec<String>,
}

/// The extra Seatbelt rules a grant profile composes with.
#[derive(Default)]
pub(super) struct GrantRules {
    pub(super) reads: Vec<PathBuf>,
    pub(super) writes: Vec<PathBuf>,
    pub(super) network: Vec<String>,
}

fn invalid(message: &str) -> RestrictedPytestError {
    RestrictedPytestError::new(PYTEST_INVALID_COMMAND_REASON_CODE, message)
}

/// Sorted, distinct, known capability names; anything else is refused.
pub fn grant_capabilities(names: &[String]) -> Option<&[String]> {
    (names
        .iter()
        .all(|name| GRANT_CAPABILITIES.contains(&name.as_str()))
        && names.windows(2).all(|pair| pair[0] < pair[1]))
    .then_some(names)
}

fn has(capabilities: &[String], name: &str) -> bool {
    capabilities.iter().any(|item| item == name)
}

/// `~/.<name>` for a plain lowercase CLI name that is not a shared or
/// credential directory: inside the canonical home, never the home itself,
/// and never a link. It need not exist yet.
pub(super) fn state_dir(name: &str, home: &Path) -> Option<PathBuf> {
    let plain = (2..=40).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !plain || SHARED_HOME_NAMES.contains(&name) || !home.is_absolute() {
        return None;
    }
    let home = home.canonicalize().ok()?;
    if home == Path::new("/") {
        return None;
    }
    let candidate = home.join(format!(".{name}"));
    let text = candidate.to_str()?;
    if crate::secret_path_probe::is_request_secret_path(text, None, Some(&home))
        || crate::secret_path_probe::is_request_secret_path(
            &format!("{text}/state"),
            None,
            Some(&home),
        )
    {
        return None;
    }
    match std::fs::symlink_metadata(&candidate) {
        Ok(meta) if !meta.file_type().is_dir() => None,
        _ => Some(candidate),
    }
}

/// Widen the base workspace `plan` by `grant` for the program the command is
/// one plain invocation of. `platform` names the host; Linux's namespace cannot
/// yet bound loopback-only network or a home state directory, so there the
/// plan carries none of those capabilities and keeps their denial.
pub(super) fn widen(
    plan: &mut Value,
    grant: &GrantInput,
    program: &str,
    search_path: &str,
    home: Option<&Path>,
    workspace: &Path,
    platform: &str,
) -> Result<(), RestrictedPytestError> {
    let hash_valid = grant.identity_hash.len() == 64
        && grant
            .identity_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let capabilities = grant_capabilities(&grant.capabilities)
        .filter(|_| hash_valid)
        .ok_or_else(|| invalid("Invalid local CLI grant."))?;
    let effective: Vec<String> = if platform == "darwin" {
        capabilities.to_vec()
    } else {
        Vec::new()
    };
    let mut reach = Reach::of(plan, search_path, home, workspace)
        .ok_or_else(|| invalid("Invalid workspace sandbox plan."))?;
    reach
        .admit_launch(program)
        .ok_or_else(|| invalid("The granted program cannot be located for the sandbox."))?;
    let mut read_only_roots = plan["read_only_roots"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if has(&effective, STATE_READ) || has(&effective, STATE_WRITE) {
        let state = home
            .and_then(|home| state_dir(&grant.name, home))
            .ok_or_else(|| invalid("The granted CLI has no admissible state directory."))?;
        read_only_roots.push(json!(state));
    }
    plan["profile_version"] = json!(GRANT_PROFILE);
    reach.write(plan);
    plan["read_only_roots"] = Value::Array(read_only_roots);
    plan["grant_identity_hash"] = json!(grant.identity_hash);
    plan["capabilities"] = json!(effective);
    Ok(())
}

/// The Seatbelt rules a grant profile adds, after checking the plan's
/// directory read grant is the CLI state directory under `home`: one
/// directory at most, and only with a state capability.
pub(super) fn rules(
    capabilities: &[String],
    read_only_roots: &[PathBuf],
    home: Option<&Path>,
) -> Result<GrantRules, RestrictedPytestError> {
    let capabilities =
        grant_capabilities(capabilities).ok_or_else(|| invalid("Invalid local CLI grant."))?;
    let directories: Vec<&PathBuf> = read_only_roots
        .iter()
        .filter(|root| std::fs::symlink_metadata(root).map_or(true, |meta| meta.is_dir()))
        .collect();
    let stateful = has(capabilities, STATE_READ) || has(capabilities, STATE_WRITE);
    let state = match (directories.as_slice(), stateful) {
        ([], false) => None,
        ([state], true) => {
            let name = state
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix('.'))
                .ok_or_else(|| invalid("Invalid local CLI grant."))?;
            let expected = home.and_then(|home| state_dir(name, home));
            if expected.as_deref() != Some(state.as_path()) {
                return Err(invalid("Invalid local CLI grant."));
            }
            Some(state.to_path_buf())
        }
        _ => return Err(invalid("Invalid local CLI grant.")),
    };
    let mut rules = GrantRules::default();
    if let Some(state) = state {
        if has(capabilities, STATE_WRITE) {
            rules.writes.push(state.clone());
        }
        rules.reads.push(state);
    }
    if has(capabilities, LOOPBACK) {
        rules.network = loopback_any_port();
    }
    Ok(rules)
}

/// Loopback-only network on any port: bind, accept and connect on
/// `localhost`. Every other address stays denied by default.
pub(super) fn loopback_any_port() -> Vec<String> {
    vec![
        "(allow network-bind (local ip \"localhost:*\"))".to_owned(),
        "(allow network-inbound (local ip \"localhost:*\"))".to_owned(),
        "(allow network-outbound (remote ip \"localhost:*\"))".to_owned(),
    ]
}

#[cfg(test)]
#[path = "workspace_grant_tests.rs"]
mod tests;
