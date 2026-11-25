//! Upgrade advice for a review the known-vulnerable runtime check raised.
//!
//! When Guard holds a command because the Node.js it launches matches a
//! high or critical advisory, the approval inbox can say how to move off that
//! build: which patched release to use, the command for the version manager
//! that installed it, and, for nvm with a patched version already installed,
//! a one-click switch of nvm's default version.
//!
//! The advice is recomputed from the stored row on every read and before
//! every switch. The row only says which executable Guard checked; that file
//! is identified and matched against the cached advisories again, so a row
//! whose runtime is no longer affected gets no advice, and a client never
//! names the directory or the version that the switch writes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Map, Value};

use crate::runtime_identity::LaunchAdvisories;
use crate::runtime_identity_range::SemVer;
use crate::runtime_known_vulnerable::{affected, assessed, is_review_finding, Finding};
use crate::runtime_known_vulnerable_source as source;

pub(crate) const SCHEMA: &str = "guard.runtime-upgrade-advice.v1";
const FAMILY: &str = "node";
const DOWNLOAD_URL: &str = "https://nodejs.org/en/download";
/// Installed nvm versions considered; a larger tree is read up to here.
const MAX_INSTALLED: usize = 128;
const MAX_ALIAS_BYTES: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Manager {
    /// The nvm directory the runtime was installed under.
    Nvm(PathBuf),
    /// The Homebrew formula, `node` or a versioned one such as `node@22`.
    Homebrew(String),
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Advice {
    pub(crate) finding: Finding,
    pub(crate) manager: Manager,
    /// The first clean release at or above the affected one.
    pub(crate) patched_version: Option<String>,
    /// A clean version nvm already has installed, ready to switch to.
    pub(crate) installed_version: Option<String>,
    /// What nvm's `default` alias names now.
    pub(crate) default_alias: Option<String>,
}

/// The advice for a pending review held by the known-vulnerable runtime
/// check, or `None` for any other row or a runtime no longer affected.
pub(crate) fn for_approval(approval: &Map<String, Value>, guard_home: &Path) -> Option<Advice> {
    if approval.get("status").and_then(Value::as_str) != Some("pending")
        || !reason_code(approval).is_some_and(|code| is_review_finding(&code))
    {
        return None;
    }
    let checked = checked_path(approval.get("risk_summary")?.as_str()?)?;
    let advisories = source::advisories(guard_home)?;
    let finding = affected(Path::new(checked), &advisories)?;
    Some(advise(finding, &advisories, |binary| {
        assessed_clean(binary, &advisories)
    }))
}

/// The advice for `finding`. `clean_binary` confirms an installed runtime by
/// identifying the file itself, as the launch check would.
pub(crate) fn advise(
    finding: Finding,
    advisories: &LaunchAdvisories,
    clean_binary: impl Fn(&Path) -> bool,
) -> Advice {
    let current = SemVer::parse(&finding.version);
    let patched_version = current
        .as_ref()
        .and_then(|current| advisories.patched_release(FAMILY, current));
    let manager = manager(Path::new(&finding.resolved_path));
    let (installed_version, default_alias) = match &manager {
        Manager::Nvm(directory) => (
            current
                .as_ref()
                .and_then(|current| installed_clean(directory, current, advisories, &clean_binary)),
            default_alias(directory),
        ),
        _ => (None, None),
    };
    Advice {
        finding,
        manager,
        patched_version,
        installed_version,
        default_alias,
    }
}

impl Advice {
    /// Whether nvm's default already names the installed patched version.
    fn switched(&self) -> bool {
        match (&self.installed_version, &self.default_alias) {
            (Some(installed), Some(alias)) => alias.trim_start_matches('v') == installed,
            _ => false,
        }
    }

    fn switch_version(&self) -> Option<&str> {
        match self.manager {
            Manager::Nvm(_) if !self.switched() => self.installed_version.as_deref(),
            _ => None,
        }
    }

    fn command(&self) -> Option<String> {
        match &self.manager {
            Manager::Nvm(_) => match (&self.installed_version, &self.patched_version) {
                (Some(installed), _) => Some(format!("nvm alias default {installed}")),
                (None, Some(patched)) => Some(format!(
                    "nvm install {patched} && nvm alias default {patched}"
                )),
                (None, None) => None,
            },
            Manager::Homebrew(formula) => Some(format!("brew upgrade {formula}")),
            Manager::Other => None,
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let finding = &self.finding;
        json!({
            "schema": SCHEMA,
            "family": FAMILY,
            "current_version": finding.version,
            "current_path": finding.resolved_path,
            "advisory_id": finding.advisory_id,
            "severity": finding.severity,
            "known_exploited": finding.known_exploited,
            "manager": match self.manager {
                Manager::Nvm(_) => "nvm",
                Manager::Homebrew(_) => "homebrew",
                Manager::Other => "other",
            },
            "patched_version": self.patched_version,
            "installed_version": self.installed_version,
            "switch_version": self.switch_version(),
            "switched": self.switched(),
            "command": self.command(),
            "download_url": DOWNLOAD_URL,
        })
    }

    /// Points nvm's `default` alias at the installed patched version, when
    /// that is the switch this advice offers and `requested` names it. New
    /// shells then start that version; running ones keep the old `PATH`.
    pub(crate) fn switch(&self, requested: &str) -> Result<(), &'static str> {
        let (Manager::Nvm(directory), Some(version)) = (&self.manager, self.switch_version())
        else {
            return Err("runtime_upgrade_unavailable");
        };
        if requested != version {
            return Err("runtime_upgrade_version_mismatch");
        }
        write_alias(&directory.join("alias"), version).map_err(|_| "runtime_upgrade_failed")
    }
}

/// The review's reason code, from the native receipt the hook recorded.
fn reason_code(approval: &Map<String, Value>) -> Option<String> {
    let envelope = match approval.get("action_envelope_json")? {
        Value::String(text) => serde_json::from_str(text).ok()?,
        envelope => envelope.clone(),
    };
    envelope
        .pointer("/native_origin_receipt/reason_code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The executable named by the finding text Guard wrote for this review:
/// `Node.js {version} at {path} is affected by {advisory}`.
pub(crate) fn checked_path(reason: &str) -> Option<&str> {
    let rest = reason.strip_prefix("Node.js ")?;
    let (_, rest) = rest.split_once(" at ")?;
    let (path, _) = rest.rsplit_once(" is affected by ")?;
    Path::new(path).is_absolute().then_some(path)
}

/// nvm keeps each version at `{nvm}/versions/node/v{version}/bin/node`, and
/// Homebrew keeps each formula at `Cellar/{formula}/{version}/bin/node`, where
/// the formula is `node` or a versioned one such as `node@22`.
fn manager(resolved: &Path) -> Manager {
    let names: Vec<_> = resolved
        .ancestors()
        .skip(1)
        .take(4)
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    if let ([bin, version, node, versions], Some(nvm)) =
        (names.as_slice(), resolved.ancestors().nth(5))
    {
        if *bin == "bin"
            && version.starts_with('v')
            && *node == "node"
            && *versions == "versions"
            && nvm.join("nvm.sh").is_file()
        {
            return Manager::Nvm(nvm.to_path_buf());
        }
    }
    if let ([bin, _version, formula], Some(cellar)) = (
        names.get(..3).unwrap_or_default(),
        resolved.ancestors().nth(4),
    ) {
        if *bin == "bin"
            && cellar.file_name().and_then(|name| name.to_str()) == Some("Cellar")
            && homebrew_node_formula(formula)
        {
            return Manager::Homebrew((*formula).to_owned());
        }
    }
    Manager::Other
}

/// `node`, or `node@{major}`.
fn homebrew_node_formula(name: &str) -> bool {
    name == "node"
        || name.strip_prefix("node@").is_some_and(|major| {
            !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// The best clean version nvm has installed: the newest on the affected
/// version's own major line, else the newest overall.
fn installed_clean(
    directory: &Path,
    current: &SemVer,
    advisories: &LaunchAdvisories,
    clean_binary: &impl Fn(&Path) -> bool,
) -> Option<String> {
    let mut clean: Vec<(SemVer, String)> = fs::read_dir(directory.join("versions").join("node"))
        .ok()?
        .filter_map(Result::ok)
        .take(MAX_INSTALLED)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let raw = name.strip_prefix('v')?.to_owned();
            let version = SemVer::parse(&raw)?;
            advisories
                .version_is_clean(FAMILY, &version)
                .then_some((version, raw))
        })
        .collect();
    clean.sort_by(|left, right| right.0.cmp(&left.0));
    let mut ordered: Vec<&(SemVer, String)> = clean
        .iter()
        .filter(|(version, _)| version.major() == current.major())
        .collect();
    ordered.extend(
        clean
            .iter()
            .filter(|(version, _)| version.major() != current.major()),
    );
    ordered
        .into_iter()
        .find(|(_, raw)| {
            let binary = directory
                .join("versions")
                .join("node")
                .join(format!("v{raw}"))
                .join("bin")
                .join("node");
            clean_binary(&binary)
        })
        .map(|(_, raw)| raw.clone())
}

fn default_alias(directory: &Path) -> Option<String> {
    let path = directory.join("alias").join("default");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ALIAS_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let alias = text.trim();
    (!alias.is_empty()).then(|| alias.to_owned())
}

/// Replaces `{alias}/default` in one rename, so nvm never reads a partial
/// file. Each call stages under its own name, so two overlapping switches
/// cannot remove each other's file, and a call removes only what it created.
/// The nvm directory comes from a canonical path, so only `alias` itself can
/// be a link; a link or any other non-directory there is refused, so the
/// write never lands outside the nvm directory.
fn write_alias(alias: &Path, version: &str) -> std::io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    match fs::create_dir(alias) {
        Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => return Err(error),
        _ => {}
    }
    if !fs::symlink_metadata(alias)?.file_type().is_dir() {
        return Err(std::io::Error::other("nvm alias is not a directory"));
    }
    let staged = alias.join(format!(
        ".default.guard-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)?;
    let written = file
        .write_all(version.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&staged, alias.join("default")));
    if written.is_err() {
        let _ = fs::remove_file(&staged);
    }
    written
}

/// Whether the runtime at `path` is a Node.js version Guard identified and
/// assessed with no high or critical advisory. A failed probe, an unknown
/// version or a failed assessment is not clean.
pub(crate) fn assessed_clean(path: &Path, advisories: &LaunchAdvisories) -> bool {
    source::probe(path).is_some_and(|(resolved, artifact)| {
        artifact["version"].as_str().is_some()
            && matches!(assessed(resolved, &artifact, advisories), Ok(None))
    })
}

#[cfg(test)]
#[path = "runtime_upgrade_advice_tests.rs"]
mod tests;
