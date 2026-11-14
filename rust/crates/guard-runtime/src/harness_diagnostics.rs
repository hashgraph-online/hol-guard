//! `harness_diagnostics` — what `hol-guard doctor` reports about one harness
//! once its adapter has detected it: the warnings Guard adds to the
//! detection, the setup status the final warnings leave, and whether any
//! detected artifact runs through Guard.
//!
//! The adapters still read the tool's files and run its probes; this kind
//! decides from what they found.
//!
//! - `{"op": "warnings", "harness", "executable",
//!   "command_absence_proves_uninstalled", "runtime_probe", "detection"}`
//!   answers `{"warnings": [...]}`, the warnings to append to the detection's
//!   own, in order. `runtime_probe` is `null` when the adapter ran no probe,
//!   else `{"timed_out", "failed", "reported_no_artifacts",
//!   "managed_install_present", "runtime_hook_registered"}`: whether the probe
//!   timed out, exited unsuccessfully and listed no MCP servers, and whether
//!   a managed install exists with its runtime hook registered.
//! - `{"op": "setup_status", "command_absence_proves_uninstalled",
//!   "detection", "warnings"}` answers `{"setup_status": "active" | "broken" |
//!   "partial" | "not_found"}`.
//! - `{"op": "uses_guard", "artifacts"}` answers `{"uses_guard": bool}`.
//!
//! A detection is `{"config_paths", "command_available", "artifacts"}` and an
//! artifact is `{"artifact_type", "command", "args", "harness"}`. The native
//! request parser refuses any array wider than 4096 entries, so every list
//! (config paths, artifacts, an artifact's args, warnings) crosses as a list
//! of chunks that join back here in order.

use serde_json::{json, Map, Value};

use crate::context_digest_local_cli::python_path_name;
// The shared runner-authority code: the Python client reads a code under
// that prefix as the resident refusing a request, not as an outage.
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MISSING_COMMAND_MARKER: &str = "command is not available";
const SETUP_FAILURE_MARKERS: [&str; 4] = [
    "guard is not installed",
    MISSING_COMMAND_MARKER,
    "native hooks are disabled",
    "managed codex hooks are missing",
];
const GUARD_LAUNCHER_SHIM: &str = "guard_launcher_shim";

type Fields = Map<String, Value>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    match fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?
    {
        "warnings" => {
            expect_keys(
                fields,
                &[
                    "op",
                    "harness",
                    "executable",
                    "command_absence_proves_uninstalled",
                    "runtime_probe",
                    "detection",
                ],
            )?;
            let detection = Detection::parse(fields.get("detection"))?;
            let adapter = Adapter {
                harness: text(fields, "harness")?,
                executable: text(fields, "executable")?,
                command_absence_proves_uninstalled: flag(
                    fields,
                    "command_absence_proves_uninstalled",
                )?,
            };
            let probe = Probe::parse(fields.get("runtime_probe"))?;
            Ok(json!({ "warnings": added_warnings(&detection, &adapter, probe) }))
        }
        "setup_status" => {
            expect_keys(
                fields,
                &[
                    "op",
                    "command_absence_proves_uninstalled",
                    "detection",
                    "warnings",
                ],
            )?;
            let detection = Detection::parse(fields.get("detection"))?;
            let warnings = strings(fields.get("warnings"))?;
            let proves = flag(fields, "command_absence_proves_uninstalled")?;
            Ok(json!({ "setup_status": setup_status(&detection, &warnings, proves) }))
        }
        "uses_guard" => {
            expect_keys(fields, &["op", "artifacts"])?;
            let listed = artifacts(fields.get("artifacts"))?;
            Ok(json!({ "uses_guard": listed.iter().any(Artifact::uses_guard) }))
        }
        _ => Err(ERR_INVALID),
    }
}

struct Adapter<'a> {
    harness: &'a str,
    executable: &'a str,
    command_absence_proves_uninstalled: bool,
}

#[derive(Clone, Copy, Default)]
struct Probe {
    timed_out: bool,
    failed: bool,
    reported_no_artifacts: bool,
    managed_install_present: bool,
    runtime_hook_registered: bool,
}

impl Probe {
    /// `None` when the adapter ran no probe.
    fn parse(value: Option<&Value>) -> Result<Option<Self>, &'static str> {
        let value = value.ok_or(ERR_INVALID)?;
        if value.is_null() {
            return Ok(None);
        }
        let fields = value.as_object().ok_or(ERR_INVALID)?;
        expect_keys(
            fields,
            &[
                "timed_out",
                "failed",
                "reported_no_artifacts",
                "managed_install_present",
                "runtime_hook_registered",
            ],
        )?;
        Ok(Some(Self {
            timed_out: flag(fields, "timed_out")?,
            failed: flag(fields, "failed")?,
            reported_no_artifacts: flag(fields, "reported_no_artifacts")?,
            managed_install_present: flag(fields, "managed_install_present")?,
            runtime_hook_registered: flag(fields, "runtime_hook_registered")?,
        }))
    }
}

struct Artifact<'a> {
    artifact_type: &'a str,
    command: Option<&'a str>,
    args: Vec<&'a str>,
    harness: &'a str,
}

impl<'a> Artifact<'a> {
    fn parse(value: &'a Value) -> Result<Self, &'static str> {
        let fields = value.as_object().ok_or(ERR_INVALID)?;
        expect_keys(fields, &["artifact_type", "command", "args", "harness"])?;
        let command = match fields.get("command") {
            Some(Value::Null) => None,
            Some(Value::String(command)) => Some(command.as_str()),
            _ => return Err(ERR_INVALID),
        };
        Ok(Self {
            artifact_type: text(fields, "artifact_type")?,
            command,
            args: strings(fields.get("args"))?,
            harness: text(fields, "harness")?,
        })
    }

    /// Whether the artifact is Guard's launcher, Guard's per-harness command,
    /// or a command line that names Guard.
    fn uses_guard(&self) -> bool {
        if self.artifact_type == GUARD_LAUNCHER_SHIM {
            return true;
        }
        if self
            .command
            .is_some_and(|command| is_guard_command_name(command, self.harness))
        {
            return true;
        }
        std::iter::once(self.command.unwrap_or(""))
            .chain(self.args.iter().copied())
            .any(value_mentions_guard)
    }
}

struct Detection<'a> {
    config_paths: Vec<&'a str>,
    command_available: bool,
    artifacts: Vec<Artifact<'a>>,
}

impl<'a> Detection<'a> {
    fn parse(value: Option<&'a Value>) -> Result<Self, &'static str> {
        let fields = value.and_then(Value::as_object).ok_or(ERR_INVALID)?;
        expect_keys(fields, &["config_paths", "command_available", "artifacts"])?;
        Ok(Self {
            config_paths: strings(fields.get("config_paths"))?,
            command_available: flag(fields, "command_available")?,
            artifacts: artifacts(fields.get("artifacts"))?,
        })
    }

    fn has_guard_config_path(&self) -> bool {
        self.config_paths
            .iter()
            .any(|path| guard_managed_path(path))
    }

    fn guard_managed(&self) -> bool {
        self.has_guard_config_path() || self.artifacts.iter().any(Artifact::uses_guard)
    }

    /// Whether a Guard launcher is the only thing Guard manages for this tool.
    ///
    /// A launcher beside an ordinary, unmanaged tool config leaves the config
    /// paths nonempty, so the config alone cannot tell leftover Guard
    /// configuration from a tool config Guard never touched.
    fn guard_management_is_launcher_only(&self) -> bool {
        if self.has_guard_config_path() {
            return false;
        }
        let managed: Vec<&Artifact<'_>> = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.uses_guard())
            .collect();
        !managed.is_empty()
            && managed
                .iter()
                .all(|artifact| artifact.artifact_type == GUARD_LAUNCHER_SHIM)
    }

    fn only_tool_command_missing(&self, warnings: &[&str]) -> bool {
        // A Guard launcher is kept broken so it stays visible rather than
        // vanishing, whether or not an unmanaged tool config sits beside it.
        if self.command_available || self.config_paths.is_empty() {
            return false;
        }
        if self.guard_management_is_launcher_only() {
            return false;
        }
        !setup_failures_besides_missing_command(warnings)
    }
}

fn added_warnings(
    detection: &Detection<'_>,
    adapter: &Adapter<'_>,
    probe: Option<Probe>,
) -> Vec<String> {
    let harness = adapter.harness;
    let executable = adapter.executable;
    let has_config = !detection.config_paths.is_empty();
    let guard_managed = detection.guard_managed();
    let mut warnings = Vec::new();
    if has_config && !guard_managed {
        warnings.push(format!(
            "{harness} config was found, but Guard is not installed for this harness. \
             Run `hol-guard install {harness}` to enable protection."
        ));
    }
    if guard_managed && !detection.command_available && adapter.command_absence_proves_uninstalled {
        warnings.push(format!(
            "Guard is configured for {harness}, but the {executable} command is not available on \
             this machine. Install {executable}, or run `hol-guard uninstall {harness}` to remove \
             the leftover Guard configuration."
        ));
    } else if guard_managed && !detection.command_available {
        // The tool runs Guard's hooks without its CLI, so the configuration is
        // in use, not left behind: naming it leftover would invite an
        // uninstall that drops live protection.
        warnings.push(format!(
            "Guard is configured for {harness}, but the {executable} command is not available on \
             this machine. Install {executable} to protect {harness} command-line sessions. \
             The configuration is still in use, because {harness} runs Guard's hooks without it."
        ));
    } else if has_config && !detection.command_available {
        warnings.push(format!(
            "{harness} config was found, but the {executable} command is not available on PATH."
        ));
    }
    let probe = probe.unwrap_or_default();
    if probe.timed_out {
        warnings.push(format!(
            "{executable} diagnostics timed out before Guard could confirm runtime state."
        ));
    }
    match harness {
        "copilot" if probe.failed && !probe.timed_out => warnings.push(
            "Copilot CLI was found on PATH, but `copilot --help` did not complete successfully."
                .to_owned(),
        ),
        "cursor"
            if probe.reported_no_artifacts
                && detection
                    .artifacts
                    .iter()
                    .any(|artifact| artifact.artifact_type == "mcp_server") =>
        {
            warnings.push(
                "Cursor CLI reported no MCP servers, but Guard found local definitions. \
                 Cursor may be using a different config root than Guard."
                    .to_owned(),
            );
        }
        "hermes" if probe.managed_install_present && !probe.runtime_hook_registered => warnings
            .push(
            "Hermes runtime hook is not registered. Shell and tool calls are launch-review only. \
             Run `hol-guard install hermes` to write a fail-closed hooks.pre_tool_call entry."
                .to_owned(),
        ),
        _ => {}
    }
    warnings
}

fn setup_status(detection: &Detection<'_>, warnings: &[&str], proves: bool) -> &'static str {
    let guard_managed = detection.guard_managed();
    if guard_managed && warnings_include_setup_failure(warnings) {
        if proves && detection.only_tool_command_missing(warnings) {
            // Guard config left behind for a tool that is no longer installed.
            // Nothing can run unprotected, so report the tool as absent rather
            // than as a broken Guard setup.
            return "not_found";
        }
        return "broken";
    }
    if guard_managed {
        return "active";
    }
    if !detection.config_paths.is_empty() || detection.command_available {
        return "partial";
    }
    "not_found"
}

fn warnings_include_setup_failure(warnings: &[&str]) -> bool {
    warnings.iter().any(|warning| {
        let lowered = warning.to_lowercase();
        SETUP_FAILURE_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
    })
}

/// Whether any warning remains once the one about the missing tool command is
/// set aside. Adapters word their own faults, so anything the missing command
/// does not already explain keeps the setup broken.
fn setup_failures_besides_missing_command(warnings: &[&str]) -> bool {
    warnings
        .iter()
        .any(|warning| !warning.to_lowercase().contains(MISSING_COMMAND_MARKER))
}

fn guard_managed_path(path: &str) -> bool {
    python_path_name(path)
        .to_lowercase()
        .starts_with("hol-guard")
}

/// Guard's per-harness command, `guard-<harness>` (or its `.cmd` wrapper),
/// in either path spelling.
fn is_guard_command_name(value: &str, harness: &str) -> bool {
    let name = python_path_name(&value.replace('\\', "/")).to_lowercase();
    let name = name.strip_suffix(".cmd").unwrap_or(&name);
    name.strip_prefix("guard-") == Some(harness)
}

fn value_mentions_guard(value: &str) -> bool {
    let lowered = value.to_lowercase();
    lowered.contains("codex_plugin_scanner.cli") || lowered.contains("hol-guard")
}

fn artifacts(value: Option<&Value>) -> Result<Vec<Artifact<'_>>, &'static str> {
    chunked(value)?.into_iter().map(Artifact::parse).collect()
}

fn strings(value: Option<&Value>) -> Result<Vec<&str>, &'static str> {
    chunked(value)?
        .into_iter()
        .map(|item| item.as_str().ok_or(ERR_INVALID))
        .collect()
}

/// A list that crossed as chunks, joined back in order.
fn chunked(value: Option<&Value>) -> Result<Vec<&Value>, &'static str> {
    let mut items = Vec::new();
    for chunk in value.and_then(Value::as_array).ok_or(ERR_INVALID)? {
        items.extend(chunk.as_array().ok_or(ERR_INVALID)?);
    }
    Ok(items)
}

fn expect_keys(fields: &Fields, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(())
    } else {
        Err(ERR_INVALID)
    }
}

fn text<'a>(fields: &'a Fields, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn flag(fields: &Fields, key: &str) -> Result<bool, &'static str> {
    fields.get(key).and_then(Value::as_bool).ok_or(ERR_INVALID)
}

#[cfg(test)]
#[path = "harness_diagnostics_tests.rs"]
mod tests;
