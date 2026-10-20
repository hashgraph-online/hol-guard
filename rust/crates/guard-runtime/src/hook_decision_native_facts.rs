//! Verdicts the resident computes itself from the raw tool call.
//!
//! The transport forwards the payload's tool call and observed caller facts in
//! `native_request`; nothing here asks Python. A missing or oversized request
//! is "not benign", so the configured default is never relaxed on bad input.

use std::cell::Cell;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use guard_command::benign_request_api::{
    is_benign_native_file_read, is_benign_tool_action, ToolActionControls,
};
use guard_command::command_evaluation_controls::{
    authority_failure_for_health, control_layers_from_wire,
};
use guard_command::Ctx;
use guard_contracts::{CodexToolOutputFactsV1, HookCompositionInputsV1};

use crate::codex_tool_output_op::ResidentInspectionHost;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_ENVIRONMENT: usize = 128;
const MAX_GROUPS: usize = 256;

fn path_is_bounded(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn host_is_bounded(host: &CodexToolOutputFactsV1) -> bool {
    path_is_bounded(&host.process_cwd)
        && path_is_bounded(&host.home)
        && host.account_home.as_deref().is_none_or(path_is_bounded)
        && host.git_executable.as_deref().is_none_or(path_is_bounded)
        && host.groups.len() <= MAX_GROUPS
        && host.environment.len() <= MAX_ENVIRONMENT
        && host
            .environment
            .iter()
            .all(|(key, value)| key.len() <= 256 && path_is_bounded(value))
}

/// `is_explicitly_benign_native_file_read_request` for the hook's tool call.
pub(crate) fn benign_native_file_read(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
    {
        return false;
    }
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_native_file_read(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
    )
}

/// Handing one composition's tool-action verdict to the composition that
/// finishes the same hook.
///
/// One hook asks for the verdict twice: `compose_current` settles the current
/// action and `finalize` composes again over the same inputs to reach the
/// final one. For a `git` command the verdict runs the native Git proofs,
/// which spawn `git` to read the repository's effective configuration, so the
/// second ask repeats every probe the first one made and costs as much.
///
/// What makes the second ask safe to answer from the first is that no tool
/// has run in between: Guard has not decided yet, so the agent cannot have
/// changed the repository the proofs read. That holds only inside one hook,
/// so the handoff is built to be unusable outside one:
///
/// * only a `ComposeCurrent` query records, and only a `Finalize` query may
///   take; every other caller computes and records nothing;
/// * one slot, so a recording composition always displaces whatever the last
///   one left, and a later hook's `ComposeCurrent` clears the slot before its
///   own `Finalize` can read it;
/// * taking empties the slot, matching key or not, so no verdict is ever read
///   twice;
/// * the key is the canonical digest of the whole input, so a different
///   command, directory, environment or control snapshot can never take this
///   verdict; and
/// * an entry expires regardless, bounding anything the rules above miss.
const VERDICT_HANDOFF_WINDOW: Duration = Duration::from_secs(2);

/// Inputs whose canonical form is larger than this are not worth a key: the
/// classifier rejects an oversized tool call as not benign anyway, so the
/// handoff declines rather than encode megabytes to say so.
const VERDICT_KEY_LIMIT: usize = 256 * 1024;

/// What the composition running on this thread may do with the slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum VerdictHandoff {
    /// Compute, and leave nothing behind. Every caller but the two queries.
    Off,
    /// Compute and record, displacing whatever the slot held.
    Record,
    /// Take this hook's own recorded verdict, else compute.
    Take,
}

thread_local! {
    static HANDOFF: Cell<VerdictHandoff> = const { Cell::new(VerdictHandoff::Off) };
}

/// Restores the enclosing mode, so a query cannot leak its own onto the next
/// request this thread serves.
pub(crate) struct VerdictHandoffScope(VerdictHandoff);

impl Drop for VerdictHandoffScope {
    fn drop(&mut self) {
        HANDOFF.with(|mode| mode.set(self.0));
    }
}

pub(crate) fn verdict_handoff(mode: VerdictHandoff) -> VerdictHandoffScope {
    VerdictHandoffScope(HANDOFF.with(|current| current.replace(mode)))
}

static RECORDED_VERDICT: Mutex<Option<(String, Instant, bool)>> = Mutex::new(None);

/// Whether the slot holds a verdict for `inputs`, without taking it. For
/// tests that assert what the handoff holds rather than time what it saves.
#[cfg(all(test, unix))]
pub(crate) fn verdict_is_recorded_after(inputs: &HookCompositionInputsV1, after: Duration) -> bool {
    let Some(key) = verdict_key(inputs) else {
        return false;
    };
    let now = Instant::now() + after;
    let Ok(slot) = RECORDED_VERDICT.lock() else {
        return false;
    };
    slot.as_ref().is_some_and(|(entry, at, _)| {
        entry == &key && now.duration_since(*at) < VERDICT_HANDOFF_WINDOW
    })
}

#[cfg(all(test, unix))]
pub(crate) fn verdict_is_recorded(inputs: &HookCompositionInputsV1) -> bool {
    verdict_is_recorded_after(inputs, Duration::ZERO)
}

/// The canonical digest of `inputs`, or `None` when it cannot be formed within
/// the key limit — in which case the verdict is computed and nothing is
/// recorded.
fn verdict_key(inputs: &HookCompositionInputsV1) -> Option<String> {
    let material = serde_json::to_value(inputs).ok()?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(
        &material,
        &mut bytes,
        VERDICT_KEY_LIMIT,
    )
    .ok()?;
    Some(guard_policy_snapshot::digest_bytes(&bytes))
}

/// Empties the slot and returns what it held, when that was this composition's
/// own verdict and still inside the window.
fn take_verdict(key: Option<&str>, now: Instant) -> Option<bool> {
    let mut slot = RECORDED_VERDICT.lock().ok()?;
    let held = slot.take()?;
    let (entry, at, verdict) = held;
    (Some(entry.as_str()) == key && now.duration_since(at) < VERDICT_HANDOFF_WINDOW)
        .then_some(verdict)
}

/// Replaces whatever the slot held. A composition with no usable key clears it
/// rather than leaving the previous entry readable.
fn record_verdict(key: Option<String>, now: Instant, verdict: bool) {
    let Ok(mut slot) = RECORDED_VERDICT.lock() else {
        return;
    };
    *slot = key.map(|key| (key, now, verdict));
}

/// Whether the hook's tool call can be a verified non-sensitive Codex patch.
///
/// This is the structural half of
/// `runtime_artifact_verified_non_sensitive_apply_patch`: the harness, the
/// artifact check, the tool name, and the patch text itself, all of which the
/// resident reads off the request it was given. Only when every one of them
/// holds is the transport asked whether the patch's target paths are
/// non-sensitive, which is the half that needs the host's filesystem. A patch
/// that deletes or moves a file is never verified here, and a request the
/// transport could not observe is not a patch that can be verified.
pub(crate) fn apply_patch_may_be_verified(inputs: &HookCompositionInputsV1) -> bool {
    if !inputs.runtime_artifact_checked || inputs.canonical_harness != "codex" {
        return false;
    }
    let Some(request) = &inputs.native_request else {
        return false;
    };
    if request
        .tool_name
        .as_str()
        .map(|name| name.trim().to_ascii_lowercase())
        .as_deref()
        != Some("apply_patch")
    {
        return false;
    }
    let Some(tool_input) = request.tool_input.as_object() else {
        return false;
    };
    let texts: Vec<&str> = ["patch", "input", "command"]
        .into_iter()
        .filter_map(|key| tool_input.get(key).and_then(|value| value.as_str()))
        .filter(|text| !text.trim().is_empty())
        .collect();
    !texts.is_empty()
        && !texts
            .iter()
            .any(|text| text.contains("*** Delete File:") || text.contains("*** Move to:"))
}

/// `is_explicitly_benign_tool_action_request` for the hook's tool call.
///
/// The extension-control snapshot the transport saw is the one that applies;
/// an unknown health value or any input that cannot be bounded is not benign.
pub(crate) fn benign_tool_action(inputs: &HookCompositionInputsV1) -> bool {
    // Without a request there is no proof to run and so nothing to hand on.
    if inputs.native_request.is_none() {
        return false;
    }
    let mode = HANDOFF.with(Cell::get);
    if mode == VerdictHandoff::Off {
        return compute_benign_tool_action(inputs);
    }
    let now = Instant::now();
    let key = verdict_key(inputs);
    if mode == VerdictHandoff::Take {
        // Empties the slot either way, so one verdict is never read twice.
        return match take_verdict(key.as_deref(), now) {
            Some(verdict) => verdict,
            None => compute_benign_tool_action(inputs),
        };
    }
    let verdict = compute_benign_tool_action(inputs);
    record_verdict(key, now, verdict);
    verdict
}

fn compute_benign_tool_action(inputs: &HookCompositionInputsV1) -> bool {
    let Some(request) = &inputs.native_request else {
        return false;
    };
    let bounded_path = |value: &Option<String>| value.as_deref().is_none_or(path_is_bounded);
    if !host_is_bounded(&request.host)
        || !bounded_path(&request.cwd)
        || !bounded_path(&request.home_dir)
        || request.tool_input.to_string().len() > MAX_TEXT_BYTES
    {
        return false;
    }
    let controls = match &request.control_snapshot {
        None => None,
        Some(snapshot) => {
            let Ok(authority_failure) = authority_failure_for_health(&snapshot.health) else {
                return false;
            };
            let Ok(layers) = control_layers_from_wire(&snapshot.layers) else {
                return false;
            };
            Some(ToolActionControls {
                layers,
                authority_failure,
            })
        }
    };
    let host = ResidentInspectionHost {
        facts: &request.host,
    };
    let ctx = Ctx::new(&host, &request.host.process_cwd, &request.host.home);
    is_benign_tool_action(
        &request.tool_name,
        &request.tool_input,
        request.cwd.as_deref().map(Path::new),
        request.home_dir.as_deref().map(Path::new),
        &ctx,
        controls.as_ref(),
    )
}
