//! Per-operation ceilings for a caller-supplied resident deadline.
//!
//! Each ceiling records why that operation legitimately outlives the default,
//! so a long but healthy call is not reported as a resident timeout.

use std::time::Duration;

/// Upper bound on a caller-supplied deadline. Operations without a longer
/// ceiling below are capped at nine seconds.
const CLIENT_TIMEOUT_CEILING_MS: u64 = 9_000;
/// Cold daemon-lifecycle startup. Python grants `_TIMEOUT_SECONDS` (10s) plus
/// `_COLD_START_ALLOWANCE_SECONDS` (20s) in `native_daemon_lifecycle.py`.
/// A packaged Windows resident can spend most of that creating the process
/// and scanning the binary before it answers; clamping the request to nine
/// seconds reports `native_resident_start_timeout` while the resident is
/// still starting.
pub(crate) const DAEMON_LIFECYCLE_TIMEOUT_CEILING_MS: u64 = 30_000;
const SKILL_SCAN_TIMEOUT_CEILING_MS: u64 = 60_000;
/// Contained local runners honour the caller's process timeout (up to ten
/// minutes) plus a minute of transport slack for the probe and snapshot, so
/// their budget must not be clamped to the nine-second ceiling that would
/// abort a legitimate test run mid-flight. The
/// package-shim admin op shares it: a probe runs each installed shim under its
/// own per-shim timeout. So does the contained workspace write, whose caller
/// allows the write two minutes.
const CONTAINED_RUNNER_TIMEOUT_CEILING_MS: u64 = 670_000;
/// A contained execute request carries its own process timeout, which the
/// containment contract bounds at one hour. The client adds thirty seconds of
/// transport slack so the resident, not the caller, reports a timed-out child,
/// and clamping that budget to nine seconds would discard the reply of a
/// healthy contained run that was permitted to take longer.
const CONTAINED_EXECUTE_TIMEOUT_CEILING_MS: u64 = 3_630_000;
/// The containment self-probe runs a real contained process under a five
/// second timeout and may spend another five seconds reaping it, so the
/// nine-second default would abort a probe that is still finishing and report
/// containment as unavailable while the backend is in fact healthy.
const CONTAINMENT_HEALTH_PROBE_TIMEOUT_CEILING_MS: u64 = 15_000;
/// A semantic preview resolves every catalog permission against the current,
/// proposed and per-target reverted layers in one call, so Python grants it
/// fifteen seconds (`_PREVIEW_TIMEOUT_SECONDS` in `native_extension_control.py`)
/// where a plain composition or resolution asks for five. Clamping that to the
/// nine-second default would report a healthy preview as a resident timeout.
const EXTENSION_CONTROL_TIMEOUT_CEILING_MS: u64 = 15_000;
/// A Codex resume retry waits up to a minute for the app server to accept
/// the turn and up to its busy timeout for the store; the caller adds five
/// seconds of transport grace.
const CODEX_REQUEST_RESUME_TIMEOUT_CEILING_MS: u64 =
    guard_contracts::CODEX_REQUEST_RESUME_MAX_TIMEOUT_MS
        + guard_contracts::CODEX_REQUEST_RESUME_MAX_BUSY_TIMEOUT_MS
        + 5_000;

pub(crate) fn client_timeout(payload: &[u8]) -> Duration {
    let value = crate::strict_json_value(payload).ok();
    let ceiling = match value
        .as_ref()
        .and_then(|value| value.get("operation")?.as_str())
    {
        Some("skill_directory_identity" | "package_context_build") => SKILL_SCAN_TIMEOUT_CEILING_MS,
        Some(
            "contained_node_execute"
            | "contained_typescript_execute"
            | "contained_package_script_execute"
            | "contained_workspace_write_execute"
            | "shim_admin",
        ) => CONTAINED_RUNNER_TIMEOUT_CEILING_MS,
        Some("contained_execute") => CONTAINED_EXECUTE_TIMEOUT_CEILING_MS,
        Some("containment_health_probe") => CONTAINMENT_HEALTH_PROBE_TIMEOUT_CEILING_MS,
        Some("extension_control") => EXTENSION_CONTROL_TIMEOUT_CEILING_MS,
        Some("codex_request_resume") => CODEX_REQUEST_RESUME_TIMEOUT_CEILING_MS,
        Some("native_bash_execute") => guard_contracts::NATIVE_BASH_EXECUTE_MAX_TIMEOUT_MS + 1_000,
        Some("daemon_lifecycle_decide") => DAEMON_LIFECYCLE_TIMEOUT_CEILING_MS,
        // A store call may wait out its own busy timeout; the caller's
        // deadline still bounds the wait.
        Some("guard_store") => crate::guard_store_op::MAX_BUSY_TIMEOUT_MS + 5_000,
        _ => CLIENT_TIMEOUT_CEILING_MS,
    };
    let budget = value
        .as_ref()
        .and_then(|value| value.get("deadline_budget_ms")?.as_u64())
        .unwrap_or(750)
        .clamp(1, ceiling);
    Duration::from_millis(budget)
}
