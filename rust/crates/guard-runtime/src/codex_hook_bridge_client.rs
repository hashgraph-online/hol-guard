//! The client modes of the Python Codex bridge, served natively.
//!
//! - Codex Desktop (`HOL_GUARD_DESKTOP=1`) forwards hooks exactly as the
//!   terminal client does; only its daemon-start environment differs, and
//!   `hook_bridge_daemon_start` keeps the signed proxy selectors for it. A
//!   transition probe asks the daemon too: Python answers one through the
//!   signed Desktop proxy only from a frozen bundle, which never installs
//!   the native bridge.
//! - An opt-in binding capture records the hook's raw and forwarded
//!   fingerprints as `record_bridge_ingress` does, in process: capture is
//!   diagnostics only and never changes how the hook is settled.
//! - A query the request line cannot carry never reaches the daemon, so the
//!   hook fails closed, as every hook without a daemon answer does.

use super::Prepared;

#[cfg(unix)]
const CAPTURE_MARKER: [&str; 2] = ["diagnostics", "codex-binding-capture.v2.json"];

/// The query goes into the request line verbatim; `http.client` refuses
/// controls, spaces and non-ASCII, so Python never reaches the daemon.
pub(super) fn query_is_sendable(query: &str) -> bool {
    query.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// `record_bridge_ingress` for the hook as it is forwarded, when the private
/// capture marker exists. Best effort: a capture that fails is not recorded
/// and the hook is settled the same way.
#[cfg(unix)]
pub(super) fn record_ingress(state_path: &str, raw_data: &str, prepared: &Prepared) {
    let Some(home) = super::guard_home(state_path) else {
        return;
    };
    let marker = home.join(CAPTURE_MARKER[0]).join(CAPTURE_MARKER[1]);
    if std::fs::symlink_metadata(marker).is_err() {
        return;
    }
    let _ = crate::binding_capture_capture::record_bridge_ingress(
        &home,
        raw_data,
        Some(&prepared.data),
        &prepared.event_name,
        "codex",
        crate::binding_capture_op::now_seconds(),
    );
}

/// Python never captures on Windows.
#[cfg(not(unix))]
pub(super) fn record_ingress(_state_path: &str, _raw_data: &str, _prepared: &Prepared) {}
