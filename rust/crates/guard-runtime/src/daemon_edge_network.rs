//! `GET /v1/network/status`, answered as `build_network_status` answers it
//! for the daemon: the default platform profiles, the host's `sys.platform`,
//! and the supervisor's health. The daemon's supervisor never receives a
//! backend advertisement, so its health is always the unavailable phase.

use serde_json::{json, Value};

/// `sys.platform` for this build, or `None` where Python would name a
/// platform this edge does not know how to spell.
fn python_platform() -> Option<&'static str> {
    match std::env::consts::OS {
        "macos" => Some("darwin"),
        "linux" => Some("linux"),
        "windows" => Some("win32"),
        _ => None,
    }
}

/// `default_platform_profiles()`.
fn default_profiles() -> Value {
    let profile = |backend_id: &str,
                   platform: &str,
                   maximum_grade: &str,
                   requires_privilege: bool,
                   reason_code: &str| {
        json!({
            "backend_id": backend_id,
            "platform": platform,
            "maximum_grade": maximum_grade,
            "production_ready": false,
            "requires_privilege": requires_privilege,
            "reason_code": reason_code,
        })
    };
    json!([
        profile(
            "linux.oci-proxy",
            "linux",
            "proxy-only",
            true,
            "alpha-not-validated"
        ),
        profile(
            "macos.observe",
            "macos",
            "observe",
            false,
            "feasibility-pending"
        ),
        profile(
            "windows.observe",
            "windows",
            "observe",
            false,
            "feasibility-pending"
        ),
        profile(
            "kubernetes.network-policy",
            "kubernetes",
            "deny-all",
            true,
            "provider-pending"
        ),
    ])
}

/// `project_network_supervisor_health(NetworkSupervisor().health(...))`.
fn supervisor_health() -> Value {
    json!({
        "phase": "unavailable",
        "backend_id": null,
        "backend_digest": null,
        "effective_grade": "unavailable",
        "healthy_until_epoch_ms": null,
        "retry_attempt": 0,
        "next_retry_seconds": 0.0,
        "permits_enforcement": false,
        "independently_observed": false,
    })
}

/// The status body, or `None` to leave the route to the daemon.
pub(in crate::daemon_edge) fn status() -> Option<(u16, Value)> {
    let request = json!({
        "platform": python_platform()?,
        "profiles": default_profiles(),
        "explicit": false,
        "host_only": false,
        "supervisor": supervisor_health(),
        "legacy_domain_policy": null,
    });
    crate::network_status_build::dispatch(&request)
        .ok()
        .map(|body| (200, body))
}

#[cfg(test)]
#[path = "daemon_edge_network_tests.rs"]
mod tests;
