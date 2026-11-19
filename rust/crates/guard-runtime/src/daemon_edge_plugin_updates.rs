//! `GET /v1/plugins/updates`: the plugins installed here compared with the
//! releases their authors checked on HOL, by
//! [`crate::plugin_telemetry_host::check_updates`].

use std::path::Path;

use serde_json::{json, Value};

use super::ReadConfig;
use crate::plugin_telemetry_host::{check_updates, LiveHol};

/// The route's answer, or `None` when the daemon names no user home to find
/// the agent runtimes under.
pub(in crate::daemon_edge) fn read(config: &ReadConfig) -> Option<(u16, Value)> {
    let home = config.user_home.as_deref()?;
    Some(
        match check_updates(&LiveHol, Path::new(home), &config.guard_home) {
            Ok(result) => (200, result),
            Err(message) => (
                503,
                json!({"error": "plugin_updates_unavailable", "message": message}),
            ),
        },
    )
}
