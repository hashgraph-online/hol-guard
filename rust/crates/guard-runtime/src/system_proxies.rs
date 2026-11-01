//! `system-proxies --stdin`: the operating system's proxy settings for a
//! managed `proxy_mode = "system"` policy (`mdm/network_transport.py`'s
//! `platform_system_proxies` before it moved here).
//!
//! The settings come from the same reader the native egress caller uses,
//! `guard_command::egress_caller_policy::platform_system_proxies`: macOS
//! `scutil --proxy`, and on Windows `ProxyEnable` and `ProxyServer` under the
//! Internet Settings key, the current user first and the machine second.
//! Environment variables never count, and any other platform, or a probe that
//! fails, has no system proxy.

use std::collections::BTreeMap;
use std::io::Read;

use guard_command::egress_caller_policy::platform_system_proxies;
use serde::Deserialize;
use serde_json::json;

const SCHEMA: &str = "system-proxies.v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "system-proxies"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    answer(reader, platform_system_proxies)
}

fn answer(
    reader: impl Read,
    proxies: impl FnOnce() -> BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "system_proxies_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("system_proxies_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "system_proxies_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("system_proxies_request_invalid".to_owned());
    }
    serde_json::to_vec(&json!({"ok": true, "proxies": proxies()}))
        .map_err(|_| "system_proxies_response_encode_failed".to_owned())
}

#[cfg(test)]
#[path = "system_proxies_tests.rs"]
mod tests;
