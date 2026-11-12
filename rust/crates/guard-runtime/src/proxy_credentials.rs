//! `proxy-credentials --stdin`: the optional proxy authentication the
//! operating-system credential store holds for one managed proxy, for the
//! Python managed transport's `load_proxy_credentials`.
//!
//! The record is read and shape-checked by
//! `guard_command::egress_proxy_credentials::load_proxy_record`, the same read
//! the native caller uses. The answer carries the credential only on the
//! runtime's own stdout; a record that is not a credential is reported by its
//! code alone, never by its contents.

use std::io::Read;

use guard_command::egress_proxy_credentials::load_proxy_record;
use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "proxy-credentials.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    proxy_url: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "proxy-credentials"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "proxy_credentials_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("proxy_credentials_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "proxy_credentials_request_invalid".to_owned())?;
    if request.schema != SCHEMA || request.proxy_url.is_empty() {
        return Err("proxy_credentials_request_invalid".to_owned());
    }
    serde_json::to_vec(&answer(load_proxy_record(&request.proxy_url)))
        .map_err(|_| "proxy_credentials_response_encode_failed".to_owned())
}

fn answer(
    record: Result<Option<guard_command::egress_caller::EgressProxyCredentials>, &'static str>,
) -> Value {
    match record {
        Ok(None) => json!({"ok": true, "credentials": null}),
        Ok(Some(credentials)) => json!({
            "ok": true,
            "credentials": {"username": credentials.username, "password": credentials.password},
        }),
        Err(reason_code) => json!({"ok": false, "reason_code": reason_code}),
    }
}

#[cfg(test)]
#[path = "proxy_credentials_tests.rs"]
mod tests;
