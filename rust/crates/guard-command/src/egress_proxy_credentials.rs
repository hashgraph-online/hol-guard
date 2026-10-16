//! Managed proxy authentication from the native operating-system credential store.
//!
//! Port of `mdm/network_credentials.py` and `load_proxy_credentials`
//! (mdm/network_transport.py:199). The record is keyed by the digest of the
//! already-validated proxy URL, so the store holds authorization for one proxy
//! endpoint and nothing else: never a policy secret, never a credential for the
//! destination. Nothing here ever logs or returns the record's contents in an
//! error - a malformed record is reported by code alone.

use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::egress_caller::EgressProxyCredentials;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::egress_caller_policy::probe_output;

/// `_PROXY_CREDENTIAL_SERVICE` (mdm/network_credentials.py:11).
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
const PROXY_CREDENTIAL_SERVICE: &str = "hol-guard-enterprise-proxy-v1";
/// `_MAX_PROXY_CREDENTIAL_BYTES`: past this the record is malformed, not a
/// credential, and the policy fails closed rather than exchanging without it.
const MAX_PROXY_CREDENTIAL_BYTES: usize = 16 * 1024;

/// `proxy_credential_key` (mdm/network_transport.py:195): the account the
/// record is stored under, so the store never holds the proxy URL itself.
pub fn proxy_credential_key(proxy_url: &str) -> String {
    hex::encode(Sha256::digest(proxy_url.as_bytes()))
}

/// The proxy-only credentials the store holds for this proxy, if any.
///
/// `Ok(None)` is the ordinary answer: no record, so the exchange goes through
/// the proxy unauthenticated. `Err` is a record that exists but is not a
/// credential, which must fail the evaluation closed.
pub fn load_proxy_credentials(
    proxy_url: &str,
) -> Result<Option<EgressProxyCredentials>, &'static str> {
    let Some(raw) = read_proxy_credential_record(&proxy_credential_key(proxy_url)) else {
        return Ok(None);
    };
    if raw.len() > MAX_PROXY_CREDENTIAL_BYTES {
        return Err("managed_proxy_credentials_invalid");
    }
    parse_proxy_credentials(&raw).map(Some)
}

/// The record's own shape: exactly `username` and `password`, both non-empty
/// strings, with no `:` in the username and no newline in either - a credential
/// that cannot be spelled into a `Proxy-Authorization` header is refused here
/// rather than truncated into one.
fn parse_proxy_credentials(raw: &[u8]) -> Result<EgressProxyCredentials, &'static str> {
    let invalid = "managed_proxy_credentials_invalid";
    let payload: serde_json::Value = serde_json::from_slice(raw).map_err(|_| invalid)?;
    let object = payload.as_object().ok_or(invalid)?;
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if keys != BTreeSet::from(["username", "password"]) {
        return Err(invalid);
    }
    let username = object["username"].as_str().ok_or(invalid)?;
    let password = object["password"].as_str().ok_or(invalid)?;
    if username.is_empty()
        || username.contains([':', '\r', '\n'])
        || password.is_empty()
        || password.contains(['\r', '\n'])
    {
        return Err(invalid);
    }
    // ureq carries proxy authorization in the proxy's own URI and reads the
    // username and password back out of that authority verbatim, with no
    // percent-decoding (ureq-3.3.0 src/proxy.rs:436, src/unversioned/transport/
    // connect.rs:113). A credential holding a character that a URI authority
    // does not carry literally would reach the proxy as something other than
    // what the store holds, so it is refused by a code of its own rather than
    // mangled, dropped, or sent as a different credential.
    if !username.bytes().all(uri_userinfo_byte) || !password.bytes().all(uri_userinfo_byte) {
        return Err("managed_proxy_credentials_unsupported");
    }
    Ok(EgressProxyCredentials {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

/// The bytes a URI authority carries literally: RFC 3986 `unreserved` and
/// `sub-delims`, plus `:`, which separates the username from the password and
/// is already refused inside a username but may appear in a password.
fn uri_userinfo_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:".contains(&byte)
}

/// `read_proxy_credential_record` (mdm/network_credentials.py:121): one bounded
/// read of the platform's own credential store, or `None` where there is no
/// record and on every failure to reach it.
#[cfg(target_os = "macos")]
fn read_proxy_credential_record(account: &str) -> Option<Vec<u8>> {
    read_keychain(account)
}

#[cfg(target_os = "linux")]
fn read_proxy_credential_record(account: &str) -> Option<Vec<u8>> {
    read_secret_tool(account)
}

/// Windows stores the record through `CredReadW`, which the native caller does
/// not read yet, so a proxy that demands authentication there answers 407
/// rather than being reached with a guessed credential.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_proxy_credential_record(_account: &str) -> Option<Vec<u8>> {
    None
}

/// `/usr/bin/security find-generic-password -s <service> -a <account> -w`.
#[cfg(target_os = "macos")]
fn read_keychain(account: &str) -> Option<Vec<u8>> {
    let raw = probe_output(
        OsStr::new("/usr/bin/security"),
        &[
            "find-generic-password",
            "-s",
            PROXY_CREDENTIAL_SERVICE,
            "-a",
            account,
            "-w",
        ],
        MAX_PROXY_CREDENTIAL_BYTES,
    )?;
    present(raw)
}

/// `secret-tool lookup service <service> account <account>`, from its absolute
/// path: the Python port requires `/usr/bin/secret-tool` to be a file and runs
/// that, never whatever the search path offers.
#[cfg(target_os = "linux")]
fn read_secret_tool(account: &str) -> Option<Vec<u8>> {
    let executable = Path::new("/usr/bin/secret-tool");
    if !executable.is_file() {
        return None;
    }
    let raw = probe_output(
        executable.as_os_str(),
        &[
            "lookup",
            "service",
            PROXY_CREDENTIAL_SERVICE,
            "account",
            account,
        ],
        MAX_PROXY_CREDENTIAL_BYTES,
    )?;
    present(raw)
}

/// `value.rstrip("\r\n") or None`: the store's trailing newline is not part of
/// the record, and an empty record is no record.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
fn present(mut raw: Vec<u8>) -> Option<Vec<u8>> {
    while matches!(raw.last(), Some(b'\r' | b'\n')) {
        raw.pop();
    }
    (!raw.is_empty()).then_some(raw)
}

#[cfg(test)]
#[path = "egress_proxy_credentials_tests.rs"]
mod tests;
