//! `runner_authority` kind `hermes_install_plan`: what a Hermes install or
//! uninstall writes into `config.yaml` beyond the runtime hooks
//! (`hermes_hook_config` owns those).
//!
//! Python keeps the YAML I/O, the Guard store read and the manifests. Answers
//! index into the caller's own lists, so user entries are never rebuilt here
//! and their key order survives the YAML round trip.
//!
//! - `servers`: which `mcp_servers` entries to keep and the `guard-` keys to
//!   add for the overlay. Guard's entries are named by the managed-servers
//!   manifest, not by prefix, so a user server that happens to start with
//!   `guard-` is kept. Uninstall passes no overlay.
//! - `overlay_names`: the overlay name for each source server, its own name
//!   when free and a scoped `<key>-<n>` otherwise.
//! - `consumer_base_url`: the Guard Cloud consumer API URL, from the origin of
//!   the connected OAuth issuer that Python reads from the Guard store.
//! - `guard_section`: the `guard` section that turns on Hermes's runtime
//!   policy, as ordered `[key, value]` pairs.
//! - `install_state`: whether the install is new, already managed or a repair.
//!   The OpenClaw overlay bundle asks the same question of its own manifest.
//!
//! Python's `urlsplit` raised on an issuer with an unbalanced IPv6 bracket,
//! which failed the install; that issuer now falls back to the default URL.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SERVER_PREFIX: &str = "guard-";
const DEFAULT_CONSUMER_BASE_URL: &str = "https://hol.org/api/v1/consumer";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("servers") => servers(fields),
        Some("overlay_names") => overlay_names(fields),
        Some("consumer_base_url") => consumer_base_url_op(fields),
        Some("guard_section") => guard_section(fields),
        Some("install_state") => install_state(fields),
        _ => Err(ERR_INVALID),
    }
}

/// `mcp_servers` keys arrive in order, `null` for a key that is not a string;
/// Python drops those, as it did before.
fn servers(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "names", "managed", "overlay"])?;
    let managed: BTreeSet<String> = strings(&fields["managed"])?.into_iter().collect();
    let keep: Vec<usize> = array(&fields["names"])?
        .iter()
        .enumerate()
        .map(|(index, name)| match name {
            Value::Null => Ok(None),
            Value::String(name) => Ok((!managed.contains(name)).then_some(index)),
            _ => Err(ERR_INVALID),
        })
        .filter_map(Result::transpose)
        .collect::<Result<_, _>>()?;
    let add: Vec<String> = strings(&fields["overlay"])?
        .into_iter()
        .map(|name| format!("{SERVER_PREFIX}{name}"))
        .collect();
    Ok(json!({"keep": keep, "add": add}))
}

/// `_overlay_name` over every source server, sharing one set of names in use.
/// Each item is `[server_key, name]`, `name` being `null` unless a string.
fn overlay_names(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "servers"])?;
    let mut in_use = BTreeSet::new();
    let mut names = Vec::new();
    for server in array(&fields["servers"])? {
        let [key, name] = server.as_array().map(Vec::as_slice).ok_or(ERR_INVALID)? else {
            return Err(ERR_INVALID);
        };
        let key = key.as_str().ok_or(ERR_INVALID)?;
        let name = match name {
            Value::Null => None,
            Value::String(name) => Some(name.as_str()).filter(|name| !name.is_empty()),
            _ => return Err(ERR_INVALID),
        };
        let candidate = name.unwrap_or(key);
        let chosen = if in_use.contains(candidate) {
            let base = key.replace(':', "-");
            let mut scoped = base.clone();
            let mut suffix = 2;
            while in_use.contains(&scoped) {
                scoped = format!("{base}-{suffix}");
                suffix += 1;
            }
            scoped
        } else {
            candidate.to_owned()
        };
        in_use.insert(chosen.clone());
        names.push(chosen);
    }
    Ok(json!({ "names": names }))
}

fn consumer_base_url_op(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "issuer"])?;
    let issuer = match &fields["issuer"] {
        Value::Null => None,
        Value::String(issuer) => Some(issuer.as_str()),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({ "base_url": consumer_base_url(issuer) }))
}

fn guard_section(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &["op", "base_url", "timeout_seconds"])?;
    let base_url = fields["base_url"].as_str().ok_or(ERR_INVALID)?;
    let timeout = fields["timeout_seconds"].as_u64().ok_or(ERR_INVALID)?;
    Ok(json!({
        "section": [
            ["enabled", true],
            ["base_url", base_url],
            ["timeout_seconds", timeout],
            ["cache_ttl_seconds", 60],
            ["fail_open", false],
            ["token_env_var", "HERMES_GUARD_TOKEN"],
            ["enforce_mcp_tools", true],
            ["pain_signals_enabled", true],
        ],
    }))
}

/// `_resolve_guard_consumer_base_url` after the store read: the issuer's
/// `{scheme}://{netloc}` as `urllib.parse.urlsplit` splits it.
pub(crate) fn consumer_base_url(issuer: Option<&str>) -> String {
    let Some(issuer) = issuer.map(py_strip).filter(|issuer| !issuer.is_empty()) else {
        return DEFAULT_CONSUMER_BASE_URL.to_owned();
    };
    let url: String = issuer
        .trim_start_matches(|ch: char| ch <= ' ')
        .chars()
        .filter(|ch| !matches!(ch, '\t' | '\r' | '\n'))
        .collect();
    let (scheme, rest) = match url.find(':') {
        Some(colon)
            if colon > 0
                && url[..colon].starts_with(|ch: char| ch.is_ascii_alphabetic())
                && url[..colon]
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) =>
        {
            (url[..colon].to_ascii_lowercase(), &url[colon + 1..])
        }
        _ => return DEFAULT_CONSUMER_BASE_URL.to_owned(),
    };
    let Some(after) = rest.strip_prefix("//") else {
        return DEFAULT_CONSUMER_BASE_URL.to_owned();
    };
    let netloc = &after[..after.find(['/', '?', '#']).unwrap_or(after.len())];
    let bracketed = netloc.contains('[');
    if netloc.is_empty()
        || bracketed != netloc.contains(']')
        || (bracketed && !bracketed_netloc_valid(netloc))
    {
        return DEFAULT_CONSUMER_BASE_URL.to_owned();
    }
    format!("{scheme}://{netloc}/api/v1/consumer")
}

/// `urlsplit`'s `_check_bracketed_netloc`: the host after the last `@` must
/// be a bracketed IPv6 (optionally scoped) or IPvFuture address.
fn bracketed_netloc_valid(netloc: &str) -> bool {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, tail)| tail);
    let hostname = match host_port.split_once('[') {
        Some(("", inner)) => {
            let (hostname, port) = inner.split_once(']').unwrap_or((inner, ""));
            if !port.is_empty() && !port.starts_with(':') {
                return false;
            }
            hostname
        }
        Some(_) => return false,
        None => host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host),
    };
    if let Some(future) = hostname.strip_prefix('v') {
        return future.split_once('.').is_some_and(|(version, rest)| {
            !version.is_empty()
                && version.chars().all(|ch| ch.is_ascii_hexdigit())
                && !rest.is_empty()
        });
    }
    let (address, scope) = hostname
        .split_once('%')
        .map_or((hostname, None), |(a, s)| (a, Some(s)));
    scope.is_none_or(|scope| !scope.is_empty() && !scope.contains('%'))
        && address.parse::<std::net::Ipv6Addr>().is_ok()
}

fn install_state(fields: &Map<String, Value>) -> KindResult {
    exact_keys(
        fields,
        &["op", "manifest_empty", "overlay_exists", "pretool_exists"],
    )?;
    let flag = |key: &str| fields[key].as_bool().ok_or(ERR_INVALID);
    let (manifest_empty, overlay, pretool) = (
        flag("manifest_empty")?,
        flag("overlay_exists")?,
        flag("pretool_exists")?,
    );
    let state = if manifest_empty {
        "installed"
    } else if overlay && pretool {
        "already_managed"
    } else {
        "repaired_managed_install"
    };
    Ok(json!({ "state": state }))
}

fn array(value: &Value) -> Result<&[Value], &'static str> {
    value.as_array().map(Vec::as_slice).ok_or(ERR_INVALID)
}

fn strings(value: &Value) -> Result<Vec<String>, &'static str> {
    array(value)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

fn exact_keys(fields: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() == keys.len() && keys.iter().all(|key| fields.contains_key(*key)) {
        Ok(())
    } else {
        Err(ERR_INVALID)
    }
}

#[cfg(test)]
#[path = "hermes_install_plan_tests.rs"]
mod tests;
