//! `mcp_registry_search` runner-authority kind: one bounded, read-only search
//! of the official public MCP server registry.
//!
//! `{"query": str}` fetches one page from the fixed registry origin under the
//! machine's managed network policy, with no redirect followed and no
//! credential attached, and answers `{"listing": {...}}` as
//! [`crate::mcp_registry_page::listing`] reads it, or `{"error": code}`:
//!
//! - `invalid_registry_search`: the query is shorter than 2 or longer than 80
//!   characters once trimmed, or holds a control character;
//! - `registry_unavailable`: the exchange failed, or the answer was not a 200
//!   `application/json` response;
//! - `registry_response_too_large`: the body is over 512,000 bytes;
//! - `registry_response_invalid`: the body is not a well-formed registry page.

use std::collections::BTreeMap;

use guard_command::egress_caller::policy_get_with_headers;
use guard_contracts::EgressOutcomeV1;
use serde_json::{json, Value};

use crate::managed_policy_load::ManagedPolicySource;
use crate::mcp_registry_page::listing;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::runner_sync_url::urlencode;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

/// The only endpoint this kind ever reaches.
const ENDPOINT: &str = "https://registry.modelcontextprotocol.io/v0.1/servers";
const TIMEOUT_SECONDS: f64 = 5.0;
const MAX_BODY_BYTES: usize = 512_000;
const MIN_QUERY_CHARS: usize = 2;
const MAX_QUERY_CHARS: usize = 80;
const PAGE_LIMIT: &str = "20";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let query = args_object(args)?
        .get("query")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let Some(query) = valid_query(query) else {
        return Ok(error("invalid_registry_search"));
    };
    Ok(match fetch(&search_url(query)) {
        Ok((status, headers, body)) => answer(status, &headers, &body),
        Err(code) => error(code),
    })
}

/// The trimmed query, when it is one the registry search accepts.
fn valid_query(query: &str) -> Option<&str> {
    if query.chars().any(|character| u32::from(character) < 32) {
        return None;
    }
    let trimmed = query.trim();
    let length = trimmed.chars().count();
    (MIN_QUERY_CHARS..=MAX_QUERY_CHARS)
        .contains(&length)
        .then_some(trimmed)
}

fn search_url(query: &str) -> String {
    let pairs = [
        ("search".to_owned(), query.to_owned()),
        ("version".to_owned(), "latest".to_owned()),
        ("limit".to_owned(), PAGE_LIMIT.to_owned()),
    ];
    format!("{ENDPOINT}?{}", urlencode(&pairs))
}

type Page = (u16, BTreeMap<String, String>, Vec<u8>);

/// The exchange under the machine's managed network policy, or the error
/// code a failed one answers. The egress layer enforces the byte cap.
fn fetch(url: &str) -> Result<Page, &'static str> {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|_| "registry_unavailable")?;
    let headers = BTreeMap::from([
        ("Accept".to_owned(), "application/json".to_owned()),
        // Identity encoding keeps the byte bound equal to the decoded bound.
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ("User-Agent".to_owned(), crate::daemon_edge::user_agent()),
    ]);
    let cap = u64::try_from(MAX_BODY_BYTES).unwrap_or(u64::MAX);
    policy_get_with_headers(url, headers, TIMEOUT_SECONDS, 0, cap, &policy)
        .map_err(|outcome| failure_code(&outcome))
}

/// An oversize page keeps its own code; every other failure is an outage.
fn failure_code(outcome: &EgressOutcomeV1) -> &'static str {
    match outcome {
        EgressOutcomeV1::Error { message } if message == "response too large" => {
            "registry_response_too_large"
        }
        _ => "registry_unavailable",
    }
}

/// What one fetched page answers. `headers` names are lowercased.
fn answer(status: u16, headers: &BTreeMap<String, String>, body: &[u8]) -> Value {
    let media_type = headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    if status != 200 || media_type.as_deref() != Some("application/json") {
        return error("registry_unavailable");
    }
    if body.len() > MAX_BODY_BYTES {
        return error("registry_response_too_large");
    }
    match listing(body) {
        Some(listing) => json!({ "listing": listing }),
        None => error("registry_response_invalid"),
    }
}

fn error(code: &str) -> Value {
    json!({ "error": code })
}

#[cfg(test)]
#[path = "mcp_registry_search_tests.rs"]
mod tests;
