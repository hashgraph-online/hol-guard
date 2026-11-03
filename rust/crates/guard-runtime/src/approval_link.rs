//! `approval_link` runner-authority kind: picks the queued approval request a
//! blocked action created and the local review link for it. Ported from
//! `approvals.py` (`primary_approval_request`, `primary_approval_url`,
//! `canonical_local_approval_url`, `attach_primary_approval_link`) and the
//! CLI's `_preferred_approval_review_url`.
//!
//! Display only: a missing link falls back to the approval center and never
//! changes a decision. Python ships each queued item as its `request_id`,
//! `artifact_id`, `approval_url` and `str(harness or "")`, with `null` for an
//! item that is not a mapping, so returned indexes match the caller's list.

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

/// What binds a blocked action to one queued request.
#[derive(Clone, Copy, Default)]
struct Binding<'a> {
    harness: Option<&'a str>,
    request_id: Option<&'a str>,
    artifact_id: Option<&'a str>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let queued = match args.get("queued") {
        Some(Value::Array(items)) => Some(items.as_slice()),
        None | Some(Value::Null) => None,
        Some(_) => return Err(ERR_INVALID),
    };
    let text = |key: &str| args.get(key).and_then(Value::as_str);
    let harness = text("harness");
    let center = text("approval_center_url");
    match text("mode") {
        Some("primary") => {
            let queued = queued.unwrap_or_default();
            let binding = Binding {
                harness,
                request_id: non_empty(text("request_id")),
                artifact_id: non_empty(text("artifact_id")),
            };
            Ok(json!({
                "index": select(queued, binding),
                "url": primary_url(queued, binding, center),
            }))
        }
        Some("attach") => {
            let Some(queued) = queued else {
                return Ok(json!({"request_id": null, "url": null}));
            };
            let ids = match args.get("approval_request_ids") {
                Some(Value::Array(ids)) => ids.as_slice(),
                None | Some(Value::Null) => &[],
                Some(_) => return Err(ERR_INVALID),
            };
            let candidates = [text("request_id"), text("primary_approval_request_id")]
                .into_iter()
                .chain(ids.iter().map(Value::as_str));
            let (request_id, url) = attach(
                queued,
                harness,
                center,
                non_empty(text("artifact_id")).or(non_empty(text("payload_artifact_id"))),
                candidates,
            );
            Ok(json!({"request_id": request_id, "url": url}))
        }
        Some("preferred") => {
            let stripped = |key: &str| text(key).map(py_strip).filter(|value| !value.is_empty());
            let center = stripped("approval_center_url");
            let binding = Binding {
                harness,
                request_id: stripped("primary_approval_request_id"),
                artifact_id: stripped("artifact_id"),
            };
            let url = queued
                .and_then(|queued| preferred_queued_url(queued, binding, center))
                .or_else(|| stripped("primary_approval_url").map(|url| canonical_url(url, center)))
                .or_else(|| center.map(str::to_owned));
            Ok(json!({"url": url}))
        }
        _ => Err(ERR_INVALID),
    }
}

/// Python `_string_or_none`: a non-empty string, unstripped.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

fn field<'a>(item: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    non_empty(item.get(key).and_then(Value::as_str))
}

fn normalize_harness(harness: &str) -> Option<String> {
    let normalized = py_strip(harness).to_lowercase();
    match normalized.as_str() {
        "" => None,
        "claude" => Some("claude-code".to_owned()),
        _ => Some(normalized),
    }
}

/// Index, in the caller's list, of the request this action created.
fn select(queued: &[Value], binding: Binding<'_>) -> Option<usize> {
    let items: Vec<(usize, &Map<String, Value>)> = queued
        .iter()
        .enumerate()
        .filter_map(|(index, item)| item.as_object().map(|item| (index, item)))
        .collect();
    if items.is_empty() {
        return None;
    }
    if let Some(request_id) = binding.request_id {
        return items
            .iter()
            .find(|(_, item)| field(item, "request_id") == Some(request_id))
            .map(|(index, _)| *index);
    }
    if let Some(artifact_id) = binding.artifact_id {
        return items
            .iter()
            .rev()
            .find(|(_, item)| field(item, "artifact_id") == Some(artifact_id))
            .map(|(index, _)| *index);
    }
    if items.len() == 1 {
        return Some(items[0].0);
    }
    let harness = normalize_harness(binding.harness?)?;
    items
        .iter()
        .rev()
        .find(|(_, item)| {
            let item_harness = item.get("harness").and_then(Value::as_str).unwrap_or("");
            normalize_harness(item_harness).as_deref() == Some(harness.as_str())
        })
        .map(|(index, _)| *index)
}

fn primary_url(queued: &[Value], binding: Binding<'_>, center: Option<&str>) -> Option<String> {
    let item = queued.get(select(queued, binding)?)?.as_object()?;
    if let Some(url) = item
        .get("approval_url")
        .and_then(Value::as_str)
        .filter(|url| !py_strip(url).is_empty())
    {
        return Some(canonical_url(url, center));
    }
    let request_id = item
        .get("request_id")
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|id| !id.is_empty())?;
    let center = center.map(py_strip).filter(|center| !center.is_empty())?;
    Some(format!(
        "{}/requests/{request_id}",
        center.trim_end_matches('/')
    ))
}

fn attach<'a>(
    queued: &[Value],
    harness: Option<&str>,
    center: Option<&str>,
    artifact_id: Option<&str>,
    candidates: impl Iterator<Item = Option<&'a str>>,
) -> (Option<String>, Option<String>) {
    let queued_ids: Vec<&str> = queued
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|item| field(item, "request_id"))
        .collect();
    let bound_request_id = candidates
        .filter_map(non_empty)
        .find(|candidate| queued_ids.contains(candidate));
    let by_artifact = Binding {
        harness,
        request_id: None,
        artifact_id,
    };
    let primary = artifact_id
        .and_then(|_| select(queued, by_artifact))
        .or_else(|| {
            select(
                queued,
                Binding {
                    request_id: bound_request_id,
                    ..by_artifact
                },
            )
        });
    let Some(item) = primary.and_then(|index| queued[index].as_object()) else {
        return (None, None);
    };
    let resolved = field(item, "request_id");
    let url = primary_url(
        queued,
        Binding {
            request_id: resolved,
            ..by_artifact
        },
        center,
    );
    (resolved.map(str::to_owned), url)
}

/// The queued review link, retrying without a stale request id, then without
/// an artifact the queue no longer records.
fn preferred_queued_url(
    queued: &[Value],
    binding: Binding<'_>,
    center: Option<&str>,
) -> Option<String> {
    let has_artifact_metadata = queued.iter().filter_map(Value::as_object).any(|item| {
        item.get("artifact_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !py_strip(id).is_empty())
    });
    primary_url(queued, binding, center)
        .or_else(|| {
            binding.artifact_id.and_then(|_| {
                let by_artifact = Binding {
                    request_id: None,
                    ..binding
                };
                primary_url(queued, by_artifact, center)
            })
        })
        .or_else(|| {
            if binding.artifact_id.is_some() && has_artifact_metadata {
                return None;
            }
            let by_harness = Binding {
                harness: binding.harness,
                ..Binding::default()
            };
            primary_url(queued, by_harness, center)
        })
}

/// `scheme`, `netloc` and the rest of a URL, split like Python `urlsplit`,
/// for the shapes this module rewrites. `None` means "leave it unchanged".
struct UrlParts<'a> {
    scheme: &'a str,
    netloc: &'a str,
    rest: &'a str,
}

fn split_url(url: &str) -> Option<UrlParts<'_>> {
    // Python drops tabs and newlines before parsing and normalises non-ASCII
    // hosts; leaving those links unchanged keeps the rewrite exact.
    if url.chars().any(|character| character.is_ascii_control()) {
        return None;
    }
    let (scheme, after) = url.split_once(':')?;
    let after = after.strip_prefix("//")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (netloc, rest) = after.split_at(end);
    if !netloc.is_ascii() {
        return None;
    }
    Some(UrlParts {
        scheme,
        netloc,
        rest,
    })
}

/// Python `_parsed_url_host` for a netloc whose brackets Python accepts. A
/// netloc with brackets anywhere but a leading `[::1]` host is left alone.
fn loopback_host(netloc: &str) -> bool {
    let host_port = netloc.rsplit('@').next().unwrap_or(netloc);
    let host = if netloc.contains(['[', ']']) {
        let single = netloc.matches('[').count() == 1 && netloc.matches(']').count() == 1;
        if !single || !host_port.starts_with("[::1]") {
            return false;
        }
        "::1"
    } else if host_port.matches(':').count() == 1 {
        host_port.split(':').next().unwrap_or("")
    } else {
        host_port
    };
    LOOPBACK_HOSTS.contains(&host)
}

fn local_http(url: &str) -> Option<UrlParts<'_>> {
    let parts = split_url(url)?;
    let web = ["http", "https"]
        .iter()
        .any(|scheme| parts.scheme.eq_ignore_ascii_case(scheme));
    (web && loopback_host(parts.netloc)).then_some(parts)
}

/// Rewrite a stale loopback approval link onto the active local approval
/// center; any other link is returned stripped and otherwise unchanged.
fn canonical_url(approval_url: &str, center: Option<&str>) -> String {
    let approval = py_strip(approval_url);
    let center = center.map(py_strip).filter(|center| !center.is_empty());
    let (Some(link), Some(center)) = (local_http(approval), center.and_then(local_http)) else {
        return approval.to_owned();
    };
    // `urlunparse` drops an empty `;params`, `?query` or `#fragment`.
    let (before_fragment, fragment) = link.rest.split_once('#').unwrap_or((link.rest, ""));
    let (path_params, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    let params_at = path_params.rfind('/').map_or_else(
        || path_params.find(';'),
        |slash| path_params[slash..].find(';').map(|at| slash + at),
    );
    let (url_path, params) = match params_at {
        Some(at) => (&path_params[..at], &path_params[at + 1..]),
        None => (path_params, ""),
    };
    let mut rewritten = format!(
        "{}://{}{url_path}",
        center.scheme.to_ascii_lowercase(),
        center.netloc
    );
    for (separator, part) in [(';', params), ('?', query), ('#', fragment)] {
        if !part.is_empty() {
            rewritten.push(separator);
            rewritten.push_str(part);
        }
    }
    rewritten
}

#[cfg(test)]
#[path = "approval_link_tests.rs"]
mod tests;
