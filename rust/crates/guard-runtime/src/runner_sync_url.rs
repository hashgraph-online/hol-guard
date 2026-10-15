//! Guard Cloud sync endpoint derivation for `RunnerAuthority`.
//!
//! Replaces the Python `urllib.parse` based normalizers that decided which
//! cloud endpoint receipts, sessions, events, pain signals and supply-chain
//! bundles are sent to. The split and join rules mirror CPython's
//! `urlsplit`/`urlunsplit`/`parse_qsl`/`urlencode` so a normalised URL is
//! byte-identical to what the retired Python produced.

use serde_json::{json, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const RECEIPTS_SYNC: &str = "/guard/receipts/sync";
const REGISTRY_RECEIPTS_SYNC: &str = "/registry/api/v1/guard/receipts/sync";
const API_RECEIPTS_SYNC: &str = "/api/guard/receipts/sync";
const USES_NETLOC: [&str; 25] = [
    "", "ftp", "http", "gopher", "nntp", "telnet", "imap", "wais", "file", "mms", "https", "shttp",
    "snews", "prospero", "rtsp", "rtspu", "rsync", "svn", "svn+ssh", "sftp", "nfs", "git",
    "git+ssh", "ws", "wss",
];

struct Split {
    scheme: String,
    netloc: String,
    path: String,
    query: String,
    fragment: String,
}

fn urlsplit(raw: &str) -> Split {
    let trimmed = raw.trim_start_matches(|c: char| c <= ' ');
    let cleaned: String = trimmed
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut scheme = String::new();
    if let Some(colon) = rest.find(':') {
        let head = &rest[..colon];
        let valid = head.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && head
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if colon > 0 && valid {
            scheme = head.to_ascii_lowercase();
            rest = &rest[colon + 1..];
        }
    }
    let mut netloc = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = after[..end].to_owned();
        rest = &after[end..];
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    Split {
        scheme,
        netloc,
        path: path.to_owned(),
        query: query.to_owned(),
        fragment: fragment.to_owned(),
    }
}

fn urlunsplit(scheme: &str, netloc: &str, path: &str, query: &str, fragment: &str) -> String {
    let mut url = path.to_owned();
    if !netloc.is_empty() {
        if !url.is_empty() && !url.starts_with('/') {
            url.insert(0, '/');
        }
        url = format!("//{netloc}{url}");
    } else if url.starts_with("//")
        || (!scheme.is_empty()
            && USES_NETLOC.contains(&scheme)
            && (url.is_empty() || url.starts_with('/')))
    {
        url = format!("//{url}");
    }
    if !scheme.is_empty() {
        url = format!("{scheme}:{url}");
    }
    if !query.is_empty() {
        url = format!("{url}?{query}");
    }
    if !fragment.is_empty() {
        url = format!("{url}#{fragment}");
    }
    url
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.unquote` (UTF-8, `errors="replace"`).
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `urllib.parse.quote_plus` with no extra safe characters.
fn quote_plus(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// `parse_qsl(query, keep_blank_values=True)`.
fn parse_qsl(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                unquote(&name.replace('+', " ")),
                unquote(&value.replace('+', " ")),
            )
        })
        .collect()
}

fn urlencode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", quote_plus(key), quote_plus(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn rstrip_slash(path: &str) -> &str {
    path.trim_end_matches('/')
}

fn with_path(parsed: &Split, path: &str, query: &str, fragment: &str) -> String {
    urlunsplit(&parsed.scheme, &parsed.netloc, path, query, fragment)
}

fn pain_signal(url: &str) -> String {
    let parsed = urlsplit(url);
    let segments: Vec<&str> = rstrip_slash(&parsed.path)
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let keep = match segments.as_slice() {
        [.., "receipts", "sync"] | [.., "inventory", "sync"] => segments.len() - 2,
        [.., "receipts"] | [.., "inventory"] => segments.len() - 1,
        _ => segments.len(),
    };
    let mut next: Vec<&str> = segments[..keep].to_vec();
    next.extend(["signals", "pain"]);
    with_path(
        &parsed,
        &format!("/{}", next.join("/")),
        &parsed.query,
        &parsed.fragment,
    )
}

fn receipts(url: &str) -> String {
    let parsed = urlsplit(url);
    if rstrip_slash(&parsed.path) == "/registry/api/v1" {
        return with_path(
            &parsed,
            "/registry/api/v1/guard/receipts/sync",
            &parsed.query,
            "",
        );
    }
    url.to_owned()
}

fn runtime_sessions(url: &str) -> String {
    let parsed = urlsplit(&receipts(url));
    let path = rstrip_slash(&parsed.path);
    let next = match path {
        REGISTRY_RECEIPTS_SYNC => "/registry/api/v1/guard/runtime/sessions/sync".to_owned(),
        API_RECEIPTS_SYNC => "/api/guard/runtime/sessions/sync".to_owned(),
        RECEIPTS_SYNC => "/guard/runtime/sessions/sync".to_owned(),
        other => format!("{other}/runtime/sessions/sync"),
    };
    with_path(&parsed, &next, &parsed.query, "")
}

fn supply_chain_bundle(url: &str, workspace_id: &str) -> String {
    let parsed = urlsplit(&receipts(url));
    let path = rstrip_slash(&parsed.path);
    let next = match path {
        REGISTRY_RECEIPTS_SYNC => "/registry/api/v1/guard/supply-chain/bundle".to_owned(),
        API_RECEIPTS_SYNC => "/api/guard/supply-chain/bundle".to_owned(),
        RECEIPTS_SYNC => "/guard/supply-chain/bundle".to_owned(),
        other => format!("{other}/supply-chain/bundle"),
    };
    let mut pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
        .into_iter()
        .filter(|(key, _)| key != "workspaceId")
        .collect();
    pairs.push(("workspaceId".to_owned(), workspace_id.to_owned()));
    with_path(&parsed, &next, &urlencode(&pairs), "")
}

fn supply_chain_index(url: &str) -> String {
    let parsed = urlsplit(url);
    let path = format!("{}/index", rstrip_slash(&parsed.path));
    with_path(&parsed, &path, &parsed.query, "")
}

fn supply_chain_partition(url: &str, ecosystem: &str, partition: i64) -> String {
    let parsed = urlsplit(url);
    let mut pairs: Vec<(String, String)> = parse_qsl(&parsed.query)
        .into_iter()
        .filter(|(key, _)| key != "ecosystem" && key != "partition")
        .collect();
    pairs.push(("ecosystem".to_owned(), ecosystem.to_owned()));
    pairs.push(("partition".to_owned(), partition.to_string()));
    with_path(&parsed, &parsed.path, &urlencode(&pairs), "")
}

fn guard_events(url: &str) -> String {
    let parsed = urlsplit(&receipts(url));
    if rstrip_slash(&parsed.path).ends_with("/api/v1/guard/events") {
        return with_path(&parsed, rstrip_slash(&parsed.path), &parsed.query, "");
    }
    let mut path = rstrip_slash(&parsed.path);
    for suffix in [REGISTRY_RECEIPTS_SYNC, API_RECEIPTS_SYNC, RECEIPTS_SYNC] {
        if let Some(stripped) = path.strip_suffix(suffix) {
            path = stripped;
            break;
        }
    }
    let next = format!("{}/api/v1/guard/events", rstrip_slash(path));
    with_path(&parsed, &next, &parsed.query, "")
}

/// `sync_url`: one derived endpoint, selected by `route`.
pub(crate) fn sync_url(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let text = |key: &str| args.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let url = text("url")?;
    let derived = match text("route")? {
        "pain_signal" => pain_signal(url),
        "receipts" => receipts(url),
        "runtime_sessions" => runtime_sessions(url),
        "guard_events" => guard_events(url),
        "supply_chain_index" => supply_chain_index(url),
        "supply_chain_bundle" => supply_chain_bundle(url, text("workspace_id")?),
        "supply_chain_partition" => {
            let partition = args
                .get("partition")
                .and_then(Value::as_i64)
                .ok_or(ERR_INVALID)?;
            supply_chain_partition(url, text("ecosystem")?, partition)
        }
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({ "url": derived }))
}
