//! Decisions of the public release transport.
//!
//! Update and activation commands read an advisory selector and release assets
//! from a few public hosts. Python opens the connection and moves the bytes;
//! what a destination, a response and a failure mean is decided here, so the
//! host allow-list, the byte bounds and the retry schedule have one
//! implementation. Transport bytes never grant policy authority: the caller
//! authenticates the root and verifies every object it names before using any
//! of them.
//!
//! Operations, selected by `operation`:
//! - `request`: may this destination be requested with this byte limit?
//! - `refusal`: what an HTTP refusal means: a missing release, a redirect to
//!   follow, or an answer to raise.
//! - `headers`: may a response with these headers be read, and how long does
//!   it declare its body to be?
//! - `body`: is the body that was read as long as the response declared?
//! - `retry`: does a failed attempt earn another one, and after how long?
//! - `selector`: validate an advisory selector and name the tag its root is
//!   published under.
//! - `root_tag`: name the tag a root is published under.
//! - `bind`: check what a fetched root shows against the selector that named it.
//!
//! A rejected input is a normal reply, `{"rejected": <message>}`, so the caller
//! can keep its own error contract. Only an unknown operation is a hard error.
use serde_json::{json, Value};

mod selector;
#[cfg(test)]
mod selector_tests;
#[cfg(test)]
mod tests;

type Outcome = Result<Value, String>;

const HOSTS: [&str; 5] = [
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
const MAXIMUM_BYTES: u64 = 32 * 1024 * 1024;
/// A download makes at most this many requests: the first and four redirects.
const REQUESTS: u64 = 5;
const REDIRECTS: [u64; 5] = [301, 302, 303, 307, 308];
// A publication that momentarily refuses the request fails an operator's save
// outright, and the operator can only try again later. The refusals that are
// transient by definition are retried: a rate limit, a server-side error and a
// connection that never completed. Every byte is still authenticated
// afterwards, so a retry admits nothing a first attempt could not.
const RETRY_STATUS: [u64; 5] = [429, 500, 502, 503, 504];
const RETRY_DELAYS: [f64; 2] = [0.5, 2.0];

fn invalid() -> String {
    "release transport request invalid".into()
}

fn limit(input: &Value) -> Result<u64, String> {
    input["maximum"]
        .as_u64()
        .filter(|maximum| (1..=MAXIMUM_BYTES).contains(maximum))
        .ok_or_else(|| "release transport byte limit invalid".into())
}

/// Only https on a listed host and the default port. The URL is held to
/// printable ASCII and its authority is compared whole, so no parser reading
/// the same string can find a different host in it than this check did.
fn permitted(url: &str) -> Result<(), String> {
    let listed = url.bytes().all(|b| b.is_ascii_graphic())
        && url.strip_prefix("https://").is_some_and(|rest| {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let authority = &rest[..end];
            HOSTS.contains(&authority.strip_suffix(":443").unwrap_or(authority))
        });
    if listed {
        Ok(())
    } else {
        Err("release transport destination is not permitted".into())
    }
}

fn request(input: &Value) -> Outcome {
    limit(input)?;
    permitted(input["url"].as_str().ok_or_else(invalid)?)?;
    Ok(json!({"permitted": true}))
}

/// `next` is the redirect target the caller resolved against the URL it asked
/// for, or null when the response named none that could be resolved.
fn refusal(input: &Value) -> Outcome {
    let status = input["status"].as_u64().ok_or_else(invalid)?;
    if status == 404 {
        return Ok(json!({"missing": "extension release is unavailable"}));
    }
    if !REDIRECTS.contains(&status) {
        return Ok(json!({"refused": true}));
    }
    let hop = input["hop"].as_u64().ok_or_else(invalid)?;
    let named = input["location"]
        .as_str()
        .is_some_and(|text| !text.is_empty());
    let next = input["next"]
        .as_str()
        .filter(|_| named && hop < REQUESTS - 1);
    let next = next.ok_or("release transport redirect limit or destination invalid")?;
    permitted(next)?;
    Ok(json!({"redirect": next}))
}

/// The declared length is ASCII digits and within the limit; anything else is
/// refused before a byte of the body is read.
fn declared(text: &str, maximum: u64) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().filter(|n| (1..=maximum).contains(n))
}

fn headers(input: &Value) -> Outcome {
    let maximum = limit(input)?;
    match &input["content_encoding"] {
        Value::Null => {}
        Value::String(encoding) if encoding == "identity" => {}
        Value::String(_) => return Err("compressed release transport is not permitted".into()),
        _ => return Err(invalid()),
    }
    let length = match &input["content_length"] {
        Value::Null => None,
        Value::String(text) => Some(
            declared(text, maximum).ok_or("release transport content length exceeds byte limit")?,
        ),
        _ => return Err(invalid()),
    };
    Ok(json!({"declared": length}))
}

fn body(input: &Value) -> Outcome {
    let maximum = limit(input)?;
    let length = input["length"].as_u64().ok_or_else(invalid)?;
    let promised = match &input["declared"] {
        Value::Null => None,
        value => Some(value.as_u64().ok_or_else(invalid)?),
    };
    if !(1..=maximum).contains(&length) || promised.is_some_and(|n| n != length) {
        return Err("release transport body length invalid".into());
    }
    Ok(json!({"accepted": true}))
}

/// `status` is the HTTP status of a refusal and null for a failure that had
/// none; `network` says that failure was a connection that never completed.
/// `attempt` counts the attempts already made, so the schedule ends here.
fn retry(input: &Value) -> Outcome {
    let attempt = input["attempt"].as_u64().ok_or_else(invalid)?;
    let transient = match &input["status"] {
        Value::Null => input["network"].as_bool().ok_or_else(invalid)?,
        status => RETRY_STATUS.contains(&status.as_u64().ok_or_else(invalid)?),
    };
    let delay = usize::try_from(attempt)
        .ok()
        .and_then(|index| RETRY_DELAYS.get(index))
        .filter(|_| transient);
    Ok(json!({"delay": delay}))
}

pub(super) fn evaluate(input: &Value) -> Result<Value, String> {
    let outcome = match input["operation"].as_str() {
        Some("request") => request(input),
        Some("refusal") => refusal(input),
        Some("headers") => headers(input),
        Some("body") => body(input),
        Some("retry") => retry(input),
        Some("selector") => selector::validate(input),
        Some("root_tag") => selector::tag(input),
        Some("bind") => selector::bind(input),
        _ => return Err(invalid()),
    };
    Ok(outcome.unwrap_or_else(|message| json!({"rejected": message})))
}
