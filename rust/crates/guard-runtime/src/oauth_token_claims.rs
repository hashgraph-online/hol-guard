//! `oauth_token_claims` runner-authority kind: what Guard reads from the claims
//! of a Guard Cloud OAuth access token. Ported from `guard/oauth_token_claims.py`
//! and the two `access_token_expires_at` copies in `runtime/runner.py` and
//! `cli/connect_flow.py`.
//!
//! The access token never reaches this kind. Python decodes the token's
//! payload segment and sends the decoded `claims` object (`null` when the
//! token carried none), as `cloud_actions_access` does:
//!
//! - `{"op": "identity", "claims"}` answers `{"identity": {"grant_id",
//!   "machine_id", "workspace_id", "device_id"}}`, each a claim or `null`;
//! - `{"op": "binding", "claims", "issuer"}` answers `{"binding": {...}}`, the
//!   grant, machine and workspace (and the device when present), or `{}` when
//!   the token names another issuer or lacks one of the three;
//! - `{"op": "credential_binding", "claims", "issuer", "credentials"}` answers
//!   the saved token's binding, or `{}` when it disagrees with a saved field;
//! - `{"op": "effective_binding", "claims", "issuer", "credentials",
//!   "refreshed"}` answers the four binding fields a rotated credential row
//!   keeps: refreshed claims win, otherwise the saved fields stay and claims
//!   only fill gaps when they agree with what is saved;
//! - `{"op": "expires_at", "claims", "expires_in", "now"}` answers
//!   `{"expires_at"}`: the token's own `exp`, else `now + expires_in`, else
//!   `null`.
//!
//! The resident's own refresh (`oauth_refresh.rs`) recovers a binding through
//! the same functions, so both sides read the same claim paths.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::guard_store_json::{add_seconds_isoformat, add_seconds_utc_isoformat};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const BINDING_KEYS: [&str; 4] = ["device_id", "grant_id", "machine_id", "workspace_id"];
const EPOCH: &str = "1970-01-01T00:00:00+00:00";

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Identity {
        claims: Option<Map<String, Value>>,
    },
    Binding {
        claims: Option<Map<String, Value>>,
        issuer: Option<String>,
    },
    CredentialBinding {
        claims: Option<Map<String, Value>>,
        issuer: Option<String>,
        credentials: Map<String, Value>,
    },
    EffectiveBinding {
        claims: Option<Map<String, Value>>,
        issuer: Option<String>,
        credentials: Map<String, Value>,
        refreshed: bool,
    },
    ExpiresAt {
        claims: Option<Map<String, Value>>,
        expires_in: Value,
        now: String,
    },
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request: Request = serde_json::from_value(args.clone()).map_err(|_| ERR_INVALID)?;
    let empty = Map::new();
    Ok(match request {
        Request::Identity { claims } => {
            let claims = claims.as_ref().unwrap_or(&empty);
            json!({"identity": {
                "grant_id": claim_string(claims, &["grant", "grantId"]),
                "machine_id": claim_string(claims, &["machine", "machineId"]),
                "workspace_id": claim_string(claims, &["workspace", "workspaceId"]),
                "device_id": device_id(claims),
            }})
        }
        Request::Binding { claims, issuer } => {
            json!({"binding": binding(claims.as_ref().unwrap_or(&empty), issuer.as_deref())})
        }
        Request::CredentialBinding {
            claims,
            issuer,
            credentials,
        } => json!({"binding": binding_from_credentials(
            claims.as_ref().unwrap_or(&empty),
            issuer.as_deref(),
            &credentials,
        )}),
        Request::EffectiveBinding {
            claims,
            issuer,
            credentials,
            refreshed,
        } => {
            let claims = claims.as_ref().unwrap_or(&empty);
            let recovered = if refreshed {
                binding(claims, issuer.as_deref())
            } else {
                binding_from_credentials(claims, issuer.as_deref(), &credentials)
            };
            let kept = refresh_binding(&credentials, &recovered, refreshed);
            let fields: Map<String, Value> = BINDING_KEYS
                .iter()
                .map(|key| {
                    (
                        (*key).to_owned(),
                        kept.get(*key).cloned().unwrap_or(Value::Null),
                    )
                })
                .collect();
            json!({"binding": fields})
        }
        Request::ExpiresAt {
            claims,
            expires_in,
            now,
        } => {
            json!({"expires_at": expires_at(claims.as_ref().unwrap_or(&empty), &expires_in, &now)})
        }
    })
}

/// `oauth_claim_string`: the stripped, non-empty string at a nested claim path.
pub(crate) fn claim_string(claims: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut current = claims.get(*first)?;
    for segment in rest {
        current = current.as_object()?.get(*segment)?;
    }
    let text = py_strip(current.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

/// `oauth_device_id`: the device claim, wherever the issuer placed it.
pub(crate) fn device_id(claims: &Map<String, Value>) -> Option<String> {
    claim_string(claims, &["deviceId"])
        .or_else(|| claim_string(claims, &["device", "deviceId"]))
        .or_else(|| claim_string(claims, &["machine", "deviceId"]))
}

/// `oauth_binding_metadata`: the grant, machine, workspace and device the
/// token was issued for, or nothing when it names another issuer or lacks
/// any of the first three.
pub(crate) fn binding(claims: &Map<String, Value>, issuer: Option<&str>) -> Map<String, Value> {
    if let (Some(expected), Some(token_issuer)) = (issuer, claim_string(claims, &["iss"])) {
        if token_issuer.trim_end_matches('/') != expected.trim_end_matches('/') {
            return Map::new();
        }
    }
    let required = [
        ("grant_id", claim_string(claims, &["grant", "grantId"])),
        (
            "machine_id",
            claim_string(claims, &["machine", "machineId"]),
        ),
        (
            "workspace_id",
            claim_string(claims, &["workspace", "workspaceId"]),
        ),
    ];
    let mut result = Map::new();
    for (key, value) in required {
        match value {
            Some(value) => result.insert(key.to_owned(), Value::String(value)),
            None => return Map::new(),
        };
    }
    if let Some(device) = device_id(claims) {
        result.insert("device_id".to_owned(), Value::String(device));
    }
    result
}

/// `oauth_binding_from_credentials`: the saved token's binding, kept only when
/// it agrees with every field already saved on the credential row.
pub(crate) fn binding_from_credentials(
    claims: &Map<String, Value>,
    issuer: Option<&str>,
    credentials: &Map<String, Value>,
) -> Map<String, Value> {
    let Some(issuer) = issuer.map(py_strip).filter(|value| !value.is_empty()) else {
        return Map::new();
    };
    let claimed = binding(claims, Some(issuer));
    let disagrees = claimed.iter().any(|(key, value)| {
        text(credentials.get(key)).is_some_and(|saved| Some(saved.as_str()) != value.as_str())
    });
    if disagrees {
        Map::new()
    } else {
        claimed
    }
}

/// `oauth_refresh_binding`: refreshed claims win; otherwise the saved fields
/// stay and the recovered binding only fills gaps.
pub(crate) fn refresh_binding(
    credentials: &Map<String, Value>,
    recovered: &Map<String, Value>,
    refreshed: bool,
) -> Map<String, Value> {
    let mut result = Map::new();
    for key in BINDING_KEYS {
        let saved = if refreshed {
            None
        } else {
            text(credentials.get(key)).map(Value::String)
        };
        if let Some(value) = saved.or_else(|| recovered.get(key).cloned()) {
            result.insert(key.to_owned(), value);
        }
    }
    result
}

/// The access token's expiry: its own `exp`, else `now + expires_in`.
fn expires_at(claims: &Map<String, Value>, expires_in: &Value, now: &str) -> Option<String> {
    if let Some(exp) = claims.get("exp").filter(|value| value.is_number()) {
        let micros = match exp.as_i64() {
            Some(seconds) => seconds.checked_mul(1_000_000),
            None => exp
                .as_f64()
                .map(|seconds| seconds * 1_000_000.0)
                .filter(|micros| micros.is_finite() && micros.abs() < 9.0e18)
                .map(|micros| micros.round_ties_even() as i64),
        };
        if exp.as_f64().is_some_and(|seconds| seconds > 0.0) {
            return add_seconds_utc_isoformat(EPOCH, micros?);
        }
    }
    let seconds = whole_seconds(expires_in).filter(|seconds| *seconds > 0)?;
    add_seconds_isoformat(now, seconds.checked_mul(1_000_000)?)
}

/// Python `int(value)` for a JSON number or a decimal string.
fn whole_seconds(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64().or_else(|| {
            number
                .as_f64()
                .filter(|seconds| seconds.is_finite() && seconds.abs() < 9.0e18)
                .map(|seconds| seconds.trunc() as i64)
        }),
        Value::String(raw) => decimal(py_strip(raw)),
        _ => None,
    }
}

/// `int(text)` for base-10 text: an optional sign, then digits with single
/// underscores between them.
fn decimal(text: &str) -> Option<i64> {
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    let magnitude: i64 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// `_text`: a stripped, non-empty string value.
fn text(value: Option<&Value>) -> Option<String> {
    let stripped = py_strip(value?.as_str()?);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

#[cfg(test)]
#[path = "oauth_token_claims_tests.rs"]
mod tests;
