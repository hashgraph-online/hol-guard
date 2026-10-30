//! HTTPS transport to the Pulse service.
//!
//! Guard talks only to the production Yanez deployment, over HTTPS, with
//! no proxy, no redirects, short timeouts and capped bodies. The agent key is
//! sent only as the bearer credential and is never logged or echoed. Every
//! failure maps to a `PulseError`, and every `PulseError` keeps the action
//! blocked.

use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::jws::JwkSet;
use crate::receipt::RegisteredUserKey;
use crate::user_sig::decode_prefixed_hex;
use crate::{AssuranceTier, PulseError};

const MAX_BODY_BYTES: u64 = 64 * 1024;
/// One Pulse call, connection included.
const CALL_TIMEOUT_SECONDS: u64 = 4;
/// One check of a pending request. Yanez can take a few seconds just to
/// connect, and one slow check must not end the wait. This still fits inside
/// one resident operation (9 s).
const POLL_TIMEOUT_SECONDS: u64 = 8;
/// How long the user has to answer in the YID app: Pulse's default, 15 minutes.
pub const DECISION_WINDOW_SECONDS: i64 = 900;

/// The production Yanez deployment, the only server Guard talks to. Guard
/// never takes a URL, so nothing an agent writes can point it elsewhere.
const BASE_URL: &str = "https://yid.yanez.ai";

/// `POST /api/agent/authorizations` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedAuthorization {
    pub request_id: String,
}

/// One poll of a Pulse request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    Pending,
    Approved { artifact: String },
    Rejected,
    Expired,
}

/// `GET /api/agent/user_keys` result: the YID bound to the agent key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserKeys {
    pub yid: String,
    pub keys: Vec<RegisteredUserKey>,
}

impl UserKeys {
    /// Tiers at least one registered key can sign at, limited to the tiers
    /// Guard accepts.
    pub fn signable_floors(&self) -> Vec<AssuranceTier> {
        [AssuranceTier::Medium, AssuranceTier::High]
            .into_iter()
            .filter(|floor| {
                self.keys
                    .iter()
                    .any(|k| k.tier.is_some_and(|t| t >= *floor))
            })
            .collect()
    }
}

/// Everything Guard needs from Pulse. Tests supply a fake.
pub trait PulseTransport {
    fn create_authorization(
        &self,
        terms: &Value,
        consent_not_after_rfc3339: &str,
        idempotency_key: &str,
    ) -> Result<CreatedAuthorization, PulseError>;
    /// One check of a request's status. Guard checks every 10 seconds instead
    /// of holding a connection open, so Pulse is asked not to wait.
    fn poll(&self, request_id: &str) -> Result<PollOutcome, PulseError>;
    fn user_keys(&self) -> Result<UserKeys, PulseError>;
    fn public_keys(&self) -> Result<JwkSet, PulseError>;
    /// Single-use consumption. `Ok(())` only when Pulse says `consumed_now`.
    fn consume(&self, artifact: &str, consumer_token: &str) -> Result<(), PulseError>;
}

/// Parse a create response.
pub fn parse_created(body: &Value) -> Result<CreatedAuthorization, PulseError> {
    let request_id = body
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| valid_request_id(id))
        .ok_or(PulseError::Unavailable)?;
    if body.get("status").and_then(Value::as_str) != Some("pending") {
        return Err(PulseError::Unavailable);
    }
    Ok(CreatedAuthorization {
        request_id: request_id.to_owned(),
    })
}

/// Request ids appear in URLs, so only a narrow alphabet is accepted.
pub fn valid_request_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Parse a poll response.
pub fn parse_poll(body: &Value) -> Result<PollOutcome, PulseError> {
    match body.get("status").and_then(Value::as_str) {
        Some("pending") => Ok(PollOutcome::Pending),
        Some("rejected") => Ok(PollOutcome::Rejected),
        Some("expired") => Ok(PollOutcome::Expired),
        Some("approved") => body
            .get("artifact")
            .and_then(Value::as_str)
            .filter(|a| !a.is_empty() && a.len() <= crate::jws::MAX_ARTIFACT_BYTES)
            .map(|a| PollOutcome::Approved {
                artifact: a.to_owned(),
            })
            .ok_or(PulseError::Unavailable),
        _ => Err(PulseError::Unavailable),
    }
}

/// Parse a user-keys response. Malformed keys are dropped, not trusted.
pub fn parse_user_keys(body: &Value) -> Result<UserKeys, PulseError> {
    let yid = body
        .get("yid")
        .and_then(Value::as_str)
        .filter(|y| !y.is_empty() && y.len() <= 256)
        .ok_or(PulseError::Unavailable)?;
    let entries = body
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(PulseError::Unavailable)?;
    let keys = entries
        .iter()
        .take(64)
        .filter_map(|entry| {
            let raw = entry.get("public_key").and_then(Value::as_str)?;
            let bytes = decode_prefixed_hex(raw, 48)?;
            let tier = entry
                .get("tier")
                .and_then(Value::as_str)
                .and_then(AssuranceTier::parse);
            Some(RegisteredUserKey {
                public_key_hex: hex::encode(bytes),
                tier,
            })
        })
        .collect();
    Ok(UserKeys {
        yid: yid.to_owned(),
        keys,
    })
}

/// Parse an introspect response. Act only on `valid` and `consumed_now`.
pub fn parse_consume(body: &Value) -> Result<(), PulseError> {
    let valid = body.get("valid").and_then(Value::as_bool) == Some(true);
    let consumed_now = body.get("consumed_now").and_then(Value::as_bool) == Some(true);
    if valid && consumed_now {
        return Ok(());
    }
    match body.get("reason").and_then(Value::as_str) {
        Some("already_consumed") | Some("reservation_held") => Err(PulseError::Replayed),
        Some("consent_expired") => Err(PulseError::ConsentExpired),
        Some("bad_signature") => Err(PulseError::ReceiptInvalid("introspect")),
        _ if !valid => Err(PulseError::ReceiptInvalid("introspect")),
        _ => Err(PulseError::Unavailable),
    }
}

/// The real transport.
pub struct HttpPulseTransport {
    agent_key: Zeroizing<String>,
    agent: ureq::Agent,
}

/// Agent keys are `yak_` credentials; anything else is refused before it is
/// stored or sent.
pub fn valid_agent_key(key: &str) -> bool {
    key.starts_with("yak_")
        && (8..=512).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_graphic())
}

impl HttpPulseTransport {
    pub fn new(agent_key: &str) -> Result<Self, PulseError> {
        if !valid_agent_key(agent_key) {
            return Err(PulseError::InvalidRequest("agent_key"));
        }
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(CALL_TIMEOUT_SECONDS)))
            .build();
        Ok(Self {
            agent_key: Zeroizing::new(agent_key.to_owned()),
            agent: ureq::Agent::new_with_config(config),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{BASE_URL}{path}")
    }

    fn bearer(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("Bearer {}", self.agent_key.as_str()))
    }

    fn read(mut response: ureq::http::Response<ureq::Body>) -> Result<(u16, Value), PulseError> {
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_vec()
            .map_err(|_| PulseError::Unavailable)?;
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, body))
    }

    fn agent_status(status: u16) -> Result<(), PulseError> {
        match status {
            200 | 201 => Ok(()),
            401 | 403 => Err(PulseError::AgentKeyRejected),
            _ => Err(PulseError::Unavailable),
        }
    }
}

impl PulseTransport for HttpPulseTransport {
    fn create_authorization(
        &self,
        terms: &Value,
        consent_not_after_rfc3339: &str,
        idempotency_key: &str,
    ) -> Result<CreatedAuthorization, PulseError> {
        let body = json!({
            "terms": terms,
            "decision_window_seconds": DECISION_WINDOW_SECONDS,
            "intent_expires_at": consent_not_after_rfc3339,
        });
        let response = self
            .agent
            .post(&self.url("/api/agent/authorizations"))
            .header("Authorization", self.bearer().as_str())
            .header("Idempotency-Key", idempotency_key)
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|_| PulseError::Unavailable)?;
        let (status, body) = Self::read(response)?;
        Self::agent_status(status)?;
        parse_created(&body)
    }

    fn poll(&self, request_id: &str) -> Result<PollOutcome, PulseError> {
        if !valid_request_id(request_id) {
            return Err(PulseError::InvalidRequest("request_id"));
        }
        let response = self
            .agent
            .get(&self.url(&format!("/api/agent/authorizations/{request_id}?wait=0")))
            .config()
            .timeout_global(Some(Duration::from_secs(POLL_TIMEOUT_SECONDS)))
            .build()
            .header("Authorization", self.bearer().as_str())
            .call()
            .map_err(|_| PulseError::Unavailable)?;
        let (status, body) = Self::read(response)?;
        if status == 404 {
            // Unknown and cross-key ids look the same; both mean "not ours".
            return Err(PulseError::WrongRequest);
        }
        Self::agent_status(status)?;
        parse_poll(&body)
    }

    fn user_keys(&self) -> Result<UserKeys, PulseError> {
        let response = self
            .agent
            .get(&self.url("/api/agent/user_keys"))
            .header("Authorization", self.bearer().as_str())
            .call()
            .map_err(|_| PulseError::Unavailable)?;
        let (status, body) = Self::read(response)?;
        Self::agent_status(status)?;
        parse_user_keys(&body)
    }

    fn public_keys(&self) -> Result<JwkSet, PulseError> {
        let response = self
            .agent
            .get(&self.url("/api/authz/public-keys"))
            .call()
            .map_err(|_| PulseError::Unavailable)?;
        let (status, body) = Self::read(response)?;
        if status != 200 {
            return Err(PulseError::Unavailable);
        }
        JwkSet::parse(&body).ok_or(PulseError::Unavailable)
    }

    fn consume(&self, artifact: &str, consumer_token: &str) -> Result<(), PulseError> {
        let body = json!({
            "artifact": artifact,
            "consume": true,
            "consumer_token": consumer_token,
        });
        let response = self
            .agent
            .post(&self.url("/api/authz/introspect"))
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|_| PulseError::Unavailable)?;
        let (status, body) = Self::read(response)?;
        if status != 200 {
            return Err(PulseError::Unavailable);
        }
        parse_consume(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_acts_only_on_consumed_now() {
        assert!(parse_consume(&json!({"valid": true, "consumed_now": true})).is_ok());
        assert_eq!(
            parse_consume(&json!({"valid": true, "consumed_now": null})),
            Err(PulseError::Unavailable)
        );
        assert_eq!(
            parse_consume(
                &json!({"valid": true, "consumed_now": false, "reason": "already_consumed"})
            ),
            Err(PulseError::Replayed)
        );
        assert_eq!(
            parse_consume(
                &json!({"valid": true, "consumed_now": false, "reason": "reservation_held"})
            ),
            Err(PulseError::Replayed)
        );
        assert_eq!(
            parse_consume(
                &json!({"valid": true, "consumed_now": false, "reason": "consent_expired"})
            ),
            Err(PulseError::ConsentExpired)
        );
        assert!(parse_consume(&json!({"valid": false, "reason": "bad_signature"})).is_err());
    }

    #[test]
    fn poll_states_parse_and_unknown_states_fail_closed() {
        assert_eq!(
            parse_poll(&json!({"status": "pending"})),
            Ok(PollOutcome::Pending)
        );
        assert_eq!(
            parse_poll(&json!({"status": "rejected"})),
            Ok(PollOutcome::Rejected)
        );
        assert_eq!(
            parse_poll(&json!({"status": "expired"})),
            Ok(PollOutcome::Expired)
        );
        assert!(parse_poll(&json!({"status": "approved"})).is_err());
        assert!(parse_poll(&json!({"status": "maybe"})).is_err());
    }

    #[test]
    fn request_ids_are_url_safe() {
        assert!(valid_request_id("azr_abc-123"));
        assert!(!valid_request_id("../admin"));
        assert!(!valid_request_id("a?b=c"));
        assert!(!valid_request_id(""));
    }

    #[test]
    fn user_keys_drop_malformed_entries_and_list_floors() {
        let pk = format!("0x{}", "ab".repeat(48));
        let keys = parse_user_keys(&json!({
            "yid": "yid_1",
            "keys": [
                {"tier": "medium", "public_key": pk},
                {"tier": "high", "public_key": "0x1234"},
                {"tier": null, "public_key": pk},
            ]
        }))
        .unwrap();
        assert_eq!(keys.keys.len(), 2);
        assert_eq!(keys.signable_floors(), vec![AssuranceTier::Medium]);
    }

    #[test]
    fn only_yak_agent_keys_are_accepted() {
        assert!(valid_agent_key("yak_0123456789abcdef"));
        assert!(!valid_agent_key("sk_live_123456789"));
        assert!(!valid_agent_key("yak_has space"));
        assert!(HttpPulseTransport::new("nope").is_err());
    }
}
