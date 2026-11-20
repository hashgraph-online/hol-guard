//! The `oauth_refresh` action of `cloud-event-sync`: one Guard OAuth
//! refresh-token exchange for a caller that owns the grant.
//!
//! The caller keeps the stored credentials, the invalid-grant retry with a
//! reloaded grant, the refresh circuit and the rotation persist. The runtime
//! signs the DPoP proof, answers the endpoint's nonce challenge, sends the
//! exchange under the machine's managed network policy and reports how it
//! ended, with the token response when it succeeded.

use std::time::{SystemTime, UNIX_EPOCH};

use guard_command::egress_broker;
use guard_command::guard_sync_transport::{self as gst, OAuthRefreshOutcome, OAuthRefreshRequest};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cloud_bundle_fetch::SyncError;

/// `_SYNC_HTTP_TIMEOUT_SECONDS`.
const TIMEOUT_SECONDS: f64 = 20.0;
/// How many fresh nonces one exchange answers.
const MAX_NONCE_RETRIES: u32 = 3;

/// The proof key that signs the exchange.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DpopKey {
    private_key_pem: String,
    public_jwk: Map<String, Value>,
    algorithm: String,
}

/// What the caller built for `oauth_refresh`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RefreshCall {
    token_endpoint: String,
    client_id: String,
    refresh_token: String,
    dpop_key: DpopKey,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The token endpoint, when it is the one Guard derives for its own issuer.
fn trusted_token_endpoint(token_endpoint: &str) -> Result<(), SyncError> {
    let untrusted = || {
        SyncError::EndpointUntrusted(
            "The Guard OAuth token endpoint is not one Guard trusts.".to_owned(),
        )
    };
    let (_, _, derived, ..) =
        gst::resolve_guard_oauth_client_config(token_endpoint).map_err(|_| untrusted())?;
    if derived == token_endpoint {
        Ok(())
    } else {
        Err(untrusted())
    }
}

fn reason(outcome: &str, reason: String) -> Value {
    json!({"outcome": outcome, "reason": reason})
}

/// Run one exchange. A transport failure while the broker still owes this
/// round an answer is `Pending`, so the broker fulfils it and runs it again.
pub(crate) fn refresh(call: &RefreshCall) -> Result<Value, SyncError> {
    trusted_token_endpoint(&call.token_endpoint)?;
    let mut nonce: Option<String> = None;
    let mut nonce_retries = 0;
    loop {
        let request = OAuthRefreshRequest {
            token_endpoint: &call.token_endpoint,
            client_id: &call.client_id,
            refresh_token: &call.refresh_token,
            dpop_private_key_pem: &call.dpop_key.private_key_pem,
            dpop_public_jwk: &call.dpop_key.public_jwk,
            algorithm: &call.dpop_key.algorithm,
            nonce: nonce.as_deref(),
            timeout_seconds: TIMEOUT_SECONDS,
            now_unix: now_unix(),
        };
        let answer = match gst::refresh_guard_oauth_access_token(&request) {
            OAuthRefreshOutcome::Refreshed { payload, .. } => {
                json!({"outcome": "refreshed", "payload": payload})
            }
            OAuthRefreshOutcome::NonceChallenge(challenge) => {
                if Some(challenge.as_str()) == nonce.as_deref()
                    || nonce_retries >= MAX_NONCE_RETRIES
                {
                    // A nonce handshake that never settles is a refusal of this
                    // exchange, not proof that the grant was revoked.
                    reason(
                        "rejected",
                        "Guard Cloud kept asking for a new DPoP nonce.".to_owned(),
                    )
                } else {
                    nonce = Some(challenge);
                    nonce_retries += 1;
                    continue;
                }
            }
            OAuthRefreshOutcome::RateLimited {
                wait_seconds,
                retry_after,
            } => json!({
                "outcome": "rate_limited",
                "retryAfterSeconds": wait_seconds,
                "retryAfter": retry_after,
            }),
            OAuthRefreshOutcome::DeadGrant => json!({"outcome": "dead_grant"}),
            OAuthRefreshOutcome::Rejected(why) => reason("rejected", why),
            OAuthRefreshOutcome::Unusable(why) => reason("unusable", why),
            OAuthRefreshOutcome::Unreachable(why) => {
                if egress_broker::needs_pending() {
                    return Err(SyncError::Pending);
                }
                reason("unreachable", why)
            }
            OAuthRefreshOutcome::Failed(why) => {
                if egress_broker::needs_pending() {
                    return Err(SyncError::Pending);
                }
                reason("failed", why)
            }
        };
        return Ok(answer);
    }
}

#[cfg(test)]
#[path = "cloud_oauth_refresh_tests.rs"]
mod tests;
