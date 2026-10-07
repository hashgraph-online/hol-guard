//! One fixed POST, no redirects, environment proxy, caller URL or retry loop.
use super::{GoogleSendCredential, GrantPurpose};
use crate::dispatch::{Acknowledgement, GoogleDispatchError, RawSendAttempt, GMAIL_SEND_URL};
use serde::Deserialize;
use std::io::Read;
use zeroize::Zeroizing;

const MAX_REPLY: usize = 64 * 1024;

struct Reply {
    status: u16,
    json: bool,
    bytes: Zeroizing<Vec<u8>>,
}

impl GoogleSendCredential {
    pub(crate) fn send_json_once(
        self,
        bytes: &[u8],
    ) -> Result<RawSendAttempt, GoogleDispatchError> {
        self.send_with(bytes, post)
    }
    fn send_with(
        self,
        bytes: &[u8],
        transport: impl FnOnce(&str, &str, &[u8]) -> Option<Reply>,
    ) -> Result<RawSendAttempt, GoogleDispatchError> {
        if self.purpose != GrantPurpose::Send {
            return Err(GoogleDispatchError::WrongPurpose);
        }
        if bytes.is_empty() || bytes.len() > 256 * 1024 {
            return Err(GoogleDispatchError::InputChanged);
        }
        if !self.is_current() {
            return Err(GoogleDispatchError::Expired);
        }
        let authorization = Zeroizing::new(format!("Bearer {}", self.access_token.as_str()));
        // Every transport failure after entry is uncertain, including malformed
        // acknowledgements. Do not turn it into a retryable pre-attempt error.
        let attempt = transport(GMAIL_SEND_URL, authorization.as_str(), bytes)
            .and_then(acknowledgement)
            .map_or(RawSendAttempt::Unconfirmed, RawSendAttempt::Accepted);
        Ok(attempt)
    }
}

fn post(url: &str, authorization: &str, bytes: &[u8]) -> Option<Reply> {
    // Reuse security settings, with a fresh connection pool for this one effect.
    let agent = ureq::Agent::new_with_config(super::token_agent().config().clone());
    let mut response = agent
        .post(url)
        .header("Authorization", authorization)
        .header("Content-Type", "application/json")
        .send(bytes)
        .ok()?;
    let values = response
        .headers()
        .get_all("content-type")
        .iter()
        .collect::<Vec<_>>();
    let json = values.len() == 1
        && values[0]
            .to_str()
            .ok()
            .and_then(|s| s.split(';').next())
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"));
    let status = response.status().as_u16();
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_REPLY + 1));
    response
        .body_mut()
        .as_reader()
        .take(MAX_REPLY as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(Reply {
        status,
        json,
        bytes,
    })
}

fn acknowledgement(reply: Reply) -> Option<Acknowledgement> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Message {
        id: String,
        thread_id: String,
    }
    if reply.status != 200 || !reply.json || reply.bytes.len() > MAX_REPLY {
        return None;
    }
    let message: Message = serde_json::from_slice(&reply.bytes).ok()?;
    // Provider IDs are opaque strings, not a client-defined alphabet. They are
    // only fingerprinted, never interpolated into URLs, headers or diagnostics.
    let valid = |s: &str| !s.is_empty() && s.len() <= 256;
    if !valid(&message.id) || !valid(&message.thread_id) {
        return None;
    }
    Some(Acknowledgement {
        id: Zeroizing::new(message.id),
        thread_id: Zeroizing::new(message.thread_id),
    })
}

#[cfg(test)]
#[path = "send_http_tests.rs"]
mod tests;
