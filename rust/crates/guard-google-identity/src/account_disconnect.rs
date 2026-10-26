//! Explicit project-grant revocation; never runs on local revoke or Drop.
use super::*;

const REVOKE_URL: &str = "https://oauth2.googleapis.com/revoke";

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleProjectGrantRevocation {
    /// Google returned 200. Provider propagation may still be pending.
    Acknowledged,
    /// Failure, timeout or a non-200 response. Local admission is still revoked.
    Unconfirmed,
}

impl GoogleSendAccount {
    /// Consume this owner, revoke its local inputs, then request revocation of
    /// this account's grants for the OAuth project. Google revokes all granted
    /// scopes and tokens for all clients in that project, not just this input.
    /// This explicit operation is never called by Drop or local revoke().
    /// Makes one fixed request with no retries; a timeout is not confirmation.
    pub fn disconnect_and_revoke_project_grant(self) -> GoogleProjectGrantRevocation {
        self.disconnect_with_agent(super::super::token_agent())
    }

    fn disconnect_with_agent(self, agent: &ureq::Agent) -> GoogleProjectGrantRevocation {
        // Wait for any admitted bounded send before contacting the provider.
        // All pending credential copies share this lease and remain revoked
        // even when revocation is unavailable or its outcome is uncertain.
        self.revoke();
        let token = self
            .credential
            .refresh_token
            .as_ref()
            .unwrap_or(&self.credential.access_token);
        if !super::super::bounded_ascii(token, 8192) {
            return GoogleProjectGrantRevocation::Unconfirmed;
        }
        let body = Zeroizing::new(
            // Avoid reallocating/freeing intermediate token-bearing buffers.
            // Each bounded ASCII byte needs at most three encoded bytes.
            oauth2::url::form_urlencoded::Serializer::new(String::with_capacity(
                6 + 3 * token.len(),
            ))
            .append_pair("token", token.as_str())
            .finish(),
        );
        let response = agent
            .post(REVOKE_URL)
            .header("content-type", "application/x-www-form-urlencoded")
            .send(body.as_bytes());
        // Do not read/log a provider error body or echo token material. The
        // existing agent bounds headers/time, prohibits redirects and proxies.
        if response.is_ok_and(|response| response.status().as_u16() == 200) {
            GoogleProjectGrantRevocation::Acknowledged
        } else {
            GoogleProjectGrantRevocation::Unconfirmed
        }
        // Consuming self drops and zeroizes owner credentials on every path.
    }
}

#[cfg(test)]
#[path = "account_disconnect_tests.rs"]
mod tests;
