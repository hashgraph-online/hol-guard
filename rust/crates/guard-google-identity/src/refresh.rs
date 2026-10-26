//! Registered fixed-endpoint refresh. No caller token, URL or identity claims.
use super::*;
use std::collections::BTreeSet;

const USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";

pub(super) struct Registration {
    client_id: String,
    client_secret: Zeroizing<String>,
    identity_key: Zeroizing<[u8; 32]>,
    hosted_domains: BTreeSet<String>,
    pub(super) observed_at: u64,
}

impl Registration {
    pub(super) fn capture(session: &GoogleSendAuthorization) -> Self {
        Self {
            client_id: session.client_id.as_str().to_owned(),
            client_secret: Zeroizing::new(session.client_secret.as_str().to_owned()),
            identity_key: Zeroizing::new(session.challenge.identity_key),
            hosted_domains: session.challenge.hosted_domains.clone(),
            observed_at: session.challenge.created_at,
        }
    }
    fn worker_copy(&self, observed_at: u64) -> Self {
        Self {
            client_id: self.client_id.clone(),
            client_secret: Zeroizing::new(self.client_secret.as_str().to_owned()),
            identity_key: Zeroizing::new(*self.identity_key),
            hosted_domains: self.hosted_domains.clone(),
            observed_at,
        }
    }
}

pub(super) fn valid_scopes(purpose: GrantPurpose, scopes: &[Scope]) -> bool {
    scopes.len() == 3
        && scopes.iter().any(|s| s.as_str() == "openid")
        && scopes.iter().any(|s| {
            matches!(
                s.as_str(),
                "email" | "https://www.googleapis.com/auth/userinfo.email"
            )
        })
        && scopes.iter().any(|s| s.as_str() == purpose.scope())
}

#[derive(Deserialize)]
struct Response {
    #[serde(deserialize_with = "secret_string")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "bearer_type")]
    token_type: BasicTokenType,
    expires_in: u64,
    #[serde(default, deserialize_with = "optional_secret_string")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(default, rename = "scope", deserialize_with = "optional_scopes")]
    scopes: Option<Vec<Scope>>,
    #[serde(default, deserialize_with = "optional_secret_string")]
    id_token: Option<Zeroizing<String>>,
}
fn optional_scopes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<Scope>>, D::Error> {
    granted_scopes(d).map(Some)
}

#[derive(Deserialize)]
struct UserInfo {
    #[serde(deserialize_with = "secret_string")]
    sub: Zeroizing<String>,
    hd: String,
    #[serde(deserialize_with = "secret_string")]
    email: Zeroizing<String>,
    email_verified: bool,
}

fn body(response: HttpResponse, limit: usize) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let status = response.status();
    let json = json_media_type(response.headers());
    let bytes = Zeroizing::new(response.into_body());
    if status.is_server_error() || status.as_u16() == 429 {
        return Err(IdentityError::ExchangeUnavailable);
    }
    if status.as_u16() != 200 || !json || bytes.len() > limit {
        return Err(IdentityError::Invalid);
    }
    Ok(bytes)
}

impl GoogleSendCredential {
    pub(super) fn can_refresh(&self) -> bool {
        self.purpose == GrantPurpose::Send
            && self.refresh_token.is_some()
            && self.refresh_registration.is_some()
            && self.account_lease.is_none()
    }

    pub(super) fn refresh_registered(&self) -> Result<Self, IdentityError> {
        self.refresh_registered_with_agent(token_agent())
    }

    fn refresh_registered_with_agent(&self, agent: &ureq::Agent) -> Result<Self, IdentityError> {
        self.refresh_with(
            |request| exchange_http_with_agent(request, agent),
            |access| userinfo_http(access, agent),
        )
    }

    fn refresh_with<E: std::error::Error>(
        &self,
        exchange: impl FnOnce(HttpRequest) -> Result<HttpResponse, E>,
        userinfo: impl FnOnce(&str) -> Result<HttpResponse, E>,
    ) -> Result<Self, IdentityError> {
        self.refresh_with_clock(exchange, userinfo, now)
    }

    fn refresh_with_clock<E: std::error::Error>(
        &self,
        exchange: impl FnOnce(HttpRequest) -> Result<HttpResponse, E>,
        userinfo: impl FnOnce(&str) -> Result<HttpResponse, E>,
        mut clock: impl FnMut() -> Result<u64, IdentityError>,
    ) -> Result<Self, IdentityError> {
        if !self.can_refresh() {
            return Err(IdentityError::Invalid);
        }
        let registration = self
            .refresh_registration
            .as_ref()
            .ok_or(IdentityError::Invalid)?;
        let refresh = self.refresh_token.as_ref().ok_or(IdentityError::Invalid)?;
        let start = ExchangeStart {
            wall: clock()?,
            monotonic: Instant::now(),
        };
        if start.wall < registration.observed_at {
            return Err(IdentityError::Expired);
        }
        let capacity = 256
            + 3 * (registration.client_id.len() + registration.client_secret.len() + refresh.len());
        let request_body =
            oauth2::url::form_urlencoded::Serializer::new(String::with_capacity(capacity))
                .extend_pairs([
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh.as_str()),
                    ("client_id", registration.client_id.as_str()),
                    ("client_secret", registration.client_secret.as_str()),
                ])
                .finish()
                .into_bytes();
        let mut request = HttpRequest::new(request_body);
        *request.method_mut() = oauth2::http::Method::POST;
        *request.uri_mut() = oauth2::http::Uri::from_static(TOKEN_URL);
        request.headers_mut().insert(
            "content-type",
            oauth2::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = exchange(request).map_err(|_| IdentityError::ExchangeUnavailable)?;
        let received = clock()?;
        if received < start.wall {
            return Err(IdentityError::Expired);
        }
        let response: Response = serde_json::from_slice(&body(response, 64 * 1024)?)
            .map_err(|_| IdentityError::Invalid)?;
        if response.token_type != BasicTokenType::Bearer
            || !bounded_ascii(&response.access_token, 8192)
            || response.expires_in == 0
            || response.expires_in > 3600
            || response
                .scopes
                .as_ref()
                .is_some_and(|s| !valid_scopes(self.purpose, s))
            || response
                .refresh_token
                .as_ref()
                .is_some_and(|s| !bounded_ascii(s, 8192))
            || response
                .id_token
                .as_ref()
                .is_some_and(|s| !bounded_ascii(s, crate::MAX_TOKEN))
        {
            return Err(IdentityError::Invalid);
        }
        let info =
            userinfo(&response.access_token).map_err(|_| IdentityError::ExchangeUnavailable)?;
        let info: UserInfo =
            serde_json::from_slice(&body(info, 16 * 1024)?).map_err(|_| IdentityError::Invalid)?;
        if !bounded_ascii(&info.sub, 255)
            || !registration.hosted_domains.contains(&info.hd)
            || !info.email_verified
            || !crate::sender::supported_mailbox(&info.email)
        {
            return Err(IdentityError::Invalid);
        }
        let observed = clock()?;
        let account_binding = crate::binding(
            &registration.identity_key,
            b"hol-guard.google-account.v1\0",
            &[crate::ISSUER, &registration.client_id, &info.hd, &info.sub],
        );
        let tenant_binding = crate::binding(
            &registration.identity_key,
            b"hol-guard.google-tenant.v1\0",
            &[crate::ISSUER, &info.hd],
        );
        if account_binding != self.identity.account_binding
            || tenant_binding != self.identity.tenant_binding
            || !self
                .identity
                .sender
                .as_ref()
                .is_some_and(|s| s.matches(&info.email))
        {
            return Err(IdentityError::Invalid);
        }
        let (expires_at, expires_monotonic) = credential_deadline(
            &start,
            received,
            observed,
            start.wall.saturating_add(crate::LIFETIME),
            response.expires_in,
            Instant::now(),
        )?;
        Ok(Self {
            refresh_registration: Some(registration.worker_copy(observed)),
            account_lease: None,
            account_epoch: None,
            purpose: self.purpose,
            access_token: response.access_token,
            refresh_token: Some(
                response
                    .refresh_token
                    .unwrap_or_else(|| Zeroizing::new(refresh.as_str().to_owned())),
            ),
            identity: GoogleIdentityEvidence {
                account_binding,
                tenant_binding,
                expires_at,
                sender: crate::sender::VerifiedSender::from_claims(
                    Some(info.email.as_str().to_owned()),
                    Some(true),
                ),
            },
            expires_at,
            expires_monotonic,
        })
    }
}

fn userinfo_http(
    access: &str,
    agent: &ureq::Agent,
) -> Result<HttpResponse, ExchangeTransportError> {
    let authorization = Zeroizing::new(format!("Bearer {access}"));
    let mut response = agent
        .get(USERINFO_URL)
        .header("authorization", authorization.as_str())
        .header("accept", "application/json")
        .call()
        .map_err(|_| ExchangeTransportError)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(16 * 1024 + 1));
    response
        .body_mut()
        .as_reader()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExchangeTransportError)?;
    let mut result = HttpResponse::new(std::mem::take(&mut *bytes));
    *result.status_mut() = response.status();
    *result.headers_mut() = response.headers().clone();
    Ok(result)
}

#[cfg(test)]
#[path = "refresh_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "refresh_http_tests.rs"]
pub(crate) mod http_tests;
