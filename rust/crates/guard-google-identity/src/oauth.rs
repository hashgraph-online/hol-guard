//! Worker-owned registered Google send authorization. No public RPC, token
//! export, account enrollment, custody proof or execution authority is added.

use super::{bounded_ascii, now, GoogleIdentityEvidence, GoogleLoginChallenge, IdentityError};
use oauth2::basic::{BasicClient, BasicTokenType};
use oauth2::{
    AuthUrl, ClientId, CsrfToken, HttpRequest, HttpResponse, PkceCodeChallenge, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;
use std::io::Read;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const SEND_SCOPE: &str = "https://www.googleapis.com/auth/gmail.send";

/// Configuration must come from the authenticated worker, not callback/tool
/// arguments. The client session binding is owned by that worker's authorized
/// client session and must be re-derived from the authenticated callback session.
pub struct GoogleSendAuthorization {
    client_id: ClientId,
    redirect: RedirectUrl,
    client_secret: Zeroizing<String>,
    challenge: GoogleLoginChallenge,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    client_session_binding: String,
    authorization_url: Zeroizing<String>,
}

/// Private credential material remains in the worker. No Clone, Debug,
/// serialization or token getter. A successful callback is not enrollment.
pub struct GoogleSendCredential {
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    identity: GoogleIdentityEvidence,
    expires_at: u64,
    expires_monotonic: Instant,
}
impl GoogleSendCredential {
    pub fn identity(&self) -> &GoogleIdentityEvidence {
        &self.identity
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn has_refresh_credential(&self) -> bool {
        self.refresh_token.is_some()
    }
    pub fn is_current(&self) -> bool {
        bounded_ascii(&self.access_token, 8192)
            && Instant::now() < self.expires_monotonic
            && now().is_ok_and(|time| time < self.expires_at && time < self.identity.expires_at())
    }
    /// Authenticate the exact primary From mailbox without exporting it.
    /// This does not resolve recipients, enroll an account or permit a send.
    pub fn authenticates_sender(&self, sender: &str) -> bool {
        self.is_current()
            && self
                .identity
                .sender
                .as_ref()
                .is_some_and(|s| s.matches(sender))
    }
}

impl GoogleSendAuthorization {
    pub fn begin(
        challenge: GoogleLoginChallenge,
        registered_client_secret: String,
        registered_redirect_uri: String,
        authenticated_client_session_binding: String,
    ) -> Result<Self, IdentityError> {
        let client_secret = Zeroizing::new(registered_client_secret);
        challenge.check_time(now()?)?;
        if !bounded_ascii(&client_secret, 4096)
            || !valid_session_binding(&authenticated_client_session_binding)
            || registered_redirect_uri.len() > 2048
        {
            return Err(IdentityError::Invalid);
        }
        let redirect =
            RedirectUrl::new(registered_redirect_uri).map_err(|_| IdentityError::Invalid)?;
        let url = redirect.url();
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err(IdentityError::Invalid);
        }
        let client_id = ClientId::new(challenge.client_id.clone());
        let client = BasicClient::new(client_id.clone())
            .set_auth_uri(
                AuthUrl::new(AUTHORIZE_URL.to_owned()).map_err(|_| IdentityError::Invalid)?,
            )
            .set_redirect_uri(redirect.clone());
        let (pkce, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new(SEND_SCOPE.to_owned()))
            .set_pkce_challenge(pkce)
            .add_extra_param("nonce", challenge.nonce())
            .add_extra_param("access_type", "offline")
            .add_extra_param("include_granted_scopes", "false")
            .add_extra_param("prompt", "select_account consent")
            .url();
        Ok(Self {
            client_id,
            redirect,
            client_secret,
            challenge,
            state: Zeroizing::new(state.into_secret()),
            verifier: Zeroizing::new(verifier.into_secret()),
            client_session_binding: authenticated_client_session_binding,
            authorization_url: Zeroizing::new(url.into()),
        })
    }

    /// A browser may receive this authorization URL; it contains no client
    /// secret or PKCE verifier. Do not log callback codes or token responses.
    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    /// Consumes the session even on failure. The session binding must come
    /// from authenticated server context, never a callback query/body field.
    pub fn complete(
        self,
        callback_state: &str,
        code: String,
        authenticated_client_session_binding: &str,
    ) -> Result<GoogleSendCredential, IdentityError> {
        self.complete_with(
            callback_state,
            code,
            authenticated_client_session_binding,
            exchange_http,
            |challenge, id, access| challenge.verify(id, access),
        )
    }

    fn complete_with<E: std::error::Error + 'static>(
        self,
        callback_state: &str,
        code: String,
        session_binding: &str,
        transport: impl Fn(HttpRequest) -> Result<HttpResponse, E>,
        verify_identity: impl FnOnce(
            GoogleLoginChallenge,
            &str,
            &str,
        ) -> Result<GoogleIdentityEvidence, IdentityError>,
    ) -> Result<GoogleSendCredential, IdentityError> {
        let code = Zeroizing::new(code);
        self.challenge.check_time(now()?)?;
        if !bounded_ascii(callback_state, 256)
            || !bounded_ascii(&code, 8192)
            || !same_state(&self.state, callback_state)
            || self.client_session_binding != session_binding
        {
            return Err(IdentityError::Invalid);
        }
        let start = ExchangeStart {
            wall: now()?,
            monotonic: Instant::now(),
        };
        // Own the fixed exchange and its decoder so temporary credential
        // buffers never pass through the SDK's non-zeroizing response parser.
        // Percent encoding can expand each bounded byte threefold. Reserve
        // that worst case so an intermediate allocation cannot retain secrets.
        let capacity = 256
            + 3 * (code.len()
                + self.client_id.as_str().len()
                + self.client_secret.len()
                + self.redirect.url().as_str().len()
                + self.verifier.len());
        let body = oauth2::url::form_urlencoded::Serializer::new(String::with_capacity(capacity))
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", self.redirect.url().as_str()),
                ("code_verifier", self.verifier.as_str()),
            ])
            .finish()
            .into_bytes();
        let mut request = HttpRequest::new(body);
        *request.method_mut() = oauth2::http::Method::POST;
        *request.uri_mut() = oauth2::http::Uri::from_static(TOKEN_URL);
        request.headers_mut().insert(
            "content-type",
            oauth2::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = transport(request).map_err(|_| IdentityError::ExchangeUnavailable)?;
        let status = response.status();
        let json = json_media_type(response.headers());
        let bytes = Zeroizing::new(response.into_body());
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(IdentityError::ExchangeUnavailable);
        }
        if status.as_u16() != 200 || !json || bytes.len() > 64 * 1024 {
            return Err(IdentityError::Invalid);
        }
        let response: GoogleTokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| IdentityError::Invalid)?;
        if response.token_type != BasicTokenType::Bearer
            || !bounded_ascii(&response.access_token, 8192)
            || !bounded_ascii(&response.id_token, super::MAX_TOKEN)
            || response.expires_in == 0
            || response.expires_in > 3600
            || response.scopes.len() != 3
            || !response.scopes.iter().any(|scope| {
                matches!(
                    scope.as_str(),
                    "email" | "https://www.googleapis.com/auth/userinfo.email"
                )
            })
            || !response
                .scopes
                .iter()
                .any(|scope| scope.as_str() == "openid")
            || !response
                .scopes
                .iter()
                .any(|scope| scope.as_str() == SEND_SCOPE)
            || response
                .refresh_token
                .as_ref()
                .is_some_and(|token| !bounded_ascii(token, 8192))
        {
            return Err(IdentityError::Invalid);
        }
        let received_at = now()?;
        self.challenge.check_time(received_at)?;
        let identity = verify_identity(self.challenge, &response.id_token, &response.access_token)?;
        if identity.sender.is_none() {
            return Err(IdentityError::Invalid);
        }
        // Google verification may fetch keys; both clocks are checked again.
        let observed = now()?;
        let (expires_at, expires_monotonic) = credential_deadline(
            &start,
            received_at,
            observed,
            identity.expires_at(),
            response.expires_in,
            Instant::now(),
        )?;
        Ok(GoogleSendCredential {
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            identity,
            expires_at,
            expires_monotonic,
        })
    }
}

fn same_state(expected: &str, presented: &str) -> bool {
    let expected = CsrfToken::new(expected.to_owned());
    let presented = CsrfToken::new(presented.to_owned());
    let same = expected == presented;
    // Preserve the SDK's timing-resistant comparison, then recover and wipe
    // the temporary comparison strings through its supported ownership API.
    drop(Zeroizing::new(expected.into_secret()));
    drop(Zeroizing::new(presented.into_secret()));
    same
}

struct ExchangeStart {
    wall: u64,
    monotonic: Instant,
}
fn credential_deadline(
    start: &ExchangeStart,
    received: u64,
    observed: u64,
    identity_expiry: u64,
    lifetime: u64,
    monotonic: Instant,
) -> Result<(u64, Instant), IdentityError> {
    let expiry = start.wall.saturating_add(lifetime).min(identity_expiry);
    let access_deadline = start.monotonic + Duration::from_secs(lifetime);
    if received < start.wall
        || observed < received
        || observed >= expiry
        || monotonic >= access_deadline
    {
        return Err(IdentityError::Expired);
    }
    Ok((
        expiry,
        access_deadline.min(monotonic + Duration::from_secs(expiry - observed)),
    ))
}

fn valid_session_binding(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Known duplicates fail Serde struct decoding. No token response diagnostic or
// serialization can expose its code/token material through generic utilities.
#[derive(Deserialize)]
struct GoogleTokenResponse {
    #[serde(deserialize_with = "secret_string")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "bearer_type")]
    token_type: BasicTokenType,
    expires_in: u64,
    #[serde(default, deserialize_with = "optional_secret_string")]
    refresh_token: Option<Zeroizing<String>>,
    #[serde(rename = "scope", deserialize_with = "granted_scopes")]
    scopes: Vec<Scope>,
    #[serde(deserialize_with = "secret_string")]
    id_token: Zeroizing<String>,
}
fn secret_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn optional_secret_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|value| value.map(Zeroizing::new))
}
impl fmt::Debug for GoogleTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GoogleTokenResponse(REDACTED)")
    }
}
impl Serialize for GoogleTokenResponse {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "credential serialization disabled",
        ))
    }
}
fn bearer_type<'de, D: serde::Deserializer<'de>>(d: D) -> Result<BasicTokenType, D::Error> {
    let value = String::deserialize(d)?;
    if value.eq_ignore_ascii_case("bearer") {
        Ok(BasicTokenType::Bearer)
    } else {
        Err(serde::de::Error::custom("unsupported token type"))
    }
}
fn granted_scopes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Scope>, D::Error> {
    let value = String::deserialize(d)?;
    if value.len() > 4096
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
    {
        return Err(serde::de::Error::custom("invalid scope"));
    }
    Ok(value
        .split_ascii_whitespace()
        .map(|scope| Scope::new(scope.to_owned()))
        .collect())
}

#[derive(Debug)]
struct ExchangeTransportError;
impl fmt::Display for ExchangeTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Google token exchange unavailable")
    }
}
impl std::error::Error for ExchangeTransportError {}

fn token_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .http_status_as_error(false)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(16 * 1024)
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        ureq::Agent::new_with_config(config)
    })
}

fn json_media_type(headers: &oauth2::http::HeaderMap) -> bool {
    let mut types = headers.get_all("content-type").iter();
    let Some(value) = types.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    types.next().is_none()
        && value
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn exchange_http(request: HttpRequest) -> Result<HttpResponse, ExchangeTransportError> {
    let valid = request.method() == "POST" && *request.uri() == TOKEN_URL;
    let body = Zeroizing::new(request.into_body());
    if !valid || body.len() > 16 * 1024 {
        return Err(ExchangeTransportError);
    }
    let mut response = token_agent()
        .post(TOKEN_URL)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .send(body.as_slice())
        .map_err(|_| ExchangeTransportError)?;
    let status = response.status();
    if status.as_u16() != 200 {
        let mut result = HttpResponse::new(Vec::new());
        *result.status_mut() = status;
        return Ok(result);
    }
    if !json_media_type(response.headers()) {
        return Ok(HttpResponse::new(Vec::new()));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(64 * 1024 + 1));
    response
        .body_mut()
        .as_reader()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExchangeTransportError)?;
    if bytes.len() > 64 * 1024 {
        return Ok(HttpResponse::new(Vec::new()));
    }
    // Transfer allocation ownership directly to the native zeroizing decoder.
    let mut result = HttpResponse::new(std::mem::take(&mut *bytes));
    result.headers_mut().insert(
        "content-type",
        oauth2::http::HeaderValue::from_static("application/json"),
    );
    Ok(result)
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "worker_input_tests.rs"]
mod worker_input_tests;
