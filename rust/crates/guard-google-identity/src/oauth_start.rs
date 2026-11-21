use super::*;

impl GoogleSendAuthorization {
    pub fn begin(
        challenge: GoogleLoginChallenge,
        secret: String,
        redirect: String,
        session: String,
    ) -> Result<Self, IdentityError> {
        Self::begin_for(GrantPurpose::Send, challenge, secret, redirect, session)
    }
    pub(crate) fn begin_directory(
        challenge: GoogleLoginChallenge,
        secret: String,
        redirect: String,
        session: String,
    ) -> Result<Self, IdentityError> {
        Self::begin_for(
            GrantPurpose::Directory,
            challenge,
            secret,
            redirect,
            session,
        )
    }
}

impl GoogleSendAuthorization {
    fn begin_for(
        purpose: GrantPurpose,
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
            .add_scope(Scope::new(purpose.scope().to_owned()))
            .set_pkce_challenge(pkce)
            .add_extra_param("nonce", challenge.nonce())
            .add_extra_param("access_type", "offline")
            .add_extra_param("include_granted_scopes", "false")
            .add_extra_param("prompt", "select_account consent")
            .url();
        Ok(Self {
            purpose,
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
}
