# Registered worker account refresh

The worker account retains the original registered client ID/secret, approved
hosted domains and private identity binding key beside its refresh credential. These
fields come from the authenticated worker's original authorization configuration;
no browser/tool payload can supply refresh configuration or a token endpoint.
Per-input credentials contain none of this renewal material.

`GoogleSendAccount.refresh()` revokes pending inputs and waits for an admitted
bounded send before exchanging authorization. It makes one fixed POST to
`https://oauth2.googleapis.com/token`, followed by an authenticated GET to
`https://openidconnect.googleapis.com/v1/userinfo`. Both use the existing HTTPS
client with environment proxy disabled, redirects disabled, bounded responses
and a five-second request timeout. It requests no additional scopes.

The refresh response must retain the original narrow `openid`, email and
`gmail.send` purpose. Omitted response scope inherits that already verified set;
changed/excessive scopes refuse. Rotated refresh material stays private with the
owner. UserInfo must identify the same opaque account, tenant and exact verified
primary mailbox. A missing managed-domain field refuses renewal; it does not infer the
tenant from the email domain or request a broader scope to recover.
The original login used signed ID-token/nonce/access-hash
verification; renewal uses Google's access-token-authenticated UserInfo response,
not a synthetic new browser challenge or an unverified refresh ID token.
See [Google's OIDC reference](https://developers.google.com/identity/openid-connect/reference).

Identity remains fresh for at most five minutes, bounded by token lifetime and
both wall/monotonic observations. Clock rollback refuses before release. Success
creates a fresh account generation, so prior input/inspection commitments and
approvals cannot authorize newly prepared inputs, even for identical bytes.

Entropy, missing-refresh, exchange, decoding, identity or timing failure leaves
the owner unavailable. Pending inputs are revoked before generation creation.
It cannot automatically retry authorization renewal or resend a business action.
Explicit reconnect creates a new verified owner; persistent enrollment and the
reconnect/disconnect UI remain unfinished. No native worker route is enabled,
and no isolated credential custody or protected business mode is qualified.
HTTP adapter tests use an in-memory ureq transport to inspect the fixed POST/form
and GET/bearer requests and exercise response framing, media types, status errors
and size limits. They perform no DNS lookup, TLS handshake or provider call.
All tests here use synthetic provider responses, not a live Google account.
