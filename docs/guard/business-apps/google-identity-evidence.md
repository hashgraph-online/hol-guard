# Native Google identity evidence

`guard-google-identity` validates a bounded Google server-flow ID token against
the actual access token held by a credential-owning worker. It supplies identity
evidence, not account enrollment, credential-isolation proof or execution authority.
It is not connected to hook facts, a public RPC or managed dispatch. Existing
business-context refusal remains in place.

The worker creates a non-cloneable, non-serializable login challenge with a fresh
256-bit nonce. Client ID, approved hosted domains and the tenant pseudonym key must
come from authenticated worker configuration. They must never come from browser,
model or tool arguments. The callback must separately validate its OAuth state and
complete the registered OAuth flow. The `oauth` module now supplies a bounded
registered code-exchange session; authenticated callback routing and worker
configuration remain the caller's responsibility. See
[worker OAuth](worker-oauth.md).

Verification consumes the challenge on success or failure. It requires RS256,
Google issuer, exact intended audience, matching authorized presenter when present,
the worker nonce, an approved signed `hd`, a bounded stable ASCII `sub`, current
expiry and fresh issue time. `at_hash` must match the actual access token. Optional
presenter/type fields reject explicit null. Unsupported algorithms, key URLs and
critical JWT headers are refused. Known duplicate fields and noncanonical base64url
are refused. Admission time is checked again after key retrieval.

Public signing keys come only from Google's fixed HTTPS key endpoint. No caller
can supply a URL or key set. Redirects and environment-selected proxies are
disabled; TLS uses the library's WebPKI roots. Retrieval has a five-second deadline,
16-KiB header limit and 64-KiB body limit. A serialized bounded public-key cache
honors published max-age and Age, capped locally at one hour; no-cache/no-store
or invalid directives prevent reuse. Expired keys are never an outage fallback.
Unknown key IDs get at most one early refresh per 30 seconds. Unique key IDs are
checked across the set, but RSA/algorithm/use checks apply to the selected key so
an unrelated algorithm does not disable valid Google logins. Token bytes are never sent to Google
tokeninfo or the key endpoint. Errors carry no token or claim text.

The public evidence API exposes only account and tenant HMAC bindings plus expiry.
Private evidence may also retain a signed verified primary mailbox for the
worker's exact-sender comparison. Generic identity verification without a verified
mailbox still yields identity evidence; send-credential admission refuses it.
Account identity includes namespace, registered client, canonical issuer, hosted
domain and stable Google subject. Email changes do not retarget it; namespace,
client, domain or subject changes do. The tenant binding is an approved hosted-domain
binding, not a Google customer ID. Existing-account verification can require its
previous binding, rejecting another valid subject in the same domain.

Evidence has no serialization, clone or diagnostic implementation. It does not
prove Gmail scopes, mailbox aliases, recipient/group expansion, CLI identity,
endpoint mediation, client-facing authorization or separation from an agent.
A trusted producer must enforce expiry and its authenticated account selection
before preparing and dispatching a business action. No producer is added here.

Tests use generated synthetic RSA keys held only in memory. A separately invoked
read-only test checks the actual public key endpoint and key shape; it is not a
Google account or agent qualification. OAuth registration, actual consent,
callback routing, refresh, isolated custody, managed transport and user journeys
remain unfinished. Code-exchange behavior has synthetic protocol evidence only.

Primary references: [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect)
and [Google discovery metadata](https://accounts.google.com/.well-known/openid-configuration).
