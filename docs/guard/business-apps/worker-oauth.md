# Worker-owned Google authorization

`guard_google_identity::oauth::GoogleSendAuthorization` implements the registered
server-flow authorization/code-exchange step for a credential-owning worker.
It requests only `openid`, `email` and `gmail.send`; it supplies no account enrollment,
execution authority, isolation proof, public RPC or Core setup route.

The authenticated worker constructs a `GoogleLoginChallenge` with its registered
client, approved hosted domains and namespace key. Reconnecting an enrolled
account must pin its existing binding before beginning authorization. The worker
then passes its registered secret, exact HTTPS redirect URI and authenticated
client-session binding. These configuration values must never come from browser,
model, callback or tool arguments. Redirect URIs with userinfo, query or fragments
are refused. Constructor validation cannot prove actual Google registration.

The resulting authorization URL includes a random OAuth state, separate S256
PKCE challenge, the owned ID-token nonce and only the fixed scope set. It asks
for offline access and account selection/consent without combining older grants.
The URL carries no client secret or PKCE verifier. The worker retains the session;
its browser/client receives only the URL. Do not log callback codes or URLs.

The callback owner must authenticate the initiating client session independently
and re-derive its binding from server context. Supplying a callback query/body
field as that binding is invalid integration. `complete` consumes the owned
session on success or failure. State mismatch, session mismatch, malformed code
and expired challenge cause zero token exchange. Successful exchange uses the
owned PKCE verifier, registered redirect/client and secret.

Exchange uses only `https://oauth2.googleapis.com/token`, POST and form encoding.
The HTTP adapter accepts no alternate URI/method; redirects and environment
proxies are disabled. It uses WebPKI TLS, a five-second request/body deadline,
16-KiB headers, 16-KiB outgoing body and 64-KiB response limits. Neither browser
bearer tokens nor caller-selected endpoints are forwarded. Public signing-key
retrieval remains separate and carries no ID/access/refresh token. A process-owned
HTTP agent pools connections. Responses must have exactly one JSON media type.
The owned outgoing form buffer is zeroized after use.

The native response decoder rejects known duplicate fields and requires actual
reported scopes, a bounded Bearer token, a one-hour-or-shorter positive expiry
and an ID token. Missing, extra or duplicated scopes are refused; requested
scopes are not silently substituted for missing granted scopes. Google signature,
issuer/audience, tenant, nonce and actual access-token hash are then verified.
Send credentials additionally require a signed, verified, bounded bare ASCII
`email`. The returned grant must contain exactly the three requested scopes;
Google's canonical `userinfo.email` spelling is accepted for the email scope.
The signed `hd` remains the tenant check; the mailbox domain does not select a
tenant. Stable account binding still uses `sub`, so an email change does not
retarget account identity. The private mailbox is never exported by the evidence
API. `authenticates_sender` compares its exact spelling and enforces credential
expiry. Alias, case, dot and plus normalization cannot establish send-as rights.
Admission clocks are checked again after exchange and key retrieval.
Token expiry starts before the exchange, so its latency cannot extend a short
lease. Currentness also has a monotonic deadline; a wall-clock rollback cannot
extend the access-token or admitted evidence lease.

`GoogleSendCredential` retains access/optional refresh material in zeroizing
strings. It has no Clone, Debug, serialization or token getter. Its public
surface exposes only identity evidence, expiry, currentness and whether a
refresh credential exists. Generic token-response serialization fails; its
diagnostic text is redacted. Currentness is bounded by fresh login evidence;
refresh, durable enrollment and renewal are not implemented. Presence of a
refresh token does not prove a successful refresh or offline protection.
Pending client secret, state, PKCE verifier, authorization URL and native callback
code are zeroizing buffers. The OAuth SDK supplies authorization URL, state and
PKCE generation. The fixed native code exchange uses its form encoder and owns
request/response buffers; successful decoded ID/access/refresh fields are
zeroizing even when another field subsequently fails decoding. Credentials move
into retention without copying. Transport failures, HTTP 429 and server failures
return `ExchangeUnavailable`; refused or malformed grants return `Invalid`.
TLS, HTTP internals and JSON decoder scratch allocations may retain transient
copies that this library cannot guarantee to erase. These cleanup controls do not prove service isolation or
whole-process memory erasure.

No worker is launched, account is granted, credential is saved, Gmail action is
dispatched or browser setup UI is activated by this library. It must be joined
to the existing authenticated Core setup/private review/managed transport and
the selected customer-operated service identity. Same-user local custody remains
insufficient for a strict-mode claim. Actual registration, callback/session
authorization, isolated custody, provider permissions, refresh, managed dispatch
and non-engineer journeys require their own implementation and evidence.

Tests feed synthetic code-exchange responses through real PKCE/request encoding,
owned state and Google RSA verification. They count exchange calls and verify
that failures cannot admit credentials. They do not contact the authorization
or token endpoint, grant scopes, authenticate a real account or prove an agent
cannot read another process. All business acceptance scenarios remain unqualified.

Primary reference: [Google server-side OAuth](https://developers.google.com/identity/protocols/oauth2/web-server).
