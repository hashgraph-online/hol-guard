# Private Google directory preparation

The registered customer worker uses a separate `GoogleDirectoryAuthorization`
flow for `openid`, `email` and `admin.directory.user.readonly`. Send and directory
grants are distinct: neither can be used for the other's operation. Registered
configuration and the customer ID come from the authenticated worker, while
callback state, PKCE, nonce and client-session checks reuse the existing flow.
Successful authorization supplies evidence rather than account enrollment.

`GoogleDirectoryCredential::resolve_owned_input` consumes an inspected immutable
send input. It retrieves the sender and each literal recipient from the fixed
Google Directory users endpoint with a fixed projection. Caller-selected hosts,
methods, fields and bearer tokens are unavailable. Redirects and environment
proxies are disabled, requests have a five-second timeout, and responses are
bounded to 64 KiB. The pilot accepts at most eight recipient entries and the
complete resolution has a strict 15-second admission budget. Slow lookup fails
closed even when recipient syntax is valid; there is no bulk latency guarantee.

Rows must identify individual users in the registered customer, with an active
account, a bounded revision and an exact primary or provider-reported alias
match. Missing fields, duplicates, extra fields, ambiguous aliases, groups,
suspended/archived users and unavailable responses cannot yield complete facts.
Multiple literal aliases of one resolved principal refuse rather than inflate
the audience count. Repeated identical mailboxes across To/Cc/Bcc count once.
The grant and input retain matching namespace/hosted-tenant evidence. Returned
private principal commitments use the customer's namespace key. No row, raw
address or token is serialized by these owned types.

Preparation derives `BusinessActionV1` from the verified input. The frozen primary
bytes are the original validated Gmail JSON body; decoding and inspecting its
MIME covers the content represented by those bytes. Recipients retain their
To/Cc/Bcc roles, with mailbox commitments and domains derived from directory
evidence. Content is conservatively labeled Personal and Confidential. Absence
of a credential finding never produces a Public label. The detector version and
input binding are committed by inspection, and the provider revision is committed
by resolution. This profile requires UTF-8 and unencoded header text; encoded-word
markers in headers refuse before clean inspection. This is bounded credential
inspection, not full DLP qualification.

The native `prepare_google_review` producer accepts only this owned prepared type.
Under the existing transition lock it reads current signed policy, checks the
business floor, persists the existing private input/request schema, authenticates
the native origin and reloads the result. Body bytes remain in the private input;
request metadata carries bindings. Disabled business policy and blocked actions
cannot publish a review. Failed preparation removes newly created matching files under the
transition lock, preserves existing shared input and refuses request ID collisions.
Cleanup failure is reported explicitly because private files may remain.
The held review refreshes directory evidence before an
owned claim and rejects changed revisions or expired evidence. The existing
single-use decision authority releases frozen bytes once and refuses replay.
Expiry after consumption leaves the decision spent without allowing provider
dispatch. A caller must prepare and approve a new request rather than retry it.

No public worker route, callback integration, account enrollment, controlled
provider dispatch, durable outcome/budget handling, isolated custody or setup UI
is enabled by these APIs. Directory membership does not prove forwarding settings.
Review revisions require a fresh provider lookup; unsupported groups remain
unresolved. Tests use synthetic authorization and directory responses, with
native private-store/claim tests using synthetic authority keys. They do not
qualify an installed or live account mode.

Primary references: [Directory users.get](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/get)
and [Google OIDC](https://developers.google.com/identity/openid-connect/reference).
