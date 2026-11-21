# ADR 0016: Brokered sign-in transport for cloud action packs

Status: accepted.

## Context

A [cloud action pack](../cloud-action-packs.md) describes a provider's requests as data. Until now a hosted gateway
could send a pack action only when it held the user's sign-in itself. Many providers need an OAuth app, a security
review or a per-tenant registration before that is possible, so their packs could be written but not used.

A sign-in broker (the first is Composio) holds the provider sign-in on its side and offers a proxy: the caller sends
a method, URL, headers and body for a connected account, and the broker adds the credential and returns the
provider's status, headers and body. That lets a gateway send exactly the request Guard rendered without ever holding
the token.

The broker's proxy was measured before this decision. Its checks are useful but are not a boundary Guard can rely on:

- A host on a different registrable domain is refused, including suffix (`api.example.ai.evil.test`) and userinfo
  (`api.example.ai@evil.test`) forms.
- A host on the **same** registrable domain as the toolkit's base URL is accepted, and the credential is attached.
- A wrong owner ID for a connected account is refused, but a call that omits the owner ID is accepted: the account
  reference alone authorizes it.
- Request bodies over 4,718,592 bytes are refused. Provider errors come back as a successful proxy response with the
  provider status inside it.
- The broker's own agent features (sessions, tool search, MCP URLs, meta-tools) let a model choose and run tools.

## Decision

A connection has a **custody source**. `guard` is today's behaviour: the gateway holds the sign-in. `partner` means a
named broker holds it; the connection stores the partner name, the partner's account reference, the auth
configuration it was made with and an opaque owner ID, and never a token.

A pack may declare which partner toolkit can serve it, as data:

```json
"transports": {"partner": [{"partner": "composio", "toolkit": "outlook"}]}
```

`partner` comes from a closed list and `toolkit` from a strict slug pattern. The block grants nothing by itself: a
pack without it cannot be brokered, and a pack with it is brokered only for a service the hosted control plane has
switched on and only through a connection whose custody source is `partner`.

One owner per concern:

| Concern | Owner | What it does |
| --- | --- | --- |
| Pack schema, `transports` validation | `guard-command` (Rust) | Accepts the block only in the closed form above; reports adding it as a widening change in `diff`. |
| Request rendering | `guard-command` (Rust) | Unchanged. `render` already produces an absolute `https` URL on the action's declared host under its literal path and refuses anything else, so a brokered call uses the same rendered request byte for byte. |
| Decision | Cloud action evaluator (Rust) | Unchanged. The route does not change facts, presets, approvals or the [approval invariant](../approval-invariant.md). |
| Exact host check | Hosted gateway, before the broker call | Re-parses the rendered URL and requires its host to be one of the pack's `hosts`. This is what closes the same-domain gap above. Broker redirects are not followed. |
| Owner and account binding | Hosted gateway | Always sends the stored account reference **and** owner ID, taken only from the connection record, never from a browser, an AI tool or a model. Never lets the broker pick a default account. |
| Credential headers | Hosted gateway | Sends only the headers Rust rendered; the pack language already refuses credential-bearing header names. |
| Size and envelope | Hosted gateway | Refuses a body over the broker limit before sending; treats the provider status inside the envelope, not the outer HTTP status, as the result; runs projection and result inspection on the provider body exactly as for a direct call. |
| At-most-once sends | Hosted gateway | A side-effecting call with an unknown outcome is recorded as unknown and reconciled, never resent. |
| Broker agent features | Hosted gateway | Never issued or exposed. Only the proxy and connection management are called. |
| Credentials and network | Outside the engine | The Rust engine holds no credential, opens no connection and never learns the broker key. |

## Consequences

A provider can be used as soon as a pack and a broker toolkit exist for it, with the same decisions, approvals and
receipts as a direct connection. Decision parity between the two routes is testable by replaying each pack's
fixtures through both: facts, decision and rendered request must be identical.

The broker becomes a holder of sign-ins and, depending on its retention settings, of request payloads. Hosted
deployments must disclose that per service before switching it on.

Guard's safety on this route does not depend on the broker's domain or owner checks; both are treated as
defence in depth. If the broker removes or changes its proxy, brokered actions fail closed and direct connections are
unaffected.

Not yet decided, and tracked as risks until measured against a real OAuth provider account: what the provider's
consent screen shows, administrator-consent behaviour, whether deleting a connected account revokes the grant at the
provider, the expiry webhook and its signature, rate-limit responses under load, and how proxy calls are billed.
