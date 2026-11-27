# Secret Provider Contract Proposal

This is the proposed wire and contribution contract for the [secret-management PRD](./secret-management-prd.md).
It is intentionally narrower than a general vault SDK. A provider contributes a bounded adapter and evidence.
Guard owns authorization, delivery, redaction, approval reuse and fail direction.

## Contract goals

- Make native and external providers look the same to the broker.
- Keep provider-specific authentication and response details behind a typed adapter.
- Reject unsafe manifests before packaging or runtime use.
- Let a sponsor fund an adapter, fixtures or support without gaining runtime authority.
- Make offline replay and installed-runtime qualification possible without real credentials.

## Versioning

- Manifest version is `guard.secret-provider.v1`.
- Secret reference version is `guard.secret-reference.v1`.
- Request and result envelopes are versioned typed Rust contracts.
- Unknown persisted or signed fields are rejected. New optional fields require a schema version or an
  explicitly documented forward-compatible section.
- A provider id is lowercase ASCII with a bounded length and a publisher-owned scope. A provider id
  cannot be changed in place after publication. A new id and trust binding is required for a breaking change.

## Secret reference

Canonical form

```text
guard-secret://<provider>/<scope>/<name>[#<field>][?version=<selector>]
```

Rules

- `provider`, `scope` and `name` are required and normalized as UTF-8 segments with no control
  characters, traversal, empty decoded segments or ambiguous percent encoding.
- `field` is optional and refers to a declared structured field. A provider cannot return an undeclared
  field through a generic pointer.
- `version` is optional. It can be `latest`, a provider version id or a provider generation declared by the
  manifest. A pinned version is the default for high-risk or dynamic credentials.
- The reference carries no value, token, URL, query credential or local file path.
- The display label is separate from the canonical reference and is sanitized before it enters a card.
- The broker computes a canonical reference digest. Approval and cache state use the digest, not raw display
  text.

## Manifest shape

The schema at `contracts/secret-providers/secret-provider.v1.schema.json` should enforce this conceptual
shape. The exact JSON Schema remains the source of validation once added.

```json
{
  "schema": "guard.secret-provider.v1",
  "id": "provider.examplevault",
  "publisher": {
    "id": "publisher.example-org",
    "display_name": "Example Org"
  },
  "display_name": "Example Vault",
  "status": "external",
  "default_enabled": false,
  "connection": {
    "auth": ["oidc_workload", "api_token"],
    "credential_scope": "provider.examplevault.connection"
  },
  "endpoints": [
    {
      "scheme": "https",
      "host": "vault.example.test",
      "port": 443,
      "paths": ["/v1/example/data/{scope}/{name}"],
      "redirects": false
    }
  ],
  "capabilities": ["secret.metadata", "secret.resolve", "secret.lease"],
  "references": {
    "scope_pattern": "^[a-z0-9][a-z0-9._-]{0,62}$",
    "name_pattern": "^[a-z0-9][a-z0-9._-]{0,62}$",
    "fields": ["value", "username"],
    "versions": ["latest", "pinned"]
  },
  "limits": {
    "request_bytes": 8192,
    "response_bytes": 1048576,
    "json_depth": 8,
    "timeout_ms": 3000,
    "retries": 1
  },
  "delivery": ["environment", "stdin", "file_descriptor"],
  "responses": {
    "metadata_pointer": "/data/metadata",
    "value_pointer": "/data/value",
    "version_pointer": "/data/version",
    "lease_pointer": "/data/lease"
  },
  "privacy": {
    "shares": ["provider_id", "capability", "reference_digest", "version_digest", "outcome"],
    "shares_secret_values": false,
    "shares_connection_credentials": false
  },
  "sponsor": {
    "label": "Sponsored integration",
    "public_url": "https://example.test/guard"
  }
}
```

The example is synthetic. `example.test` and the example publisher are fixture-only names and must not be
copied into a real provider contribution without an explicit public review.

## Closed capability set

Initial capabilities

- `secret.metadata` returns provider, reference, version and availability metadata without a value.
- `secret.resolve` returns one value to the broker for a selected delivery sink.
- `secret.lease` returns lease metadata and an optional value for providers with dynamic credentials.
- `secret.verify` checks provider connection or reference availability without returning a value.

Deferred capabilities

- `secret.renew` renews a lease with a fresh approval.
- `secret.revoke` revokes a lease or connection with a fresh approval.
- `secret.write`, `secret.rotate` and `secret.delete` mutate provider state and require separate contracts,
  cards and recovery semantics.

A manifest that names an unknown capability is rejected. A provider cannot create a new capability by adding
a string to JSON.

## Authentication modes

Allowed mode names are closed and map to reviewed adapter implementations.

- `native_keychain`
- `api_token`
- `oauth_device`
- `oauth_loopback`
- `oidc_workload`
- `spiffe_workload`
- `local_peer`

Connection credentials are written through a native setup flow and stored under the manifest's credential
scope. A manifest cannot request an arbitrary environment variable, read a credential file, invoke a
provider CLI or ask an agent to paste a token.

## Request envelope

The broker creates a request with metadata only.

```json
{
  "schema": "guard.secret-request.v1",
  "request_id": "req.synthetic-001",
  "provider_id": "provider.examplevault",
  "connection_id": "conn.digest",
  "reference_digest": "ref.digest",
  "capability": "secret.resolve",
  "version_selector": "pinned",
  "destination": {
    "kind": "environment",
    "name": "EXAMPLE_TOKEN",
    "process_digest": "proc.digest"
  },
  "workspace_digest": "workspace.digest",
  "purpose": "synthetic-test",
  "policy_digest": "policy.digest",
  "extension_digest": "extension.digest"
}
```

The request is not sent to a provider as-is. The adapter maps it to the provider API and redacts the request
journal. `request_id` and all digests are synthetic in fixtures.

## Result envelope

Provider results are split so metadata can be handled without loading a value.

```json
{
  "schema": "guard.secret-result.v1",
  "provider_id": "provider.examplevault",
  "reference_digest": "ref.digest",
  "state": "available",
  "version_digest": "version.digest",
  "lease": {
    "lease_digest": "lease.digest",
    "expires_at": "2030-01-01T00:00:30Z",
    "renewable": false
  },
  "metadata": {
    "content_type": "opaque",
    "updated_at": "2030-01-01T00:00:00Z"
  }
}
```

The value is a resident field on an internal Rust type and is never part of this outward envelope. The type
must not implement outward `Debug`, `Serialize` or `Display`. It is consumed exactly once by the delivery
layer unless a provider lease explicitly permits a bounded reuse.

## Result states and errors

| State or error | Meaning | Delivery behavior |
| --- | --- | --- |
| `metadata` | Metadata returned without a value | No value sink is opened |
| `available` | Value is available for the bound request | Require approval and sink validation |
| `stale` | Cached or provider version cannot satisfy the selector | Require refresh or return unavailable |
| `unavailable` | Store, provider, identity or network is unavailable | No new value delivery |
| `revoked` | Connection, lease or version is revoked | Invalidate cache and covering grant |
| `malformed` | Response or manifest violates the contract | Reject and record bounded error |
| `changed_binding` | Destination, process, workspace, policy or extension changed | Require a new decision |
| `unsupported_sink` | Requested delivery sink is not enabled on this platform | Return a typed error |
| `approval_required` | Valid request has no matching decision | Show a review with supported choices |

Provider state cannot turn `block` into `allow`. A failure may produce a user-visible unavailable state, but
it must not cause a prompt that can never execute.

## Delivery contract

The broker accepts only sinks declared by both provider and local policy.

- `environment` sets one named variable in a disposable child process.
- `stdin` writes the value to a pipe and closes it at the operation boundary.
- `file_descriptor` passes a private descriptor with a bounded lifetime where the platform supports it.
- `file` is deferred and requires a separate lifecycle and cleanup review.

The following are always rejected by the secret API: agent text, command arguments, URLs, query strings,
clipboard, shell history, workspace files, receipts, telemetry and dashboard response bodies.

## Approval and cache binding

The exact binding includes

- provider id and manifest digest
- connection id and authentication mode
- canonical reference digest and field
- version selector and resolved version digest
- capability and lease digest when present
- delivery sink, destination name and child-process digest
- workspace, purpose, policy digest and extension digest

The binding excludes the secret value. A change to any included field invalidates the covering approval. A
provider value rotation with the same name changes the resolved version or generation and therefore cannot
silently reuse a pinned approval.

## Hooks

The initial hook names are closed.

- `pre_tool.secret_request`
- `pre_exec.secret_delivery`
- `post_tool.output`
- `lease.expiring`
- `provider.revoked`
- `cloud.policy.updated`

Hook payloads contain request metadata, digests, bounded error codes and delivery outcome. They do not contain
values, provider credentials, raw response bodies or arbitrary provider fields.

## Provider trust binding

Each shipped provider has a generated binding containing

- provider id and manifest digest
- publisher id and verification state
- schema and adapter version
- external or first-party status
- local enablement requirement
- supported capabilities and platforms
- conformance evidence digest

The binding is generated from the contribution directory. It is not hand-edited to grant authority.

## Fixture and conformance requirements

Every provider contribution ships synthetic offline fixtures for

- metadata success
- value success through each declared sink
- disabled provider
- missing connection
- expired or revoked connection
- pinned version and changed version
- lease expiry and renewal refusal
- malformed JSON
- unknown fields
- redirect
- wrong host
- oversized response
- timeout and bounded retry
- output reflection
- changed destination and changed process

The conformance command checks schema, manifest labels, declared shares, deterministic response mapping,
no added prompt for metadata, approval choices for value delivery, bounds, redaction and outage behavior.

## Compatibility and migration

- Existing direct environment and sensitive-file classification remains active.
- Existing approval tokens and internal encrypted-file state keep their current semantics.
- A provider integration cannot silently reinterpret an existing raw read as a safe reference.
- A release can disable external provider routes while leaving native raw-read floors and existing Guard
  protections available.
- Schema and trust changes require generated artifacts and a new conformance report.

## Public contribution checklist

- Manifest uses synthetic fixture values and public provider documentation.
- Adapter has no shell or provider CLI dependency.
- Connection credential scope and rotation are documented.
- Privacy statement lists every metadata field shared and states that values are not shared.
- Contract and fixture tests pass from a clean checkout.
- Installed Guard version and conformance evidence are recorded without local paths or private endpoints.
- Sponsor label and referral URL are presentation-only and are excluded from policy inputs.
