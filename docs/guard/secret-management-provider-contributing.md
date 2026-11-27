# Contributing a Secret Provider

This guide is for a first-party or external team contributing a secret provider to HOL Guard. It extends the
general [extension contribution guide](extensions/contributing.md) with secret-specific data-flow and qualification rules.
The [secret provider contract](secret-management-provider-contract.md) and [PRD](secret-management-prd.md)
are authoritative when this guide is ambiguous.

## Contribution boundary

A provider contribution contains a manifest, a reviewed typed adapter, synthetic fixtures, a privacy statement,
generated trust metadata and conformance evidence. It does not contain a shell script, provider CLI invocation,
downloaded code, arbitrary callback, unbounded HTTP client or secret value.

Guard owns

- reference parsing and canonical digests
- local policy and approval decisions
- native connection storage
- delivery sinks and child-process lifecycle
- redaction, audit metadata and provider failure behavior
- local administrator enablement and external opt-in

The provider owns

- mapping a declared reference to its provider API
- translating provider version, lease, revocation and availability state
- documenting supported authentication and scope
- maintaining public provider documentation and compatibility evidence

The provider cannot grant an allow, weaken a Guard floor, select a sink, read an arbitrary local credential,
or receive values through Guard telemetry.

## Before writing code

1. Read `docs/guard/secret-management-prd.md`, `secret-management-todo.md`,
   `secret-management-threat-model.md` and `secret-management-provider-contract.md`.
2. Read `docs/guard/approval-invariant.md` before touching approval or retry behavior.
3. Choose synthetic fixture names, hosts, account ids and values. Do not copy a private checkout, customer
   tenant, provider endpoint, local path or real secret into the contribution.
4. Decide whether the adapter is a native first-party backend, a typed HTTPS provider, a customer-hosted
   connector or a workload-identity transport.
5. Document the provider API version, authentication scope, version behavior, lease behavior, audit behavior,
   rate limits and rotation behavior using public provider sources.
6. Agree on whether the first capability is metadata, resolve, verify or lease. Write capabilities as a closed
   set rather than a provider-specific string list.

## Repository artifacts

The normal contribution contains

```text
contributions/secret-providers/provider.<slug>.json
contracts/extensions/trust/provider.<slug>.v1.json      generated
tests/fixtures/secret-provider-<slug>.v1.json
docs/guard/secret-providers/<slug>.md
```

Typed adapter code belongs in the reviewed Rust crate selected by the implementation owner. Do not place
runtime logic in the manifest or fixture JSON. Add new generated source inputs to the native build list when
the crate participates in command projection.

## Manifest requirements

The manifest must use `guard.secret-provider.v1` and declare

- stable provider id, publisher id and display name
- external or first-party status and `default_enabled: false` for external providers
- authentication modes and a native credential scope
- exact HTTPS host and port, or a reviewed local transport
- paths, methods, request and response bounds, timeout, retry count and redirect policy
- closed capabilities and declared delivery sinks
- scope, name, field and version selectors
- strict response pointers for metadata, value, version and lease fields
- privacy fields that state values and connection credentials are not shared
- public setup, privacy and terms links where appropriate
- sponsor label and referral link as presentation data only

The compiler must reject

- wildcard hosts, IP literals and unreviewed private endpoints
- non-HTTPS remote endpoints
- query-string or path credentials
- redirects or host changes
- arbitrary command, script, regular-expression callback or downloaded code fields
- undeclared capabilities, response pointers, delivery sinks or auth modes
- unbounded request, response, nesting, field, timeout or retry values
- remote icons or assets that are loaded at decision time
- a value-bearing fixture or telemetry share declaration

## Adapter requirements

- Use typed Rust request and result types.
- Keep provider network calls off the ordinary hook path. Use the broker worker and bounded cache.
- Use the managed egress policy and exact host checks.
- Treat response content as untrusted. Validate content type, body size, depth, fields and version before
  creating a resident value.
- Do not log request bodies, authorization headers, provider values or raw response bodies.
- Return metadata and errors separately from the resident value.
- Zeroize or drop resident values at the delivery boundary where the platform and API permit it.
- Treat provider errors, stale data, revoked credentials, redirect attempts and rate limits as typed states.
- Keep provider-specific auth, version, lease and audit behavior behind the adapter. Do not add provider
  branches to generic Guard policy.

## Fixture requirements

Use synthetic values such as `fixture-value-7` and synthetic hosts such as `vault.example.test`. Fixtures must
cover

| Case | Required assertion |
| --- | --- |
| Metadata success | No value is loaded or returned |
| Resolve success | Value reaches only the selected synthetic sink |
| Disabled provider | No network or value delivery occurs |
| Missing connection | Typed unavailable result |
| Expired or revoked connection | Cache invalidated and no new delivery |
| Pinned version | Resolved version enters the approval and cache binding |
| Changed version | Old approval cannot be reused |
| Lease expiry | Expiry is visible and value is not renewed implicitly |
| Malformed response | No value delivery and bounded error |
| Unknown field | Contract rejection before value extraction |
| Redirect or wrong host | One request at most and no second host request |
| Oversized response | Rejected before unbounded allocation |
| Timeout and retry | Retry cap and unavailable state are deterministic |
| Output reflection | Child output is redacted or operation stops according to policy |
| Changed destination | New approval required |
| Changed process | New approval required |

Every protected case has a benign counterpart on the same driver. Journals contain request method, synthetic
host, bounded status and digests. They never contain values or credentials.

## Privacy statement

The contribution must include a public statement that answers

- which provider metadata Guard sends
- which connection credential is used and where it is stored
- whether the provider sees the canonical reference or a provider-local mapping
- which version, lease, audit and error metadata Guard retains
- whether any secret value leaves the local broker or target process
- which optional cloud or sponsor metadata is exported
- retention, deletion and provider-side audit behavior

The default statement should say that Guard does not export secret values, provider credentials, raw response
bodies, prompts, command text or workspace contents.

## Conformance and validation

Run the generated contribution flow rather than hand-editing generated artifacts.

```text
hol-guard --version
hol-guard extensions generate --secret-provider
hol-guard extensions validate --secret-provider
hol-guard command explain '<synthetic-sensitive-case>'
```

Use the repository's pinned Rust and Python commands for focused tests. Add the exact crate and test path to
the pull request. Run `git diff --check`, schema checks, generated projection checks, fixture replay and
redaction tests.

The installed Guard section records

- released Guard version
- agent and harness used
- safe and sensitive `command explain` results
- provider manifest and trust-binding digests
- conformance result
- exact candidate and installed runtime evidence
- platform and provider API version
- unavailable tests and their reason

Never approve your own Guard request. Do not request or paste a one-time authentication code into public
artifacts. Use a user-controlled setup step when provider sign-in requires interactive action.

## Sponsor and marketplace rules

- Sponsorship may fund adapter code, test lanes, documentation or support.
- A listing has a visible sponsor label and a public setup link.
- Referral attribution contains no device id, account id, local path, provider token or secret reference value.
- Payment cannot change provider trust, conformance, ranking of security findings, approval choices or sink
  permissions.
- A verified-publisher or conformance badge is earned from evidence and review. It is not purchased.

## Review checklist

- [ ] Manifest uses the current closed schema.
- [ ] External provider remains disabled until local enablement.
- [ ] Adapter contains no shell, CLI, arbitrary URL, redirect or unbounded parser path.
- [ ] Authentication and provider scope are documented.
- [ ] Connection credentials are stored through the native secure-store flow.
- [ ] Values are absent from logs, receipts, telemetry, fixtures and public text.
- [ ] Approval binding includes provider, connection, reference, version, capability, sink, process,
      workspace, purpose, policy and extension digests.
- [ ] Provider results cannot lower a Guard decision.
- [ ] Metadata, unavailable, malformed, stale, revoked, changed-binding and value cases have fixtures.
- [ ] Benign counterparts exist for protected cases.
- [ ] Allow once and Always allow remain available where review is supported.
- [ ] Conformance, focused tests, generated checks and installed Guard evidence are attached.
- [ ] Public-surface scan is clean.
