# Secret Management and Secret Reads Threat Model

This model covers the proposed local broker, native secure stores, external provider adapters, bounded
delivery sinks and future metadata-only cloud policy. It is a design input for the [PRD](./secret-management-prd.md),
not a claim that these components already exist.

## Security objectives

1. A secret value is available only to the user-approved operation and the selected delivery sink.
2. A provider, sponsor, cloud policy or network response cannot weaken a Guard floor or create an allow.
3. A changed reference, provider connection, version, destination, process, workspace or policy cannot reuse
   an old approval.
4. Secret values are absent from agent text, command arguments, URLs, files, logs, receipts, telemetry,
   dashboard responses and public artifacts by default.
5. Provider failures are bounded and visible without causing a fail-open delivery.
6. Local administrators can remove providers, credentials, grants and cached metadata.

## Assets and owners

| Asset | Examples | Primary owner | Required treatment |
| --- | --- | --- | --- |
| Secret value | API token, password, signing material, dynamic credential | User or provider | Resident only, zeroized where practical, never serialized outward |
| Connection credential | Provider token, OAuth refresh token, service-account exchange result | User or provider | Native secure store, write-only setup, scope and rotation |
| Secret reference | Provider, scope, name, field and version selector | User and policy | Canonicalized, digest-bound, safe display label |
| Lease metadata | Lease id digest, expiry, renewal and revocation state | Provider and Guard | Metadata only in audit and cloud exports |
| Approval decision | Exact-action token, scope, expiry and binding | Guard | Preserve Allow once and Always allow, hash-bound |
| Provider manifest | Host, capabilities, response pointers, bounds and publisher | Guard and publisher | Closed schema, signed or digest-bound, external opt-in |
| Policy | Local settings, managed policy digest and expiry | Local administrator | Tightening composition, signed and expiring |
| Audit metadata | Request, approval, delivery, failure, rotation and revocation events | User or tenant | No values, bounded references, retention and deletion controls |
| Sponsor metadata | Listing, label, referral link and conformance badge | Guard and sponsor | Presentation only, no policy input |

## Actors

| Actor | Intended authority | Adversarial behavior considered |
| --- | --- | --- |
| User | Store, approve, revoke and use a credential | Accidental disclosure, unsafe copy or overbroad grant |
| Agent | Request a reference and invoke an approved operation | Prompt injection, confused deputy, repeated retries, output reflection |
| Local process | Receive a bounded delivery | Child process writes environment, stdin or output to an unsafe sink |
| Provider | Resolve metadata or a secret within declared scope | Malformed response, overbroad scope, outage, revoked credential, hostile content |
| Provider publisher | Ship manifest and adapter | Supply arbitrary command, URL, redirect, oversized body or misleading capability |
| Sponsor | Fund or promote an integration | Buy placement, influence policy or request telemetry values |
| Cloud policy service | Tighten fleet policy and export metadata | Stale, compromised, unavailable or overbroad policy |
| Local attacker | Read process, files, IPC or logs | Memory scraping, environment inspection, symlink or path races, clipboard capture |
| Remote attacker | Control provider endpoint, network or response | TLS interception, DNS confusion, replay, redirect, response injection |

## Trust boundaries

### B1 Agent and hook boundary

Agent input is untrusted. The hook receives a structured request and should pass only metadata and digests
into the native decision engine. A free-form prompt, tool argument or environment read cannot authorize a
secret.

### B2 Native broker and platform-store boundary

The broker calls Keychain, Secret Service or Credential Manager through a typed platform trait. The store
returns a resident value or a typed failure. Store lookup attributes are treated as metadata and do not carry
the value.

### B3 Broker and child-process boundary

Materialization crosses into a child process through a named sink. The broker owns lifecycle, cancellation,
cleanup and output handling. The child is not trusted to preserve confidentiality after receipt.

### B4 Broker and provider boundary

Provider requests cross a network or reviewed local transport. A manifest declares the exact host, method,
paths, bounds and response pointer. The provider is untrusted evidence and cannot decide Guard policy.

### B5 Runtime and cloud-policy boundary

Cloud policy can tighten local behavior and report metadata. It cannot enable a disabled provider, deliver a
secret by default, grant an approval or replace a local floor. An unavailable or expired policy is handled
according to the last valid bounded state.

### B6 Public-surface boundary

Provider manifests, conformance reports, sponsor listings and pull-request text are public. They must not
contain local paths, credentials, private endpoints, account identifiers, request ids or secret-like values.

## Threats and mitigations

| ID | Threat | Attack path | Mitigation | Proof |
| --- | --- | --- | --- | --- |
| T01 | Agent receives a value in text | Broker returns value to tool or review card | Delivery-only API, value-free cards, direct-read block | Hook replay and card snapshot tests |
| T02 | Value leaks through command arguments | Agent expands `--token <value>` | Named sink validation rejects argument delivery | Process argv journal with placeholders |
| T03 | Value leaks through URL or query | Adapter builds URL with credential | Schema rejects query credentials, typed request builder | Manifest rejection and request journal |
| T04 | Value persists in a workspace file | Provider output is written to `.env` or temp file | Environment, stdin and fd first, file sink disabled or bounded | Sink policy and cleanup tests |
| T05 | Value enters logs or receipts | Error or `Debug` formats secret-bearing type | Non-serializable types, redaction wrapper, output scanner | Panic, tracing and snapshot tests |
| T06 | Value enters cloud telemetry | Broker exports request payload | Metadata-only event schema and value injection tests | Export fixture contains no value |
| T07 | Approval reused after rotation | Same reference resolves a new version | Bind resolved version or generation and invalidate on change | Property test changes version |
| T08 | Approval reused for another sink | Environment grant applied to file or stdin | Destination and sink in exact binding | Cross-sink replay tests |
| T09 | Approval reused by another process | Child identity or workspace changes | Process, workspace, purpose and policy digest in binding | Process identity vectors |
| T10 | Always allow becomes a blanket grant | Provider or reference omitted from key | Exact canonical reference and provider connection binding | Hash vectors and persisted-token tests |
| T11 | Provider creates an allow | Provider returns safe verdict or sponsor signal | Provider result can only tighten policy | Composition property tests |
| T12 | Malicious manifest executes code | Manifest names a shell command or script | Closed manifest, typed adapter only, no subprocess route | Compiler rejects command fields |
| T13 | Malicious manifest reaches arbitrary host | Host wildcard, IP literal or user URL | Exact HTTPS host, explicit self-hosted proof, no redirects | Schema and compiler tests |
| T14 | Response exhaustion | Provider returns huge body or nested JSON | Byte, depth, field and timeout caps before allocation | Oversized and nesting fixtures |
| T15 | Redirect escapes trust boundary | Endpoint redirects to a credential collector | Redirects disabled and final host checked | Redirect fixture and HTTP client test |
| T16 | Stolen provider token is overpowered | Connection uses administrator credential | Scoped machine account or workload identity, read-only capability | Provider setup scope evidence |
| T17 | Long-lived bootstrap credential leaks | Service-account key in file or env | Prefer OIDC, WIF, JWT, SPIFFE or short-lived exchange | Adapter auth matrix and docs |
| T18 | Provider outage causes fail-open | Cache or stale state returns value without policy | Typed unavailable and stale states, no new delivery | Offline replay and expiry tests |
| T19 | Revoked lease remains usable | Broker ignores revocation or expiry | Lease state and expiry in request, bounded cache | Revoke and expiry tests |
| T20 | Retry consumes another request's grant | Pending requests share a token | Request id, exact action digest and destination in retry binding | Concurrent retry test |
| T21 | Child process reflects value | Command prints env or sends value to output | Output redaction, sink warning and fail direction | Reflection fixture |
| T22 | Child crash leaves residue | Crash before cleanup | RAII cleanup, process termination handling and sink owner | Crash and cancellation tests |
| T23 | Local attacker reads process memory | Secret resident too long | Short lifetime, zeroization wrappers, optional OS isolation | Lifetime and drop tests |
| T24 | Local attacker reads environment | Child process has environment access | Explicit sink review, scoped child and cleanup | Process inspection test on supported runner |
| T25 | Store metadata reveals sensitive names | Attributes include token or account details | Canonical safe labels and bounded metadata fields | Attribute redaction tests |
| T26 | Native store fallback weakens security | Headless backend writes plaintext or internal file | Explicit unavailable result, no silent fallback | Unsupported backend test |
| T27 | Provider response triggers prompt flood | Repeated stale or malformed responses | One bounded review per request, cached metadata and caps | Prompt-budget fixtures |
| T28 | Provider swaps identity | DNS or connection changes endpoint | Exact host, TLS verification, connection identity in approval | Connection identity replay |
| T29 | Public docs disclose private data | Logs or local paths copied into PR | Public-text scan and synthetic fixtures | Pre-publish checklist |
| T30 | Sponsor buys runtime authority | Paid placement feeds ranking or decision | Payment-independent data model and tests | Sponsored fixture composition |
| T31 | Cloud policy authorizes a provider | Remote policy turns on external integration | Local-admin enablement remains required | Managed-policy test |
| T32 | Stale policy loosens behavior | Expired policy stays active indefinitely | Signed expiry and tightening-only fallback | Policy clock tests |
| T33 | Adapter bypasses Guard | Agent calls provider CLI directly | Command classification floor and provider adapter boundary | `command explain` safe and sensitive cases |
| T34 | Clipboard or shell history captures value | User copies expanded value or command | No value in UI, arguments or shell text | UI and shell-history fixtures |
| T35 | Error message becomes an exfiltration channel | Provider echoes request or secret in error | Capped sanitized errors and no raw response body | Malformed response tests |

## Abuse cases and expected decisions

| Scenario | Expected result |
| --- | --- |
| Agent asks to print a native secret | Block and offer the bounded delivery flow if the process and sink are known |
| Agent asks for metadata for an existing reference | Allow metadata if local policy permits and no value is resolved |
| Provider is disabled locally | Return `provider_capability_unavailable`, with no network call |
| Provider returns a new version for a pinned reference | Require a fresh decision or return stale, according to reference policy |
| Provider returns a redirect | Reject as malformed or unavailable, with no second request |
| Child requests a second secret during one approved operation | Require a separate request and binding |
| Cloud policy is missing or expired | Keep local policy and do not enable new capabilities |
| Sponsor listing is selected | Open public setup information only. No runtime decision changes |
| User removes a connection | Delete native credential, invalidate grants and clear provider cache metadata |
| Native store is unavailable | Return unavailable. Do not write a plaintext or silent file fallback |

## Residual risk and accepted limits

- A process that has received a secret can intentionally exfiltrate it. Guard limits delivery, lifecycle and
  output exposure, but cannot make an untrusted process trustworthy.
- A local administrator can authorize an unsafe destination. The approval card and audit metadata should make
  the scope visible, but local authority remains a trust assumption.
- OS platform stores differ in prompts, session behavior and backup semantics. Each supported backend needs
  its own qualification lane and an explicit unavailable path.
- Provider-side audit, rotation and revocation are only as strong as the selected provider account and policy.
  Guard records bounded metadata and cannot repair provider authorization.
- Memory scraping and kernel-level attacks require OS hardening, process isolation and endpoint controls that
  sit outside the broker.
- Hosted brokered-value mode is intentionally deferred. It needs tenant-owned keys, envelope encryption,
  regional controls, retention, incident response and a separate compliance review.

## Test mapping

The TODO maps the threat model to implementation work. SM-T003 to SM-T009 cover manifest and trust threats.
SM-T010 to SM-T017 cover native-store and fallback threats. SM-T020 to SM-T027 cover binding, cache and
provider-composition threats. SM-T030 to SM-T037 cover delivery, output, lifecycle and retry threats.
SM-T040 to SM-T049 cover adapter, network and installed-runtime threats. SM-T050 to SM-T055 cover lease,
rotation and cloud-policy threats. SM-T060 to SM-T076 cover public surfaces, release evidence and recovery.

## External design references

- OS keychain, Secret Service and Credential Manager behavior is summarized in the companion research report.
- OWASP guidance informs short-lived credentials, rotation, least privilege, audit, redaction and minimized
  plaintext lifetime. [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- Workload identity and short-lived SVID concepts inform bootstrap-credential avoidance. [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
