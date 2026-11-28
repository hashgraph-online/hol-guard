# Secret Management and Secret Reads TODO

This checklist implements the [Secret Management and Secret Reads PRD](./secret-management-prd.md).
An item is complete only when the implementation, a regression test, and the evidence named in the item
land together. Configuration inspection alone does not check an item.

Rules that apply to every item

- New hot-path logic is Rust. Python remains a thin CLI, rendering, or native-runtime shim.
- Read `docs/guard/approval-invariant.md` before changing approval tokens, saved decisions, scope
  contracts, retry bindings, or review cards. Every supported review keeps Allow once and Always allow.
- New provider integrations are external and inert until a local administrator enables them. A manifest
  cannot grant authority, weaken a Guard floor, or execute provider-supplied code.
- Secret values never appear in logs, receipts, telemetry, dashboard responses, test snapshots, fixture
  journals, public pull requests, or agent-visible text. Fixtures use synthetic names and values.
- Every new Rust source file is added to `rust/build_support/command_source_inputs.v2.json` when it is
  part of the generated native command projection.
- JSON contract and fixture files are declarative data. Review them for schema, bounds, trust and data-flow
  correctness rather than line count.
- Run focused tests for changed code. A release claim requires an exact-source installed-runtime check.
- Do not add provider network calls to the ordinary hook path. Offline, unavailable, stale and malformed
  provider states must have deterministic bounded behavior.
- Every provider pull request includes a Rust test, a deterministic fixture, a privacy statement, a
  conformance result, and a direction check that fails on the parent revision.

Dependencies

Phase 0 gates all implementation. The contract and fixture harness land before any provider can affect a
decision. Native storage and the reference parser can proceed in parallel after the contract is accepted.
Provider adapters depend on the broker, delivery containment, trust binding and conformance runner.
Hosted policy and sponsorship surfaces remain planning-only until local delivery and audit boundaries pass.

## Phase 0: decisions and contracts

- [ ] **SM-T001** Record an ADR for the product boundary. Include resident custody, no value telemetry,
  evidence-not-authority, payment independence, external opt-in, no provider execution, fail-closed
  delivery, no hot-path network and the relationship to the existing raw environment and file-read floors.
  Evidence: ADR merged and linked from the PRD.
- [ ] **SM-T002** Record the approval contract. Define the review subject, exact-action token, Allow once,
  Always allow, expiry, retry binding, changed reference behavior, changed destination behavior, and the
  response when an executable binding is unavailable. Evidence: approval-invariant review and contract tests.
- [ ] **SM-T003** Add `contracts/secret-providers/secret-provider.v1.schema.json` with closed fields,
  bounded strings, exact HTTPS hosts, no query credentials, no wildcard hosts, no redirect permission,
  declared response pointers, declared capabilities and explicit delivery modes.
- [ ] **SM-T004** Add `contracts/secret-providers/secret-reference.v1.schema.json` and a grammar for
  `guard-secret://<provider>/<scope>/<name>[#<field>][?version=<selector>]`. Reject empty segments,
  traversal, ambiguous decoding, control characters, unbounded selectors and values in the reference.
- [ ] **SM-T005** Add typed Rust contracts under `rust/crates/guard-contracts/src/secret_provider.rs`,
  `secret_request.rs`, `secret_delivery.rs` and `secret_lease.rs`. Use `deny_unknown_fields` where the
  wire format is persisted or signed. Secret-bearing response types must not implement outward `Debug`
  or `Serialize`.
- [ ] **SM-T006** Add provider trust bindings under `contracts/extensions/trust/provider.<slug>.v1.json`.
  The generated binding records publisher, manifest digest, schema version, external status and local
  opt-in state. Payment or placement never changes the binding.
- [ ] **SM-T007** Define the effect and error enums. Provider responses can be `metadata`, `available`,
  `stale`, `unavailable`, `malformed` or `revoked`. Only Guard policy can produce `allow`, `review` or
  `block`, and a provider result may only tighten the local outcome.
- [ ] **SM-T008** Decide and document whether v1 includes file-descriptor delivery on all supported OSes,
  whether direct agent reads are always blocked, and how self-hosted provider endpoints prove locality.
  Add an ADR before dependent code lands.
- [ ] **SM-T009** Add a synthetic fixture provider and contract corpus. Include valid manifests and rejection
  cases for unknown fields, wildcard hosts, non-HTTPS hosts, query credentials, redirects, oversized body
  limits, undeclared response pointers, arbitrary commands and secret-bearing telemetry fields.

## Phase 1: native secure storage

- [ ] **SM-T010** Add `rust/crates/guard-runtime/src/secret_store_platform.rs` with a platform trait for
  put, metadata, read, delete and availability. Use a distinct Guard service scope for user secrets.
  Keep approval-enrollment storage and the internal encrypted file store separate.
- [ ] **SM-T011** Implement the macOS Keychain backend using generic-password items with service and account
  as the stable lookup tuple. Do not log item values or access-control details. Tests cover missing item,
  duplicate item, denied access, user cancellation and successful read.
- [ ] **SM-T012** Implement the Linux Secret Service backend. Treat attributes as lookup metadata rather than
  secret material. Tests cover unavailable session bus, locked collection, prompt denial, missing item and
  successful read.
- [ ] **SM-T013** Implement the Windows Credential Manager backend with per-user generic credentials. Tests
  cover target mismatch, unavailable API, denied access, missing item and successful read. Do not add a file
  fallback without the ADR from SM-T008.
- [ ] **SM-T014** Add an explicit unavailable backend for unsupported or headless environments. It returns a
  typed unavailable result and never silently downgrades to plaintext or an encrypted file.
- [ ] **SM-T015** Add zeroization and redaction wrappers around resident values. Verify that error paths,
  panic messages, tracing fields, `Debug`, and drop order do not expose the value.
- [ ] **SM-T016** Add CLI commands for native setup and metadata status. A write-only setup flow accepts a
  value from an approved terminal or platform prompt and never echoes it. A status command prints provider,
  scope, name, version metadata and availability, never a value.
- [ ] **SM-T017** Add cross-platform tests on supported runners and deterministic unavailable tests elsewhere.
  Record OS, backend, operation, prompt behavior and result class in evidence without recording values.

## Phase 2: reference parser, broker and policy

- [ ] **SM-T020** Add `rust/crates/guard-runtime/src/secret_reference.rs` with canonical parsing,
  normalization and digesting. Preserve the original display label separately from the canonical digest.
- [ ] **SM-T021** Add `rust/crates/guard-runtime/src/secret_broker.rs` with provider selection, local policy,
  native lookup, cache expiry, lease metadata and deterministic errors. Provider values remain in the broker
  and selected delivery path only.
- [ ] **SM-T022** Bind every approval to provider identity, connection identity, reference digest, version
  selector and resolved version, capability, destination sink, process identity, workspace, purpose, policy
  digest and extension digest. Never bind an approval to a secret value.
- [ ] **SM-T023** Reuse the existing direct environment and sensitive-file detectors as lower-bound floors.
  A provider reference must not make a raw `env`, `printenv`, `process.env`, `os.environ` or credential-file
  read quiet.
- [ ] **SM-T024** Add exact error handling for unavailable, stale, revoked, changed-reference,
  changed-destination, missing-approval, malformed-provider-response and unsupported-sink cases. Each case
  has a stable machine code and a user-safe message.
- [ ] **SM-T025** Add cache rules. Metadata may be cached for a bounded interval. Secret values are either
  resident for one operation or retained only for an explicit provider lease. Rotation and version changes
  invalidate a covering approval and cached value.
- [ ] **SM-T026** Add property tests asserting that a provider result never lowers the Guard action and that
  changing provider, connection, reference, version, sink, process, workspace, policy or extension digest
  cannot reuse an old Always allow.
- [ ] **SM-T027** Add an offline replay harness for native, provider, stale, revoked, unavailable and malformed
  cases. The harness captures decision skeletons and digests only.

## Phase 3: bounded delivery and hooks

- [ ] **SM-T030** Add `rust/crates/guard-runtime/src/secret_delivery.rs` with environment, stdin and
  file-descriptor sinks. Default to the least persistent sink available for the requested process.
- [ ] **SM-T031** Reject direct delivery to agent text, command arguments, URLs, query strings, clipboard,
  workspace files, shell history, receipts and telemetry. File delivery remains disabled until the sink is
  explicitly reviewed and its lifecycle is bounded.
- [ ] **SM-T032** Implement `hol-guard secrets exec` with opaque references, named destination variables,
  disposable child-process scope, exit-status propagation and cleanup on cancellation. Never print the
  expanded command or environment.
- [ ] **SM-T033** Add pre-tool and pre-exec hooks for secret requests and post-tool output redaction. Hooks
  receive request metadata and digests, not values. A hook that cannot establish an executable binding
  returns unavailable and does not show an approval that cannot run.
- [ ] **SM-T034** Add secret-specific review cards. Show provider, reference label, purpose, destination,
  process, workspace, version state, expiry and policy reason. Preserve both Allow once and Always allow
  where review is supported. Never show the value or provider credential.
- [ ] **SM-T035** Add output scanners for accidental value reflection in child output, error text and
  diagnostics. Redaction is defense in depth and does not turn unsafe delivery into an allow.
- [ ] **SM-T036** Test cancellation, child crash, timeout, partial spawn, retry and concurrent requests.
  Prove that cleanup happens before a new request can reuse a sink and that one request cannot consume
  another request's approval.
- [ ] **SM-T037** Add fixture cases for safe metadata, allowed delivery, direct-read block, stale version,
  changed destination, provider outage, malformed response, redirect and oversized response. Pair every
  protected case with a benign case using synthetic values.

## Phase 4: provider compiler and adapters

- [ ] **SM-T040** Add `rust/crates/guard-secret-provider/` for manifest compilation, exact host matching,
  body and response-pointer validation, capability mapping, trust binding and fixture generation.
- [ ] **SM-T041** Prohibit shell or CLI execution from provider manifests. The adapter surface is a typed
  Rust implementation with bounded HTTP or a reviewed local transport. No manifest can select a binary,
  script, arbitrary URL, redirect or unbounded response.
- [ ] **SM-T042** Add the provider conformance command and extension workflow. `hol-guard extensions
  generate --secret-provider` creates a manifest, trust binding, fixtures and documentation skeleton.
  `hol-guard extensions validate --secret-provider` checks all generated artifacts.
- [ ] **SM-T043** Implement a native fixture provider and publish its conformance evidence. Its provider id,
  host and secret values are synthetic and cannot be compiled into the contribution directory.
- [ ] **SM-T044** Implement a HashiCorp Vault adapter for KV v2 metadata and read, with a separate bounded
  lease capability. Test JWT or OIDC workload identity first. Treat token, lease and audit values as
  secrets and keep them in the native store.
- [ ] **SM-T045** Implement the first cloud adapter, selected by the sponsor ADR. Use workload identity or
  short-lived exchange where available, explicit version selectors, least-privilege scopes and provider
  audit correlation metadata. Do not accept long-lived account keys in a manifest.
- [ ] **SM-T046** Implement a second cloud adapter and prove provider neutrality. The same reference,
  delivery, approval and outage fixtures must pass without provider-specific branches in Guard policy.
- [ ] **SM-T047** Implement one team password-manager adapter through a customer-controlled Connect or
  machine-account endpoint. Scope vaults or projects explicitly, support read-only permissions, and keep
  client-side decryption inside the provider's supported boundary.
- [ ] **SM-T048** Add Doppler and Infisical adapters only after service-token or machine-identity scope,
  rotation, rate-limit and audit tests exist. Their tokens are connection credentials, not secret values to
  place in agent requests.
- [ ] **SM-T049** Run installed Guard checks for each shipped adapter. Record released version, agent,
  `command explain` safe and sensitive cases, conformance result, exact candidate digest and evidence path.
  Never approve the agent's own Guard request.

## Phase 5: leases, rotation and cloud policy

- [ ] **SM-T050** Add lease metadata with expiry, renewal eligibility, revocation state and provider lease
  digest. The first implementation may expose expiry notices without automatic renewal.
- [ ] **SM-T051** Add explicit renew and revoke capabilities with fresh approvals, exact lease binding,
  provider idempotency and bounded retry. A failed renewal never extends local validity.
- [ ] **SM-T052** Add rotation invalidation. A new version, provider generation, connection change or
  revocation event invalidates cached material and covering Always allows where the reference requires a
  pinned version.
- [ ] **SM-T053** Add metadata-only audit events for request, approval, delivery, expiry, failure and
  revocation. Prove that values, full references with sensitive fields, provider tokens and response bodies
  cannot enter events.
- [ ] **SM-T054** Add optional managed policy that can tighten local rules. A remote policy digest is signed,
  cached with an expiry and ignored when unavailable. It cannot enable a disabled external provider or
  authorize a provider response.
- [ ] **SM-T055** Add a cloud audit export design with tenant-selected metadata, regional controls, retention,
  deletion and break-glass review. Do not implement value brokering until a separate encryption and
  compliance ADR is accepted.

## Phase 6: user experience and sponsorship

- [ ] **SM-T060** Add an Integrations view for provider status, local enablement, connection identity,
  capabilities, last metadata refresh, expiry and conformance status. Hide credentials and values.
- [ ] **SM-T061** Add provider setup and disconnect flows with write-only credentials, explicit scope,
  local-admin proof and clear deletion behavior. A failed setup leaves no half-connected credential.
- [ ] **SM-T062** Add the secret reference inspector. It shows canonical provider, scope, name, field,
  version state, permitted sinks and the approval history digest. It never resolves the value.
- [ ] **SM-T063** Add sponsor placement with a visible sponsor label, public setup link and referral
  attribution that contains no device, account, path or secret identifier. Placement cannot affect policy,
  ranking of security findings or approval outcomes.
- [ ] **SM-T064** Add verified-publisher and conformance badges based on review evidence. Payment cannot earn
  a badge. The public record contains manifest digest, supported versions and privacy statement only.
- [ ] **SM-T065** Add release and recovery switches for the provider compiler, provider routes and cloud
  policy. `off` must leave native raw-read floors and existing Guard protections unchanged.

## Phase 7: qualification and release

- [ ] **SM-T070** Add focused Rust tests for each changed crate and run the smallest matching Python tests.
  Preserve the distinction between focused evidence and full-suite or typecheck baseline diagnostics.
- [ ] **SM-T071** Run contract, fixture, property, cross-platform, harness and redaction tests. Save complete
  logs outside the public artifact and publish only bounded summaries and evidence digests.
- [ ] **SM-T072** Run `git diff --check`, schema validation, generated projection checks and package-content
  checks. Regenerated artifacts come from the supported generation flow and are not hand-edited.
- [ ] **SM-T073** Run installed Guard validation from a released build. Include `hol-guard --version`, a
  destructive sensitive case and safe counterpart for `command explain`, provider conformance, and a
  disposable delivery task. Record unavailable live-provider tests as unavailable rather than passing.
- [ ] **SM-T074** Review all outgoing public text for local paths, credentials, internal hosts, account
  identifiers, provider connection details, request ids and secret-like values before any issue, PR,
  comment or release note is created.
- [ ] **SM-T075** Publish a release checklist with supported OS backends, provider versions, known unavailable
  states, approval-invariant proof, value-exposure proof, latency, rollback switch and exact installed
  runtime evidence.
- [ ] **SM-T076** Re-test after source changes invalidate any optional Gauntlet evidence. Record exact source
  and installed SHAs, native wheel, provider or model, platform and evidence path.
