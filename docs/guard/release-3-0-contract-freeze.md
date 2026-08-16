# `release/3.0` execution-assurance contract freeze (wave one)

Status: contract freeze candidate for the G1 gate. Audience: execution-assurance gate reviewers and wave-two implementers. Source evidence snapshot: `origin/release/3.1` at `97e2408a629acd4946db0677abd4022027d421f4`; release identity migrated to 3.0 and revalidated in PR #1901.

This freezes the execution-assurance contract set as schema specifications. It reuses existing types wherever one exists and introduces new types only where no home exists. Every new contract is explicitly 3.0 alpha and capability-negotiated. Nothing here is implemented in this wave; wave two implements against these frozen schemas.

## Security objectives and non-goals

Objectives (invariants to hold under the threat model):

1. A required assurance boundary is never satisfied by a weaker boundary. Minimum boundary is a floor, not a label.
2. Atomic guarantees are enforced or explicitly absent; a missing filesystem/network/resource guarantee is never papered over by a higher-level assurance label.
3. Remote execution may return `unknown_outcome`; it never claims exactly-once completion.
4. Secret values never enter `DecisionContext`, `EvidenceSummary`, logs, trace baggage, or Cloud evidence. Only secret handles cross a boundary.
5. Existing 2.1/2.2 local policy, receipt, runtime-session, protection, and approval behavior is preserved.

Non-goals for the 3.0 alpha: remote workload grants/execution beyond the separately gated Phase 3 capability; VS Code Copilot extension-host interception; production GA; any TestPyPI/PyPI publish or deploy.

Attacker capabilities: malicious workspace/repository/dependency/plugin/skill/MCP server; malicious local standard user; compromised or stale provider endpoint/image; cross-tenant attacker; network attacker replaying/substituting attestations; malicious or buggy harness integration; operator misconfiguration. Out of scope: an attacker with root/admin on the local host (they can delete Guard and forge local health; Guard does not claim protection against a fully privileged local adversary).

## Assurance levels

The assurance model is a partial-order tuple, not an ordinal:

- `GuardExecutionAssuranceBoundary`: `observed_host` | `controlled_host` | `os_isolated` | `hardware_isolated`.
- Atomic guarantees : the set actually enforced.
- `GuardExecutionAttestationTrust`: `unattested` | `self_attested` | `verified`.

`ExecutionAssuranceLevel` (name chosen to avoid the existing `mdm/contracts.py:20` `AssuranceLevel`, which is MDM enrollment assurance) is the user-facing projection of that tuple. Labels EA0–EA4 are presentation projections only and never substitute for an unmet atomic guarantee. Naming rule: execution-assurance names must not collide with protection assurance or AIBOM assurance types (distinct namespaces, signers, verifier policies).

## Atomic guarantee schema

`AtomicGuarantee` is a bounded, versioned enum value plus an enforcement record. Frozen guarantee kinds: `filesystem`, `secret`, `network`, `process`, `privilege`, `resource`, `kernel_hardware`, `identity`, `output`, `cleanup`, `tenant`. Each carries: `kind`, `enforced: bool`, `evidence_ref` (opaque), `boundary: GuardExecutionAssuranceBoundary`. Compatibility rule: unknown future guarantee kinds are forward-compatible (parseable) but cannot satisfy an existing requirement. The schema is versioned (`guard.atomic-guarantee.v1`); bounded (fixed kind set, max evidence ref length).

Reference mapping to today's containment (`release-3-0-containment-baseline.md`): `filesystem`/`network`/`process`/`privilege`/`resource`/`output`/`cleanup`/`identity` map to the Seatbelt/Bubblewrap enforcement cells; `secret` maps to the env-scrub/secret-handle cells; `kernel_hardware` and `tenant` are not enforced by the local reference backend and are recorded as absent, not inferred.

## Execution-context schema

Three digest-bound contracts, reusing the existing context types as inputs rather than replacing them :

- `DecisionContext` (privacy-safe): digest-bound decision inputs. Reuses `GitRepositoryDigest`, `WorkspaceDigest`, `ExecutableDigest` (`package_execution_context_inputs.py:224/256/288`) and the containment `digest` framing (`containment_contract.py:94-100`). Forbidden fields (rejected at validation): raw command text, prompt text, file contents, secret/env values, absolute home/workspace paths, user email/account/repo URL/branch/issue-PR body/customer payload, stable cross-workspace personal identifiers.
- `LaunchMaterial` / `ProviderPlan` (local-only, sensitive): constructed only by trusted Guard adapter code. Reuses `ShellExecutionContext` (`shell_execution_context.py:69`), `ApprovalContextToken` (`approval_context.py:56`), `GitHubWorkflowDescriptor` (`github_workflow_context.py:46`), and `ContainmentRequest` (`containment_contract.py:110-139`, with `launch_digest`/`executable_digest`). These are inputs to the frozen contracts, not parallel identity models. Uses secret handles, never secret values. Never synced or persisted.
- `EvidenceSummary` (privacy-safe): bounded decision/evidence summary with the same forbidden-field rejections as `DecisionContext`, plus over-limit and invalid-parentage rejection.

The fifth identity model is explicitly forbidden: `DecisionContext` composes the four existing context identities rather than inventing a new one.

## Provider contract

`guard.isolation-provider.v1`. Every execution-provider adapter implements `identity`, `capabilities`, `health_check`, `plan(context, policy)`, `execute(plan)`, `cancel(execution_id)`, `cleanup(execution_id)`. New types (no existing home): `ExecutionProvider` (Protocol), `ProviderRegistry`, `ProviderHealth`. Provider discovery never executes workspace-controlled code; provider config is Guard/admin-owned, not repository-owned. Plan is pure/side-effect-free; discovery/health receive no workspace/action payload. `execute` is one fenced attempt with stable idempotency and at-most-one provider launch, returning a terminal statement from the same execution instance. `cancel`/`cleanup` are idempotent. `plan` validation rejects any input manifest or mount request targeting the forbidden host set — `.env`, `.ssh`, Guard state directories, VCS metadata, and host sockets (Docker/container control sockets) — so a malicious plan is refused at the trusted planning boundary rather than trusted away by the provider.

## Policy composition

Assurance planning extends the existing effect engine as a single `DecisionFactorSource` variant in `evaluate_effect_decision` (`effect_decision.py:202`), not a parallel policy authority. New type: `AssurancePlanAssessment` extends `EffectAssessment` (`effect_contract.py:173`). Composition stays pure and monotonic (max-floor); the central safety floor, local/managed strengthening, and fallback rules are unchanged. Assurance requirements only raise floors, never lower them.

## Resolver semantics

The resolver maps (action, context, policy) to a required `GuardExecutionAssuranceBoundary` + atomic guarantee set. Precedence: explicit user policy > managed strengthening > central safety floor > derived default. Every resolution records its authority source in the decision reason (`DecisionReason`, `effect_decision.py:163`) so the provenance of the required boundary is auditable. No resolution path may select a boundary weaker than the policy-required floor.

## Attestation statement

A terminal execution statement binds: exit/outcome, full-stream byte counts and digests, truncation flags, declared-output digests, cleanup state, and the exact execution instance. Provider responses are untrusted until schema, signature, freshness, nonce, subject, audience, workspace, and policy bindings verify. Freshness uses a bounded validity window with a defined maximum accepted clock skew; an attestation whose window, combined with the accepted skew, exceeds the freshness bound is treated as stale and rejected. An unscanned output tail is never implicitly allowed.

## Trust and rotation

Reuses the policy keyring/signer machinery (`policy_bundle_trusted_keys.py`) for provider trust roots: pinned trust domain, key fingerprints, rotation, revocation, and downgrade prevention. A valid signature never upgrades a claim beyond independently pinned configuration/runtime evidence. New: provider trust anchor type carrying kind/version/digest/signing identity/trust domain.

## Fenced retry

New types: `ExecutionLease`, `FencingGeneration`, `AttemptNonce`, `UnknownOutcome`, `StartupReconciliation`. Each launch binds plan digest, provider instance/key thumbprint, monotonic provider generation, lease expiry, attempt nonce, and immutable input manifest. Replacement, restart, or generation drift invalidates the launch. Retry never executes a remote mutation twice; idempotency is keyed on the attempt nonce. The immutable input manifest and the secret-delivery lease enforce the same forbidden-host denylist as `plan`; after `unknown_outcome`, reconciliation determines the terminal state without launching a changed or unfenced retry.

## Privacy contract

`PrivacyContract` with field visibility classes: `local_only` | `cloud_allowed` | `forbidden`. A serialization denylist enforces that `forbidden` fields never serialize to Cloud/sync payloads and `local_only` fields never leave the local store. New types: `PrivacyContract`, `PrivacyField`, `FieldVisibility`, `SerializationDenylist`. Reuses existing receipt redaction levels where present.

## Fail and recovery matrix

Provider health is a typed state machine: `unknown`, `verifying`, `healthy`, `degraded`, `unavailable`, `revoked`, `incompatible`. Cached health carries a `verified_at` timestamp and a hard expiry short enough to prevent stale assurance without forcing a network round trip per benign local action; stale-while-reverify is permitted only for optional routes. Optional-provider failure: health cache with freshness + stale-while-reverify for optional routes; a benign action is not spammed with approvals because optional health is unavailable. Mandatory-provider failure: reject stale capability proof after the configured bound; never silently downgrade to host execution (no host fallback for mandatory assurance). Daemon outage/cancellation/cleanup: cleanup retries independently and surfaces orphan incidents; no deadlock, no approval-tab storm. Recovery never auto-installs privileged components without prior managed authorization.

## Freeze conditions

Every contract above is explicitly `*.v1` 3.0 alpha, capability-negotiated. Forward compatibility requires an explicitly negotiated schema version; unknown security fields fail closed. Local and Cloud share one versioned contract source — no hand-maintained divergent enums. This freeze was adjudicated by the abuse-case review in `release-3-0-contract-freeze-abuse-review.md` (findings F1/F2 amended above).
