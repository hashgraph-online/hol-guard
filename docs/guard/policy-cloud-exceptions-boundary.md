# Local Policy + Cloud Exceptions — Implementation Boundary

Date: 2026-06-13

This note defines how local `./hol-guard` Policy work relates to Review/Decision
Memory, Evidence, and Guard Cloud exceptions. It is the source of truth for
implementation boundaries in this slice.

## Product split

| Surface | Question it answers | Owns |
| --- | --- | --- |
| **Review / Inbox** | What is blocked right now? Decide so the agent can continue. | Live approvals, scoped memory writes from review, fast reusable allow/block |
| **Evidence** | What happened? Show proof. | Receipts, commands, envelopes, export, history |
| **Policy → Remembered rules** | What will Guard do next time? | Local remembered allow/block rules, read-only Cloud-managed rules |
| **Policy → Cloud exceptions** | Which governed risk acceptances apply here? | Read-only synced Cloud exceptions, request flow, ack status |
| **Policy → Strict config** | What is the local fallback when nothing else matches? | Strict-mode tuning on this device |

Local Review keeps fast reusable approvals. That flow is **not** removed or
redesigned in this slice.

Cloud exceptions are separate governed risk acceptances: owner, approver, reason,
expiry, source receipt, blast radius, signed bundle, and local daemon ack.

Local Policy must **not** author broad local exceptions directly.

## Current code map (Phase 0 audit)

### Local dashboard (Policy UI)

| File | Role today | Gap vs target |
| --- | --- | --- |
| `dashboard/src/policy-workspace-page.tsx` | Page shell + header | Header copy still mentions "add custom exceptions here" |
| `dashboard/src/policy-workspace.tsx` | Tab host: rules / exceptions / strict | Tab 2 labeled `Exceptions`; hosts local `PolicyExceptionForm` |
| `dashboard/src/policy-workspace-views.tsx` | Rule cards, grouped sections | Remembered rules OK structurally; lacks M1 right-rail helper |
| `dashboard/src/policy-exception-form.tsx` | Local broad exception authoring via `savePolicyDecision` | **Must be replaced** by Cloud request flow; violates Cloud-only exceptions |
| `dashboard/src/policy-workspace-helpers.ts` | Plain-language display, Cloud bundle copy | Abstracts commands; links to Evidence via "See approval record" |
| `dashboard/src/approval-center-primitives.tsx` | Sidebar + shared UI | Sidebar IA correct; no Policy changes needed in Phase 0 |
| `dashboard/src/guard-api.ts` | `fetchPolicies`, `savePolicyDecision`, `clearPolicy` | No Cloud exception DTO yet |
| `dashboard/src/workspace-page-header.tsx` | Optional header tabs | Policy page uses header without tabs (fixed in #820) |

### Local daemon / store

| Endpoint / module | Role today |
| --- | --- |
| `GET /v1/policy` | Lists local `GuardPolicyDecision` rows plus `cloud_exceptions` DTO field |
| `POST /v1/policy/decisions` | Saves local policy decision (used by exception form today) |
| `POST /v1/policy/clear` | Clears local remembered rules |
| `GET /v1/policy/cloud-exceptions` | Lists active Cloud exception DTO rows |
| `POST /v1/policy/sync` | Syncs Cloud policy bundle |
| `policy_bundle_parser.py` | Schema validation, bundle hash, payload hash, RSA signature verify |
| `policy_bundle_trusted_keys.py` | Trusted signing keys, key expiry |
| `store_approvals.py` | Local decision persistence substrate |

Bundle parser capabilities today: canonical payload, `bundleHash` / `payloadHash`
integrity, RSA-PSS signature verification, schema validation for rules and
acknowledgements. Downgrade protection and exception expiry enforcement live in
evaluator/sync paths and will be extended in later phases.

### Guard Cloud (read-only audit for this slice)

| Route / module | Role today | Gap |
| --- | --- | --- |
| `app/api/guard/exceptions/route.ts` | List/upsert exceptions | No cwd/project/team scope in API |
| `app/api/guard/exceptions/requests/route.ts` | Create/list exception requests | Scope limited to `artifact \| publisher \| harness` |
| `app/api/guard/exceptions/requests/[requestId]/resolve/route.ts` | Resolve pending request | Exists |
| `src/lib/guard/service/exception-service.ts` | DB persistence, owner isolation | No source receipt field on create; no owner avatar metadata |
| `src/types/registry/guard/core.ts` | `GuardExceptionScope` | Only `artifact \| publisher \| harness` |
| `src/lib/guard/policy/policy-compiler.ts` | Bundle compilation | Exceptions may need richer metadata in bundle |
| `src/lib/guard/policy/policy-sync-ack-service.ts` | Daemon ack path | Reuse for exception bundle ack |

**Portal worktree decision (HGLP002):** Not required for Phase 0. Portal backend
changes deferred until Phase 4 unless Cloud exception request UX cannot be made
truthful with existing APIs.

## Sidebar IA (must not change)

Actual sidebar labels from `approval-center-primitives.tsx`:

1. Home
2. Inbox
3. Protect
4. Evidence
5. Supply chain
6. Policy
7. Settings
8. About

## Target Policy tabs

Visible tabs (internal `PolicyPageView` may keep `exceptions` alias):

1. **Remembered rules** — local + read-only Cloud-managed remembered decisions
2. **Cloud exceptions** — read-only governed risk acceptances + request CTA
3. **Strict config** — local fallback tuning only

## Review / Inbox non-touch rule

Implementation PRs in this slice **must not** modify Review/Inbox product IA or
decision-memory flows except through documented integration contracts:

- Consume remembered decisions as `GuardPolicyDecision` / future Cloud exception DTO
- Link to source receipts from Policy cards
- Prefill Cloud exception requests from receipt/approval ids

### File allowlist (Policy slice may edit)

```
dashboard/src/policy-workspace*.tsx
dashboard/src/policy-exception-form.tsx
dashboard/src/policy-cloud-exception*.tsx
dashboard/src/guard-api.ts
dashboard/src/guard-types.ts
dashboard/src/workspace-page-header.tsx
dashboard/src/app.tsx                    # policy route wiring only
src/codex_plugin_scanner/guard/daemon/server.py
src/codex_plugin_scanner/guard/policy_bundle_*.py
src/codex_plugin_scanner/guard/store_approvals.py
docs/guard/policy-cloud-exceptions*.md
dashboard/src/policy-cloud-exceptions*.test.ts
```

### File denylist (do not edit without explicit cross-PR link)

```
dashboard/src/approval-center-layout.tsx
dashboard/src/approval-center-utils.tsx
dashboard/src/queue-state.tsx
dashboard/src/inbox*.tsx
dashboard/src/approval-gate*.tsx
hol-points-portal/src/lib/guard/triage/**
hol-points-portal/src/lib/guard/review/**
```

## No-fixture scan plan (HGLP013)

Run before each Policy frontend PR merge:

```bash
cd dashboard
pnpm exec tsx src/policy-cloud-exceptions-boundary.test.ts
rg -n 'Acme|Jane Doe|john@example|policy-2026|receipt_[a-f0-9]{8}|exception_request_' \
  src/policy-workspace*.tsx src/policy-exception-form.tsx src/policy-cloud-exception*.tsx \
  && exit 1 || true
```

Production Policy UI must use real API/local store data or honest empty states.
Mockup filenames and fixture rows are forbidden in shipped components.

## Mockup delta summary (HGLP011)

Compared current code structure to mockup contracts M1–M4 (layout references only):

| Mockup | Current delta |
| --- | --- |
| M1 Remembered rules | Missing right-rail helper; cards lack concrete trigger from receipt; tab IA OK |
| M2 Cloud exceptions | Tab still named `Exceptions`; local `New exception` form; no summary cards, grouping, or detail panel |
| M3 Request Cloud exception | `PolicyExceptionForm` saves locally via `/v1/policy/decisions`; no Cloud request API, owner, expiry, blast radius |
| M4 Strict config | Tab exists but minimal; no evaluation order diagram, simulator, or ack display |

Browser screenshot proof (HGLP010) requires a running local daemon; capture paths
will be added in Phase 1+ browser proof tasks.

## Integration with Review/Decision Memory

Review/Decision Memory owns live queue, scope ladder, signed memory bundle, and
Review UI. This Policy slice consumes its outputs:

- Remembered local rules → `Remembered rules` tab
- Source receipt id → Cloud exception request prefill
- Scope identifiers → request scope cards (when backend exposes them)

Do not rewrite Review/Inbox components to implement Policy features.

## Phase 0 completion

Phase 0 delivers this boundary doc, audit notes, and automated boundary tests.
Phase 3 adds the local Cloud exception DTO (`cloud_exceptions.py`), separate sync
storage, and `/v1/policy` + `/v1/policy/cloud-exceptions` API fields.
