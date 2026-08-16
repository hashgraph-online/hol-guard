# Guard policy legacy removal PRD

## Status

Deferred. This proposal must not be approved or implemented as part of the v1alpha1 compatibility rollout.

## Goal

Remove legacy policy fields and signed bundle v1 only after every supported Portal and HOL Guard version reads, writes, signs, acknowledges, and enforces the canonical policy contract.

## Measured support window

The window starts after canonical enforcement reaches 100% of production workspaces. It ends only when all of the following remain true for at least two supported client release cycles:

- no active client negotiates only bundle v1;
- no Portal canonical-read fallback is exercised;
- no unexplained canonical-versus-legacy decision mismatch is observed;
- rollback to the legacy authority remains exercised and successful during the observation window;
- package telemetry confirms unsupported client versions are outside the published support policy.

Calendar time alone does not complete the window.

## Legacy reader and writer inventory

The removal implementation must regenerate this inventory from current source and attach exact call sites to its PR. The v1alpha1 rollout intentionally retains these categories:

- Portal JSONB `reviewDecisionRules`, `policyRules`, and graph projections;
- Portal bundle v1 compiler, signer, API negotiation, acknowledgement, and receipt compatibility paths;
- Portal canonical backfill, dual-write, shadow-read, and exact legacy fallback controls;
- HOL Guard bundle v1 parser, signature verification, sync persistence, decision compiler, and acknowledgement paths;
- HOL Guard local `PolicyDecision` SQLite rows and YAML import/export adapters;
- frozen v1 payload, canonical signing-byte, signature, hash, precedence, Suggested Memory, undo, simulation, and sync fixtures.

## Entry criteria

1. GuardPolicy is stabilized beyond `v1alpha1` after independent interoperability and security review.
2. Every canonical-read owner is converted and verified without partial canonical/legacy merges.
3. Every active rule has exactly one semantic authority and one stable canonical identifier.
4. Production cohort metrics and sampled receipts show no safety-affecting mismatch.
5. The oldest supported Portal and HOL Guard releases understand canonical documents and signed bundle v2.
6. A tested rollback artifact exists for the last release that still contains legacy readers.

## Removal sequence

1. Freeze a final legacy inventory and byte-level regression corpus.
2. Stop legacy writes behind a reversible production flag; retain readers.
3. Observe one full supported release cycle and exercise rollback.
4. Stop bundle v1 negotiation for clients outside the support window; retain parser and last-known-good rollback data.
5. Remove legacy readers, storage fields, and bundle v1 in separate repository PRs with cross-version tests.
6. Remove compatibility flags only after rollback data expires under the published retention policy.

## Stop conditions

Any unexplained decision mismatch, signature or digest regression, stale client still inside support, lost Builder or Suggested Memory update, or failed rollback stops removal and restores the previous authority path.

## Non-goals

This document does not authorize deletion, schema migration, field removal, bundle v1 removal, or a reduced support window. Each requires a separately approved implementation plan and release evidence.
