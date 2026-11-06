# Protection Center implementation audit

Audit date: 2026-08-09

This document records the implementation baseline for the Protection Center UX overhaul. It contains repository identifiers only and no local user data.

## Exact baseline

- Repository: `hashgraph-online/hol-guard`
- Target branch: `release/3.0`
- Batch 1 original base: `4cc09ee78a8b1cc9c0d604854aca2b737af93b3a`
- Batch 1 synchronized release base before merge validation: `cbd62f1a4d2863c169cf11fead1d66e30dc49220`
- Existing Extension Control Center detail implementation: PR #2172, merged into `release/3.0`
- Existing granular policy implementation: PR #2193
- PR #2193 audited head: `d1435839a6490d0b3a2af56baeb9f233387198bf`
- PR #2193 audited original base: `6933a04f37af25b3bcd3be271a4e9d2241822ffe`
- PR #2193 disposition: held as Draft until Protection Center Batch 4

## PR #2193 disposition

Preserve and rebase during Batch 4:

- server-authoritative extension-control projection
- semantic preview and canonical diff
- exact one-use approval proof binding
- strict response normalization
- local policy draft model
- stale revision/catalog/authority conflict handling and rebase model
- persistence verification
- installed-wheel real-daemon apply/restart/runtime-probe/restore coverage

Rewrite before merge:

- permission-card wall
- Inherit / Allow / Block as primary user copy
- baseline-floor and provenance-first presentation
- `Server semantic preview` and `Blast radius before apply` primary headings
- raw IDs and digests in the normal review path

Batches 1 through 3 must not recreate the server preview, proof, projection, or stale-rebase logic.

## Current route contract

The compatibility routes remain:

- `/extensions`
- `/extensions/:extensionId`

The user-facing navigation label is `Protections` and the page title is `Protection Center`. Canonical extension, permission, and rule identifiers remain unchanged.

## Presentation inventory

The pre-overhaul Simple surface mixed user tasks with implementation vocabulary including:

- extension
- permission
- rule
- authority
- provenance
- baseline floor
- catalog digest
- canonical ID
- matcher kind
- semantic blast radius

The overhaul moves these details behind Advanced or Developer disclosure while preserving the canonical facts.

## Security boundary

The backend registry, resolver, authority store, managed policy, semantic preview, and proof system remain authoritative. Presentation code may translate facts into user-safe language but must not independently calculate a weaker effective policy.

## Batch 1 review note

Source review caught one pre-merge interaction defect: an unenrolled device initially rendered a `Finish setup` action that only refreshed status. The final Batch 1 behavior labels that action `Show setup steps`, switches to the existing trusted enrollment instructions, and proves the transition in the installed-wheel browser test. Browser enrollment itself remains intentionally terminal-bound because first authority enrollment requires the trusted foreground terminal flow.

Before merge, `release/3.0` advanced through PR #2198 with the frozen-daemon launch repair. Batch 1 was merged with that release head on its feature branch and reran the dashboard contracts before the final repository gates. This avoids merging UX work on stale release evidence.

## Batch sequence

1. Foundation and information architecture
2. Novice-first landing
3. Module detail and explanations
4. Secure granular policy editor integration
5. Test Lab, activity, rollback, recovery, lockdown, and profiles
6. Cloud value gates, developer experience, accessibility, performance, documentation, and final proof

Every batch targets `release/3.0` only. This work must not merge, retarget, publish, deploy, tag, or release `release/3.0` into `main`.
