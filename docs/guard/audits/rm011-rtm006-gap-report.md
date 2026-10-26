full report content follows verbatim (this subagent has no file-write tool):

# RM-011 / RTM-006 Gap Report
Worktree: /tmp/hg-rtm008 @ feat/rtm008-native-composition. Generated 2026-10-02.

## 0. Terminology: 'G4'/'G7' have no literal definition
Exhaustive grep of ~/.codex/plans, /tmp/hg-rtm008, docs/guard/contracts finds NO 'G4'/'G7' tokens. Two candidate mappings:
- **PRIMARY (used here)**: rows 4 and 7 of the nine-row 'Required test layers' gate table in HOL_Guard_Rust_Next_Leg_PRD_2026-09-30.md §8.1 (~lines 338-355). The Majority TODO explicitly says 'Do not renumber these findings into the prior nine-item conversation checklist' (RM-phase preamble, ~line 95), confirming the prior spec used an ordered gate list. Row 4 = 'Mixed traffic', row 7 = 'Platform'.
- **ALTERNATE**: rows 4 and 7 of Majority PRD §8.2 SLO table (lines 296-309): 'Direct 250k/1M/5M p95' (50/120/350ms) and 'Direct concurrent p99' (100ms). These are enforced by scripts/native_slo_contract.py:307-346 gate_results() dict (keys: resident_share, safe_corpus, warm_latency, 250k_latency, 1m_latency, 5m_latency, cold_latency, readiness, concurrency, rss, python_fallback) plus scripts/bench_guard_native_release_gate.py:355-527. Under positional reading dict-key #4 = '250k_latency' (native_slo_contract.py:334) and #7 = 'cold_latency' (:337) — both are measured gates whose Rust side is the resident hook path; no fixture gap identified there. If the assignment meant the SLO table, both named gates are implemented-but-not-yet-evidenced-on-final-head (RM-012 records 'partial' installed-artifact execution).

## 1. RM-011 fixture gap table
| Fixture (name) | Required by | Status | Generated-at path |
|---|---|---|---|
| native-archive-inspection/cases.v1.json | RTM-006 bullet 2 'language-neutral expected actions/codes'; RM-008 corpus; test_native_archive_inspection.py is its only carrier | **MISSING** — no such dir/file anywhere | /tmp/rtm011-fixtures/native-archive-inspection/cases.v1.json (content embedded in finding rm011-generated-fixtures) |
| expiry-boundaries.v1.json (controlled-clock oracle for timestamp_has_expired / sqlite_julianday / canonical_utc_timestamp) | RM-011 checkbox 1 + done-evidence 'date-independent expiry tests' | **MISSING** — Python used far-future literals (test_guard_runtime.py:22455-22525); Rust has inline literals only (policy_store_tests.rs:98, approval_gate_grants.rs:531-536) | /tmp/rtm011-fixtures/expiry-boundaries.v1.json |
| native-hook-parity/cases.v1.json + differential-expectations.v1.json | python_capability_cleanup_gate.py:157-161; ci/native_runtime/test_guard_native_runtime_differential.py:31-35 | PRESENT (Python-only consumers; schema gate validates case_count==6, test_python_capability_cleanup_gate.py:440-443) | — |
| context-digest-parity/cases.v1.json | Rust consumer guard-runtime/src/context_digest_tests.rs:8-10 | PRESENT, hermetic via env!(CARGO_MANIFEST_DIR) | — |
| guard-command-corpus/{seed-manifest,minimal-delta-pairs,known-gaps,native-contract,decision-diff-report}.json | tests/guard_command_corpus*.py | PRESENT | — |
| testdata oracles (policy_integrity, local_authority_integrity, policy_integrity_resolver, secret_store, claim_reuse_seed, local_once_claim_seed, approval_reuse_oracle, specialized-matchers.v1) | ported-module parity tests | PRESENT under rust/crates/*/testdata/ | — |
| guard-cloud-review/exact-transport-fixture.json freshness | RM-011 'remove date timebombs' | **STALE** — expiresAt 2026-08-24 already past (lines 27,30,46,49) | regenerate or move to far-future |
| native_command_extension_evidence fixtures | native_command_extension_evidence_tests.rs:18-21 | **NON-HERMETIC** — read from /tmp, not committed | move to rust/crates/guard-command/testdata/ |
| quarantine/SQLite-corruption repro fixture | RM-011 checkbox 2 'reproduce prior SQLite quarantine/native hook failures' | **MISSING** — no quarantine fixture dir; checkbox still open | not derivable without reproducing the failure |

## 2. G4 / G7 assessment (legacy §8.1 interpretation)
- **G4 Mixed traffic**: Rust implements lease-overload/orphan/deadline semantics (archive_inspect_containment.rs:15-33; archive_inspect.rs:154-162,171-193; hardening.rs:20-22). Evidence exists ONLY via Python-driven native tests (test_native_archive_inspection.py:857-1102, all unix-skipif). PARTIAL — not hermetic; lost when Python transport retires (RMN-014).
- **G7 Platform**: structural fail-closed on non-unix (archive_inspect.rs:154-162 sandbox_unavailable; guard-seatbelt lib.rs:47-53). Wheel-target presence checked by verify_native_runtime_release.py:40-46. NO compiled test executes the non-unix path; Windows x64 behavioral proof absent. PARTIAL.

## 3. Correctness / security-relevant diffs
- Expiry boundary parity VERIFIED: Rust `timestamp_has_expired` uses `<=` + fail-closed-on-parse-error (utc_timestamp.rs:242-246); matches Python julianday filter (unparseable -> NULL -> row filtered) and approval_gate_grants.rs:531-536 boundary test. Low residual risk: Rust compares integer microseconds while Python filters via SQLite julianday f64; at >6-digit fractional seconds near an exact boundary the f64 path can round differently — pinned in generated expiry-boundaries.v1.json (nanosecond-fraction case).
- Prune ordering: approval_gate_grants.rs:177-179 documents deliberate reorder vs Python ('observably identical') — verified reasonable, flag for re-check if Python moves prune.
- Fork-safety: approval_gate_grants.rs:18-22 documents residual-TTL grant inheritance in forked child with owner_pid re-check — load-bearing, non-obvious.
- lease_error() uniform failure (archive_inspect_containment.rs:31-33): deliberately information-free error text — do not enrich without reviewing the hostile-state_dir rationale.

## 4. Generated fixtures
Contents embedded in yield evidence/deferred entries; write verbatim to /tmp/rtm011-fixtures/. The cases manifest encodes all ~60 expectation cases from test_native_archive_inspection.py: kind=member-policy cases carry member specs + expected status/code; kind=transport-fault cases carry the fault description for a future Rust-side equivalent. expiry-boundaries.v1.json pins julianday f64, canonical_utc_timestamp, and timestamp_has_expired outputs for boundary/rollover/naive/offset/unparseable inputs.