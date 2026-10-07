# RTM runtime migration slice record

## Verified implementation checkpoint: 2026-10-04

The implementation checkpoint is `65a1bc83c6df2846322f8032c0aad7d186b09ea9`.
The increment notes below are historical, not the current completion checklist.
This record covers the changes in PR #3424; it does not declare the entire RTM
migration program complete.

### Native prompt ownership

Prompt extraction, injection detection, request identity, artifact construction,
and reapproval analysis delegate to the Rust owner through the typed native
prompt client. The superseded Python prompt implementations and semantic
fallbacks must not be restored to satisfy old implementation-specific tests.
Unavailable or malformed native responses do not authorize a Python decision.

Production callers must pass the request's actual Guard home. A fresh guarded
launch provisions the existing store-derived resident verifier before requesting
native analysis. Prompt and attachment tests must use a compiled runtime and
matching generated command projections, not a mocked successful decision.

### Resident recovery

Stopping the native resident can leave an empty `resident-v3-*` scope directory.
The publisher accepts the first authenticated generation acknowledgement in the
same empty scope roots without an unnecessary second publication. This startup
case does not relax validation when a generation was already present. Scope
changes, stale or future acknowledged generations, and metadata changes after
acknowledgement remain rejection conditions.

Regression coverage is in
`tests/test_native_policy_snapshot_empty_resident_roots.py`, alongside the
existing publisher readiness, retry, and startup-budget suites. The installed
performance gate retains its 1,000 ms resident-recovery p95 limit.

### Evidence and limits

The following completed workflow runs are tied to the implementation checkpoint
above, not automatically to later commits:

- [CI, run 37206732097](https://github.com/hashgraph-online/hol-guard/actions/runs/37206732097): successful.
- [Native wheel CI, run 37206732116](https://github.com/hashgraph-online/hol-guard/actions/runs/37206732116): successful after the isolated Windows proof rerun; includes installed Linux, Windows, Intel macOS, and Apple Silicon qualification.

Further source commits require their own current-head checks. Unit-test counts
alone do not establish installed-product qualification, and installed native
proofs do not establish live-model inference evidence. The optional Guard
Gauntlet qualification still requires a fresh real-agent evidence bundle for
the candidate commit; none is claimed by this record.

## Historical increment notes

### Increment 2: effect_decision reduction proven byte-parity (commits ce1467b..58a93a1)
- Contract + dispatch (`command_effect_decide`, `command-effect-v1` capability)
- Full `evaluate_effect_decision` port: all enums, DecisionBasis/PositiveProof/
  EffectAssessment/DecisionFactor/EffectDecisionRequest/EffectDecision types,
  reasons→sort→max-floor→controlling→proof_routes→disposition reduction.
- `__post_init__` invariants enforced natively (fail-closed): pattern regexes,
  basis/proof/assessment cross-invariants, dedup, proof_route<->proof match.
- `effect_decision_to_payload` = exact `effect_decision_to_dict` (null refs,
  exact key set) → embedded as `decision_plane`.
- PROVEN: 15 Python-oracle golden vectors → byte-identical payload
  (tests/effect_decision_parity.rs + fixtures/effect_decision_vectors.json).
- 105/105 lib + parity tests green; workspace builds clean.

### Remaining at that historical increment: evaluate_command composition (:210-555)
- owned_matches → permission/extension resolution → control_resolution →
  floor lattice → factor producers → evidence batch → workflow auth →
  CompositeCommandEvaluation assembly → decision_plane request → to_dict.
- Historical surface map: /tmp/rtm008-evaluate-command-surface.md (terra).
