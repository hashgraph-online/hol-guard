
## Increment 2 — effect_decision reduction proven byte-parity (commits ce1467b..58a93a1)
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
## Remaining: evaluate_command composition (:210-555)
- owned_matches → permission/extension resolution → control_resolution →
  floor lattice → factor producers → evidence batch → workflow auth →
  CompositeCommandEvaluation assembly → decision_plane request → to_dict.
- Surface map: /tmp/rtm008-evaluate-command-surface.md (terra, in flight)
