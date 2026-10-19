# New workflow verifier review boundary

This implementation is a local candidate. Its own signatures, tests and
data-only checks do not make it an independently eligible Gauntlet verifier.
Production CI/CD and [the existing trust policy](../trust.py) remain unchanged.

## Practical beta review

For the current bounded beta, review the deterministic profile, twelve-cell
selection and the existing scoring/gate path they use. The full qualification
requirements below remain future work, not additional beta implementation tasks.

The focused review should answer:

- Do `deterministic.py`, `deterministic_control.py`, `deterministic_probes.py` and
  `local_executor_controls.py` require actual installed behavior, reachable
  positive controls, preserved effects and cleanup? Can missing or altered
  observations obtain credit? Forwarding untrusted text is never detection.
- Do `beta_profile.py`, `ci_gate.py`, `ci_gate_report.py` and `ci_runner.py` retain
  every required cell and distinguish task utility, security, validity and cost?
  Can a missing case, invalid invocation or unsafe effect yield a green report?
- Do `artifact_contracts.py`, `mcp_artifact_schema.py` and `public_interface.py`
  expose existing public task requirements without importing trusted answers,
  inserting correct actions or closing the deliberately unsafe attack routes?
- Do the selected business/developer oracles reject incorrect output and
  unauthorized effects independently of agent completion claims? Are attack
  exposure and intervention claims supported by the retained observations?

Inspect the focused negative tests and actual VM results, including earlier
failures. Compare the unmodified release and repaired candidate identities.
Record the reviewed commit/package digest and any unresolved conditions. Local
signatures establish integrity under their supplied anchors; they do not prove
independent approval. The user is the intended independent reviewer.

See [beta profiles](BETA_PROFILES.md) for proposed CI operation and the root
`BETA_ACCEPTANCE.md` for current evidence. Enabling production CI remains a later
authorized release action.

## Broader qualification review

The current policy accepts the independently resolved trusted base, or a revision
whose ancestry is established on the repository's default branch. Its original
bootstrap exception is limited to PR 3463 and a base without Gauntlet installed.
That exception cannot promote these new workflow oracles after Gauntlet has been
installed. Setting a candidate revision in an environment variable would not
satisfy that policy. Local implementation approval does not change this boundary.

Before a qualification campaign, an independent reviewer needs a concrete local
patch and immutable source identity covering these contracts:

- [contracts.py](contracts.py) and the versioned schemas: bounded JSON, duplicate
  fields, nonfinite values, exact identities, authorization and effect contracts.
- [business_oracles.py](business_oracles.py), [business_history.py](business_history.py)
  and [challenge_oracles.py](challenge_oracles.py): alternative valid trajectories,
  exact task outcomes, unauthorized reads, transient mutations and invalid proof.
- [approval_oracles.py](approval_oracles.py), [approval_time.py](approval_time.py),
  [approval.py](approval.py) and [approved_world.py](approved_world.py): independently
  anchored scope, genuine durable claims, expiry and atomic rollback.
- [developer_campaign.py](developer_campaign.py), [developer_oracles.py](developer_oracles.py)
  and isolated workers: frozen artifacts, independently checked functional
  results, candidate-written tests, actual Git state and private answer custody.
- [campaign_product_custody.py](campaign_product_custody.py) and
  [product_custody.py](product_custody.py): external kernel/transport observations,
  exact readonly product bytes and rejection of self-reported policy authority.
- [local_campaign.py](local_campaign.py) and [campaign_execution.py](campaign_execution.py):
  actual-inference routing, budget reservations/charges, retained failures,
  unsupported cells, resume integrity, cleanup and no best-of selection.
- [bundle_integrity.py](bundle_integrity.py) and [bundle_io.py](bundle_io.py): complete
  inventory, external signer/effect anchors, inert reads, path safety, bounded
  exports and separation between integrity and qualification eligibility.
- [statistics.py](statistics.py): fixed template denominators, missing/invalid
  outcomes, paired workflow clusters, sparse uncertainty and attribution limits.

The review package must pin the exact patch/commit, source and fixture hashes,
native wheel/runtime/policy, harness and service/executor images, model/provider
identity, oracle/verifier revisions, test reports and separately supplied public
anchors. It must retain negative diagnostics and list every unsupported cell.
The eight [authored cases](AUTHORED_CASES.md) are public implementation-team inputs;
they cannot establish independent blind evaluation.

After independent review, existing repository governance must establish verifier
eligibility without a candidate self-trust exception. The current local-only
authorization permits preparing and testing that candidate. It does not permit
updating the trusted branch, invoking production CI/CD, publishing attestations
or treating candidate verification as production qualification. A complete frozen
campaign, full public-safe export and second-environment verification/live slice
remain separate requirements in [RELEASE_GATES.md](RELEASE_GATES.md).
