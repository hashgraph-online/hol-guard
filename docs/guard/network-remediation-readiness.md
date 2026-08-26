# Network isolation remediation readiness

This document is the public, evidence-bounded closure record for the HOL Guard 3.0 network-isolation proof tasks REM-121 through REM-139.

## Evidence metadata

- **Data as of:** 2026-08-25.
- **Assurance level:** Source, contract, test, packaging, and reachability validation. This is not a live installed selective-egress or independent-observer attestation.
- **Primary limitations:** No signed installed Linux selective-egress provider, privileged live matrix, or synchronized Guard Cloud network-control path is production-reachable.

## Current verdict

**Not ready for an enforcement claim or release action.**

The release branch contains useful network policy, destination correlation, containment, provider, artifact, and recovery reference implementations. The capability reachability manifest correctly advertises no production-ready network capability. This proof work preserves that boundary and converts the final checklist into a machine-validated record instead of inferring completion from source presence or unit tests.

No release, deployment, promotion, branch deletion, managed-policy activation, or general-availability action is authorized by this work.

## Proven in this slice

- REM-121 through REM-139 are represented exactly once in a checked-in machine-readable proof record.
- Each task is bound to a task-specific evidence contract; unrelated existing files cannot substitute for the declared proof.
- Existing bypass, exfiltration, harness, benign-workflow, approval, recovery, provider, privacy, performance, and supply-chain coverage is linked to the task that it supports.
- Incomplete interface-level or installed-provider evidence remains explicitly partial or blocked.
- The proof validator invokes the authoritative capability reachability contract and refuses a ready verdict while any required task is incomplete or no advertised production capability exists.
- Raw domain storage remains disabled, and the closure report contains only bounded state and task identifiers.
- Private planning artifacts are rejected by repository-path hygiene checks.
- The public capability manifest remains the authority for advertised reachability.

## Open release blockers

1. No signed, installed Linux selective-egress provider is reachable through the public Guard runtime.
2. No live privileged matrix proves complete process-tree attachment, IPv4 and IPv6 TCP enforcement, controlled DNS and UDP behavior, independent observation, repair, and cleanup.
3. gVisor, container, and Kubernetes implementations remain reference or directly callable paths rather than one installed production workload path.
4. The synchronized Guard Cloud network-policy, assignment, application, observer, incident, emergency-deny, and simulation path is not proven.
5. Final synchronized review closure must be recorded on both proof pull requests.

## Verification

Run the bounded proof validator:

```bash
python scripts/guard_network_remediation_proof.py
```

A release gate must additionally use `--require-ready`. That command is expected to fail until every blocker is closed with installed behavioral evidence:

```bash
python scripts/guard_network_remediation_proof.py --require-ready
```

Focused proof tests:

```bash
uv run --no-sync pytest -q tests/test_guard_network_remediation_proof.py tests/test_guard_network_capability_reachability.py
```

The synchronized Cloud repository carries a peer proof record for its own policy and fleet-truth boundary. Neither repository may infer the other repository's achieved state from requested policy, static schema, object presence, or self-report.
