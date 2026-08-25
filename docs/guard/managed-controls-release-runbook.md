# Managed Controls release runbook

This runbook covers the HOL Guard Local side of Extension-First Managed Controls on `release/3.0`.

## Required gates

1. Verify the four negotiated capability markers.
2. Validate the canonical, privacy-safe catalog and its digest.
3. Reject unknown Extension and permission targets.
4. Compile Package Firewall delegates through the package path.
5. Apply policy and Extension projections atomically.
6. Preserve the complete last-known-good state on failure.
7. Require monotonic, idempotent acknowledgement evidence.
8. Exclude unsupported or catalog-mismatched clients from rollout.
9. Keep Emergency Lockdown and managed blocks non-weakenable.
10. Confirm local blocks still tighten Cloud permits.
11. Verify custom Extension copy remains local-only until continuity is real.
12. Run adversarial, privacy, accessibility, and performance checks.
13. Complete and record the independent review required by the
    [Managed Controls threat model](managed-controls-threat-model.md).

From the repository root, run:

```bash
python scripts/ci/managed_controls_release_gate.py
pytest tests/managed_controls
```

No release may silently drop Extension semantics or move detector ownership into Guard Cloud.
