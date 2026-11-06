# Managed Controls release runbook

This runbook covers the HOL Guard Local side of Extension-First Managed Controls on `release/3.0`.

The Guard Cloud workflow is implemented behind independent staged controls. Keep each stage disabled until the composed Local and Cloud evidence below passes for the target environment. See the [Cloud operator boundary](managed-controls-cloud-operator-guide.md).

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
11. Verify custom Extension copy reflects the actual continuity stage and that continuity defaults off.
12. Run adversarial, privacy, accessibility, and performance checks.
13. Complete and record the independent review required by the
    [Managed Controls threat model](managed-controls-threat-model.md).
14. Verify the target environment enables only the reviewed rollout stage and retains every kill switch.

From the repository root, run:

```bash
uv run python scripts/ci/managed_controls_release_gate.py
uv run pytest tests/managed_controls
```

No release may silently drop Extension semantics or move detector ownership into Guard Cloud.

## Operator documentation gate

Before release, review and link-check:

- [release notes](managed-controls-release-notes.md)
- [Local Extensions guide](managed-controls-local-extensions.md)
- [Guard Cloud operator guide](managed-controls-cloud-operator-guide.md)
- [existing-policy migration](managed-controls-policy-migration.md)
- [catalog-mismatch recovery](managed-controls-catalog-mismatch-recovery.md)
- [support runbook](managed-controls-support-runbook.md)
- [invalid-bundle incident runbook](managed-controls-invalid-bundle-incident-runbook.md)
- [rollback runbook](managed-controls-rollback-runbook.md)

Run the focused documentation contract check:

```bash
uv run pytest tests/test_managed_controls_contract_docs.py
```
