# Policy Extension fields v1

Release 3.0 adds two signed, namespaced fields without replacing canonical GuardPolicy rules.

Document-level controls use this exact shape:

```yaml
x-hol-extension-controls:
  schemaVersion: guard.extension-controls.v1
  authorityMode: personal-shared | workspace-shared | managed-restrictive
  globalLockdown: true # optional; managed-restrictive only
  controls:
    - targetKind: extension | permission
      targetId: canonical-id
      state: enabled | disabled
```

Rule-level targeting uses this exact shape:

```yaml
x-hol-extension-targets:
  schemaVersion: guard.policy-extension-targets.v1
  extensionIds: []
  permissionIds: []
```

A rule may target permissions without repeating their owning Extension IDs. Local resolves and validates each permission's owner from the canonical catalog. When `extensionIds` are also supplied, every permission must belong to one of those listed Extensions.

The canonical capability names are `extension-control-layer.v1`, `policy-extension-targets.v1`, and `managed-controls-atomic-apply.v1`. Transitional `guard.*` aliases are accepted for compatibility but are not the advertised contract.

Shared authority may materialize into the signed-Cloud layer. Local disable dominance, required Extensions, and immutable permission floors remain intact. Explicit Cloud enablement may target only configurable permissions. Managed-restrictive authority may only disable an Extension, disable a permission, or enable Emergency Lockdown.

Local validates schema versions, authority, target kind, canonical identity, state, limits, catalog membership, duplicates, conflicts, and delegated protection after the signed v2 envelope has passed workspace, expiry, hash, rollback, and signature verification. Explicitly present `null` Extension fields are malformed and fail closed. A policy without these fields retains existing v2 behavior. A policy with these fields is rejected rather than silently downgraded when capability support is incomplete.

Package-manager Extensions continue through Package Firewall and never become duplicate generic command controls. Local protection remains active when Cloud is disconnected or unavailable.
