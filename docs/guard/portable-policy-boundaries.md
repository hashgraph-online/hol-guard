# Portable policy import and device selectors

The existing `GuardPolicy` v1alpha1 file format remains unchanged. Keep the original
policy file when you need its annotations, disabled rules or inert `ignore` rules.
An export from the local store describes the rules that were materialized there;
it does not reconstruct source annotations or an inert rule that created no row.
Imported rules remain local import authority. Provenance does not grant Cloud
write authority or turn an imported row into a signed Cloud rule.

Redacted exports identify their provenance as `export-redacted`. A workspace
restriction cannot be removed for privacy: export requires the existing explicit
provenance option and approval gate, or returns
`sensitive_local_policy_requires_provenance` without producing a broader rule.
Unsupported selector intersections and local scope overrides return
`unsupported_policy_scope_projection` before import. For example, a workspace and
artifact selector can remain a workspace-scoped artifact rule, but an
artifact-scoped override cannot discard its workspace restriction.

One rule may expand into several local rows. Export keeps that rule's ID and
combines its selectors only when every resulting combination is already present
with the same action, expiry, source and non-selector metadata. Missing
combinations return `policy_rule_export_sparse_selectors`; conflicting metadata
returns `policy_rule_export_conflict`. Neither error produces a partially exported
policy. Different document identities sharing a rule ID also produce a conflict.

Merge imports reject reuse of a rule ID from another document and changes to an
existing rule's target set. This avoids retaining the old target as an extra
permission. Use distinct rule IDs, or review a replacement import. **Replace
removes all earlier YAML-imported rows**, including rows from other imported
documents; it preserves separately owned local and Cloud policy rows. The preview
checks identities, and the transaction checks them again before writes. The
existing approval gate remains required when configured.

Retrying the same supported merge or replacement leaves one grant per selector
and preserves document/rule identity. Local database row IDs and signing
generations may change; callers must not treat those row IDs as portable identity.
A failed transaction leaves no partially imported grant. Presentation order does
not define additional policy priority.

Device selectors in signed generic and legacy bundles now match the stable local
installation ID exactly. A human-readable device label is display metadata and
cannot authorize a match, including when that label is another installation's ID.
Renaming a device keeps its targeting; replacing its installation identity does
not inherit the prior identity's selector. Existing policies containing display
names must be republished with the intended installation IDs. No label migration
is inferred automatically.

An acknowledgement names the installation that assessed a bundle. It does not say
that every rule in that bundle matched the installation. Tests cover signature
validation, simulated receipt transport, real isolated SQLite stores, matching
decisions, rename and identity rotation. These are deterministic contract tests;
they do not establish browser OAuth, fleet reconciliation, installed OS behavior
or live cross-device delivery.
