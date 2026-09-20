# Core policy capabilities and authority paths

This operator guide describes the current Core implementation. The shared
[policy semantics](../../spec/guard-policy/v1alpha1/semantics.md) and
[compatibility contract](../../spec/guard-policy/v1alpha1/compatibility.md)
remain the schema references; deployment evidence must identify the tested
artifact and source commit.

## Runtime capability inventory

Run `hol-guard policy capabilities --json` on the intended Core binary. Its
`guard_version` reports the declared package version, and
`local_row_projection` describes its local SQLite compiler. Record the exact
artifact digest and source commit to identify tested bytes; a version string
alone does not identify a binary. The existing `command-pattern-expressions.v1` capability
continues to describe the separate command-expression path. A schema field being
valid does not mean that every runtime path can enforce it.

The local inventory is descriptive. Always run `policy validate` against the
actual document: selector values, scope overrides, expiry, input bounds, and
combined row expansion still matter. The inventory is not permission to lower a
restriction or route a policy to another authority path.

| Target path | Match/effect/lifetime contract | Unsupported intent and boundary |
| --- | --- | --- |
| Local SQLite row projection | Enabled `allow`, `block`, `review`; `permanent` or UTC `until`. Supported nonempty matcher combinations are listed below and emitted in `supported_match_combinations`. | Other lifetimes fail `unsupported_policy_lifetime`. Unsupported matchers fail `unsupported_policy_match`; incompatible local scope overrides fail `unsupported_policy_scope_projection`. `ignore` and disabled rules emit no row. |
| Signed generic Cloud bundle with canonical row enforcement enabled | The same row compiler after verified installation-ID device filtering. Cloud envelope/signature/rollout/validity checks remain mandatory; they are not inferred from this inventory. | `devices` is a Cloud prefilter, not a local import matcher. Display labels are not installation IDs. A stale/invalid bundle or disabled canonical rollout does not become applied merely because its rule shape compiles. |
| Command-expression runtime | Existing command capability reports `all`/`any` and exact, startsWith, contains, endsWith, glob, regex operators with its timeout. | A command expression cannot become a local SQLite row. Local validation may report a command-runtime requirement; do not treat its empty row count as an applied command policy. |
| Managed extension controls | `guard.extension-controls.v1` and the target's negotiated catalog/control capabilities. Managed-restrictive controls are disable-only; shared enables require a configurable permission. | Catalog identity, delegation, runtime delivery and atomic application are separate checks. This local inventory does not certify a managed target or advertise generic rule lifetimes for it. |
| Native hook policy | Authenticated `PolicySnapshotV3` / `EffectiveNativePolicyV3`, plus the native hook's intrinsic action floor. | Native snapshot fields are not an unrestricted GuardPolicy matcher API. A local compiler success is not native publication proof; policy allow cannot lower an intrinsic native block. |

For the local row compiler, each row below permits every subset of the listed
fields, including an explicitly empty match (global). Selector entries are nonempty strings; empty/absent fields and extension overrides still
require document validation. Lists select alternatives and their product expands
into rows, subject to the document-wide 10,000-row cap.

| Maximal supported matcher set | Row representation |
| --- | --- |
| `artifacts`, `harnesses`, `workspaces` | Exact artifact rows, or workspace-constrained artifact rows when a workspace is selected. |
| `publishers`, `harnesses` | Publisher scope; publisher cannot combine with an artifact, workspace or tool-family constraint without losing a restriction. |
| `tools`, `harnesses`, `workspaces` | Registered tool-family rows, optionally restricted to a workspace. |

`artifacts` and `tools` cannot appear together. The supported tool aliases are
`file-read`, `mcp`, `mcp-tool`, `package-request`, `prompt`, `prompt-env-read`,
`prompt-file`, `shell`, and `tool-action`; `shell` maps to `tool-action` and the
others retain their family name. Arbitrary tool names are rejected, not converted
into a global match. A document may use multiple rules for distinct supported
scopes only when doing so preserves its intended semantics.

`tests/test_policy_capability_inventory.py` checks all 32 subsets of the five matcher fields against the actual compiler for three active effects
and both local lifetimes. The installed binary's inventory must still be checked
for a deployment; the package's source version alone does not prove that older
Desktop pins or fleet devices support this contract. Publication clients must validate against intended targets and surface
rule-specific failures. This command publishes Core's inventory; it does not
prove that a publication client consumes it yet.

## Authority path examples for policy help

Choose the authority path before explaining a winner. There is no single
Cloud-over-local priority rule across these paths. "Shadowed" below means that
another applicable input did not determine the effective result; it does not
mean that the input was deleted.

| Authority path and applicable inputs | Winner | Shadowed input | Reason and execution reference |
| --- | --- | --- | --- |
| Generic persisted rows at the same specificity: older valid Cloud `block`, newer local `allow` | Local `allow` | Cloud `block` | When both rows coexist and are eligible, `updated_at` breaks the tie; source is not a priority. `StorePolicyMixin.resolve_policy_decision_lookup`; `test_generic_row_recency_is_not_a_cloud_priority_rule[True]`. |
| Generic persisted rows at the same specificity: older local `allow`, newer valid Cloud `block` | Cloud `block` | Local `allow` | The same timestamp rule applies in the other direction. `test_generic_row_recency_is_not_a_cloud_priority_rule[False]`. |
| Generic persisted rows: exact artifact `block`, newer global `allow` | Artifact `block` | Global `allow` | Artifact scope has higher specificity than global scope. The persisted-row ordering applies before timestamp ties; `store_policy.py` and the frozen precedence vectors. |
| Generic eligible one-shot `allow` and selected valid persisted Cloud `block` | Cloud `block`; one-shot remains unclaimed | One-shot `allow` | After selecting the persisted row by existing specificity and recency, its stronger action outranks the one-shot. `test_generic_one_shot_consumption_depends_on_selected_persisted_action[block]`. |
| Generic eligible one-shot `allow` and selected valid persisted Cloud `allow` | One-shot `allow`, consumed atomically for this consuming lookup | Persisted `allow` for this lookup | The one-shot is claimed only if it remains the selected decision; an equal action does not displace it. `test_generic_one_shot_consumption_depends_on_selected_persisted_action[allow]`. Non-consuming lookups do not claim it. This never removes managed restrictions or native intrinsic blocks. |
| Managed/extension permission: signed Cloud `disabled`, local administrator `enabled` on the same permission | Permission remains disabled; control factor blocks | Local `enabled` | `compose_control_layers` gives disable dominance regardless of layer order. Resolver reason is `control.disabled-permission`; `test_managed_permission_disable_retains_its_reason_against_local_enable`. |
| Managed-restrictive publication attempts `enabled` | Publication fields are rejected | No enablement is applied | `_append_control` raises `managed_restrictive_broadening`. This authority supports restrictions only; there is no accepted enable rule to compare for recency. |
| Shared Cloud enable targets a non-configurable permission | Enablement is rejected | No enablement is applied | `_append_control` rejects `immutable_floor`; catalog authority determines configurability. |
| Native pre-tool intrinsic `block`, authenticated native policy `allow` | Intrinsic `block`; deny | Policy `allow` | `apply_pre_tool_policy` joins action floors and validates the typed decision. Native test `policy_allow_cannot_lower_intrinsic_review_or_block`. |
| Native intrinsic `block` in observe mode | Intrinsic `block`; deny | Any weaker policy-only action | Observe mode does not remove intrinsic blocks. Native tests `observe_pre_policy_floor_is_non_blocking_but_intrinsic_block_is_hard` and `observe_preserves_intrinsic_block_but_does_not_enforce_policy_only_floor`. |
| Extension global lockdown on typed trusted local recovery surface | Only documented recovery access | Command execution remains blocked | `resolve_extension_controls` preserves observations and exempts the typed recovery surface from the control block; this is not a general command approval. Existing test `test_global_lockdown_preserves_observations_and_allows_only_typed_local_recovery`. |

The generic examples describe selection among existing rows, not write merge
behavior. Today `_upsert_policy_locked` replaces an exact stored selector key
before inserting a local decision, regardless of the previous source. If that
write removed the other row, a help view must describe replacement instead of a
recency winner between two still-existing rows. The signed-sync proving tests
create the local row first and then apply the Cloud bundle so both inputs are
present for the timestamp comparison. This documentation does not change that
write behavior or claim that deleted rows remain enforceable. This limitation is
about generic stored rows; it grants no authority to remove managed restrictions
or native intrinsic safety floors.

Source references: `src/codex_plugin_scanner/guard/store_policy.py`,
`src/codex_plugin_scanner/guard/managed_controls_policy_fields_core.py`,
`src/codex_plugin_scanner/guard/runtime/extension_control_resolver.py`, and
`rust/crates/guard-runtime/src/policy_enforcement.rs`. Python examples execute in
`tests/test_policy_authority_explanations.py`; native examples refer to the
existing tests in `rust/crates/guard-runtime/src/policy_enforcement_tests.rs`.
These examples do not substitute for a signed installed-runtime workflow test.
