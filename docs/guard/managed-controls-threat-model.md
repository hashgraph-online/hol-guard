# Managed Controls threat model

Status: release 3.0 security-review baseline
Scope: Local catalog projection, signed Cloud policy delivery, authority composition,
atomic activation, acknowledgement, telemetry, and Package Firewall delegation.

This model supplements the command Extension threat model. It does not change
authentication, approval, exception, or remembered-rule semantics.

## Security objectives

Managed Controls must preserve these invariants:

1. A Cloud document is applied only when its signature, workspace, monotonic
   revision, capabilities, catalog digest, and target identities agree.
2. Managed restrictions and immutable built-in floors cannot be weakened by a
   local control, remembered allow, shared Cloud control, downgrade, or replay.
3. Local administrators may always tighten effective posture.
4. Policy and Extension authority become visible as one complete activation or
   the last-known-good state remains visible.
5. Package controls have exactly one enforcement owner.
6. Catalog sync, telemetry, diagnostics, and acknowledgements disclose no raw
   command, source path, secret, authentication material, or unconsented custom
   identity.

## Trust boundaries and data flow

1. The Local registry produces a canonical, bounded catalog and digest.
2. Local sends only the privacy-filtered catalog projection to its authenticated
   workspace.
3. Cloud compiles Extension targets against that exact catalog and signs the
   bounded policy envelope with a workspace-scoped key.
4. Local validates envelope authority and monotonicity before parsing any
   namespaced Managed Controls fields.
5. Local stages policy and authority projections, publishes them atomically,
   persists an authenticated activation and epoch, and retains the authenticated
   last-known-good state.
6. Runtime resolution composes Local and signed-Cloud layers with disable
   dominance. Delegated package targets leave the command plane.
7. Local acknowledges the exact bundle, catalog, authority revision, and
   effective projection digest using privacy-safe fields.

The local database is untrusted storage. The authority key, machine-managed
trust anchors, authenticated transition records, and monotonic external anchor
form the trust boundary. Cloud administrators are authorized policy authors,
not authority to weaken required Local floors.

## Adversaries

- A compromised or malicious Cloud administrator.
- A user with write access to Local configuration or the Guard database.
- A network attacker replaying, reordering, substituting, or crossing workspace
  messages.
- A malicious custom Extension attempting identity confusion or data exfiltration.
- A policy author supplying pathological sizes, namespaces, or Advanced matchers.
- A crash or injected failure at any activation phase.
- An old or capability-incomplete Local client.

## Threat analysis and executable evidence

| Threat | Required control | Executable evidence |
| --- | --- | --- |
| Catalog poisoning | Canonical bytes bind every projected field; a changed projection changes the digest; signed layers with a different digest fail closed. | `tests/managed_controls/test_capabilities_catalog.py::test_catalog_poisoning_changes_digest_and_duplicate_permission_ids_fail_closed`; `tests/test_guard_extension_control_resolver.py::test_resolver_failures_are_typed_privacy_safe_and_fail_closed`; `tests/test_guard_extension_control_authority.py::test_catalog_manifest_tamper_is_detected_immediately` |
| Permission-ID collision | Permission IDs are unique across the whole projection and the runtime permission catalog retains one canonical owner. | `tests/managed_controls/test_capabilities_catalog.py::test_catalog_poisoning_changes_digest_and_duplicate_permission_ids_fail_closed`; `tests/test_guard_extension_control_catalog_detail.py::test_catalog_exposes_deterministic_full_extension_permission_and_rule_contract` |
| Custom Extension identity spoofing | Cloud identity must exactly match the locally observed ID and version; absence and mismatch never become an applicable identity. | `tests/managed_controls/test_catalog_privacy_identity.py::test_custom_identity_spoofing_requires_exact_id_and_version` |
| Downgrade to a client that ignores `x-*` | All negotiated Managed Controls capabilities are mandatory; an incomplete client is incompatible and receives no weakened fallback. | `tests/managed_controls/test_compatibility_migration.py::test_unsupported_client_is_excluded_not_silently_downgraded`; `tests/test_managed_controls_policy_fields.py::test_full_capability_negotiation_parses_managed_controls_and_rule_targets` |
| Signed bundle replay | Bundle versions are monotonic; same-version content substitution fails. Exact acknowledgement replay is idempotent, conflicting replay fails. | `tests/test_policy_bundle_v2.py::test_v2_transition_rejects_replay_and_same_version_substitution`; `tests/test_policy_bundle_v2.py::test_v2_acknowledgement_rejects_sequence_conflicts_and_terminal_reapply` |
| Out-of-order rollback | A lower bundle version is rejected. Rollback is a newer signed envelope bound to the current and expected last-good hashes. | `tests/test_policy_bundle_v2.py::test_v2_transition_accepts_only_authorized_monotonic_rollback`; `tests/test_managed_controls_activation_integration.py::test_replayed_authenticated_activation_cannot_rollback_durable_epoch` |
| Cross-workspace application | Workspace identity is checked before rule application and the trusted signing key is scoped to the expected workspace. | `tests/test_policy_bundle_parser.py::test_policy_bundle_rejects_wrong_workspace_before_rule_application`; `tests/test_policy_bundle_parser.py::test_policy_bundle_rejects_revoked_or_wrong_purpose_anchor` |
| Catalog TOCTOU | Activation validation is bound to the candidate catalog digest; catalog migration and runtime publication are atomic boundaries. A validation failure cannot stage or publish. | `tests/managed_controls/test_atomic_apply.py::test_validation_failure_never_stages_or_changes_state`; `tests/test_guard_extension_control_authority.py::test_catalog_digest_change_requires_trusted_migration_boundary`; `tests/test_managed_controls_activation_integration.py::test_activation_and_epoch_are_read_from_one_sqlite_snapshot` |
| Partial policy and authority activation | Validation, staging, commit, persistence, runtime publication, and rollback retain one complete prior projection on failure. | `tests/managed_controls/test_atomic_apply.py`; `tests/test_managed_controls_activation_integration.py::test_failed_partial_activation_retains_prior_complete_state`; `tests/test_managed_controls_activation_integration.py::test_runtime_publish_failure_rolls_back_database_activation`; `tests/test_managed_controls_activation_integration.py::test_commit_failure_does_not_publish_staged_runtime` |
| Local database tamper | Snapshots, transitions, managed activation, and revision epoch are authenticated and externally anchored; tamper yields a fail-closed authority state. | `tests/test_guard_extension_control_authority.py::test_authenticated_snapshot_transition_and_anchor_detect_sqlite_tamper`; `tests/test_guard_extension_control_authority.py::test_database_rollback_against_monotonic_anchor_fails_closed`; `tests/test_managed_controls_activation_integration.py::test_tampered_authenticated_activation_fails_closed` |
| Malicious administrator weakens a required floor | Managed-restrictive authority can only disable or lock down. Shared enablement is permission-only and requires a configurable permission. Required Extensions cannot be disabled by shared posture. | `tests/test_managed_controls_policy_fields.py::test_managed_restrictive_is_disable_or_lockdown_only`; `tests/test_managed_controls_policy_fields.py::test_shared_enable_respects_configurability_and_required_floors`; `tests/test_guard_extension_control_semantic_preview.py::test_local_draft_cannot_create_fixed_permission_or_required_extension_controls` |
| Remembered allow bypass | Remembered/local permits are inputs below disable-dominant managed floors; they cannot erase or outrank a managed block. | `tests/managed_controls/test_authority_composition.py::test_remembered_local_allow_cannot_bypass_managed_restriction`; `tests/test_guard_extension_control_semantic_preview.py::test_preview_explains_when_managed_disable_dominates_local_allow` |
| Oversized catalog or Control Set | Catalog bytes, extension/permission counts, rules, targets, layers, controls, observations, and identity text have explicit bounds and fail closed. | `tests/test_managed_controls_policy_fields.py::test_duplicates_conflicts_and_limits_fail_before_projection`; `tests/test_managed_controls_policy_fields.py::test_targeted_rule_count_limit_is_enforced`; `tests/test_guard_extension_control_resolver.py::test_resolver_input_limits_fail_closed_at_boundary`; `tests/test_guard_extension_control_catalog_wire.py::test_catalog_payload_limit_uses_exact_daemon_wire_encoding` |
| Regex or matcher denial of service in Advanced mode | Managed namespaced parsing never compiles or executes Advanced matchers. IDs are length-checked before their bounded canonical regex. Advanced-rule execution remains in the existing policy engine and its separate limits. | `tests/test_managed_controls_policy_fields.py::test_oversized_target_and_advanced_regex_are_not_evaluated_by_extension_parser`; `tests/test_managed_controls_policy_fields.py::test_namespaced_control_field_fuzz_rejects_near_matches` |
| Package Firewall double enforcement | Canonical delegation selects exactly one plane; package targets are returned as delegated targets and omitted from the signed command-control layer. | `tests/managed_controls/test_delegated_package_firewall.py`; `tests/test_managed_controls_policy_fields.py::test_delegated_targets_require_package_firewall_and_do_not_double_materialize` |
| Custom name or source-path leakage | Catalog export uses an exact allowlist, rejects sensitive/path-like text recursively, and telemetry/diagnostics use separate allowlists and redaction. | `tests/managed_controls/test_catalog_privacy_identity.py::test_custom_catalog_privacy_rejects_names_paths_commands_and_secrets`; `tests/managed_controls/test_flags_telemetry_redaction.py::test_telemetry_is_allowlisted_and_privacy_safe`; `tests/managed_controls/test_flags_telemetry_redaction.py::test_diagnostics_redact_sensitive_values_recursively` |

## Property, fuzz, and fault-injection matrix

The security properties are tested across generated combinations rather than
only one example:

- Disable dominance and order independence:
  `test_composition_is_permutation_independent_and_disable_dominates_enable`.
- Local tightening monotonicity:
  `test_adding_restrictions_never_reduces_the_resolved_action`.
- Immutable floors across every non-configurable permission and required
  Extension are enforced by
  `test_every_builtin_immutable_floor_rejects_shared_cloud_weakening` and the
  semantic-preview tests.
- Namespaced-field fuzzing covers wrong types, nulls, unsupported keys, embedded
  NUL, Unicode near-matches, regex-shaped keys, oversized IDs, duplicate and
  conflicting targets.
- Atomic-apply fault injection covers revision validation, candidate validation,
  compilation, commit, rollback, last-known-good restoration,
  database commit, runtime publication, and crash/retry recovery. The production
  SQLite transaction is terminated in subprocesses after remote-row replacement,
  before commit after all state writes, and immediately after commit but before
  runtime installation by
  `tests/test_managed_controls_activation_integration.py::test_process_crash_restart_never_exposes_partial_managed_activation`.

## Residual risk and review gate

- Custom Extension continuity depends on the workspace-scoped opaque identity
  contract and authenticated Local observation being enabled end to end. A
  display name is never identity.
- Advanced mode remains a separate expert surface. Managed Controls neither
  interprets nor broadens its matcher language; changes to that engine require
  its own complexity and denial-of-service review.
- A rollback failure is reported distinctly and the candidate is not published,
  but operators must treat it as an incident and repair from authenticated
  last-known-good state.
- Tests and this model are author evidence, not independent review. Managed
  Controls must not leave pilot until a reviewer independent of the implementer
  examines this model, the named controls, and the exact release diff, records
  findings, and signs off with no unresolved security findings.

## Review checklist

- [ ] Independent reviewer identified.
- [ ] Exact release diff reviewed against every threat row.
- [ ] Focused security matrix and full release CI green at reviewed commit.
- [ ] No unresolved security findings or review threads.
- [ ] Pilot exit approval recorded with reviewer, date, and commit SHA.
