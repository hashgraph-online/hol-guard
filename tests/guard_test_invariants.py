"""Stable ownership records for security-critical Guard regression tests.

The registry intentionally covers protected security boundaries rather than every
ordinary unit assertion. A selector may only point to a concrete test function,
which makes removal or relocation visible during collection validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class TestInvariant:
    """A security or release guarantee owned by one concrete test."""

    invariant_id: str
    selector: str
    subsystem: str
    guarantee: str
    markers: tuple[str, ...]


TEST_INVARIANTS: Final[tuple[TestInvariant, ...]] = (
    TestInvariant(
        "GUARD-INV-001",
        "tests/test_guard_command_corpus.py::test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline",
        "command-corpus",
        "Known command-evaluation gaps cannot widen without an explicit reviewed baseline update.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-002",
        "tests/test_guard_command_corpus.py::test_ten_reviewed_pairs_have_one_machine_checked_delta_and_run_through_guard",
        "command-corpus",
        "Reviewed minimal pairs keep their single semantic delta and Guard decision boundary.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-003",
        "tests/test_guard_runtime.py::test_guard_hook_codex_post_tool_use_blocks_credential_looking_output",
        "hook-output",
        "Codex post-tool output that resembles a credential is blocked before delivery.",
        ("security_critical", "regression", "integration", "release"),
    ),
    TestInvariant(
        "GUARD-INV-004",
        "tests/test_guard_runtime.py::test_guard_hook_codex_post_tool_use_blocks_named_secret_output",
        "hook-output",
        "Named secrets in Codex post-tool output cannot bypass output review.",
        ("security_critical", "regression", "integration", "release"),
    ),
    TestInvariant(
        "GUARD-INV-005",
        "tests/test_guard_runtime.py::test_guard_hook_codex_user_prompt_submit_guard_bypass_hard_blocks_without_approval_url",
        "hook-policy",
        "Guard-bypass prompt attempts hard-block without offering an approval escape hatch.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-006",
        "tests/test_guard_runtime.py::test_guard_hook_saved_artifact_approval_never_lowers_current_payload_block",
        "approval",
        "A remembered artifact approval cannot lower a current payload block.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-007",
        "tests/test_guard_runtime.py::test_guard_hook_claude_alias_saved_allow_does_not_lower_canonical_reapproval",
        "approval",
        "A Claude alias allow cannot lower canonical reapproval requirements.",
        ("security_critical", "regression", "policy", "adapter_contract", "release"),
    ),
    TestInvariant(
        "GUARD-INV-008",
        "tests/test_guard_runtime.py::test_policy_bundle_validation_rejects_tampered_hash",
        "managed-policy",
        "A policy bundle with a tampered hash is rejected.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-009",
        "tests/test_guard_runtime.py::test_cached_policy_bundle_revalidation_rejects_expired_last_known_good",
        "managed-policy",
        "An expired last-known-good policy bundle cannot be reactivated.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-010",
        "tests/test_guard_package_shims.py::test_guard_protect_requires_reapproval_for_untrusted_package_sources_without_cloud",
        "package-shim",
        "Untrusted package sources require reapproval without cloud policy support.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-011",
        "tests/test_guard_package_shims.py::test_guard_protect_saved_approval_does_not_bypass_new_bundle_block_for_unpinned_package",
        "package-shim",
        "A saved package approval cannot bypass a new signed bundle block.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-012",
        "tests/test_guard_policy_integrity.py::test_sync_state_tamper_cannot_downgrade_enforcement",
        "policy-integrity",
        "Tampered sync state cannot downgrade policy enforcement.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-013",
        "tests/test_guard_policy_integrity.py::test_direct_sqlite_insert_is_ignored_when_integrity_is_degraded",
        "policy-integrity",
        "Direct policy-row insertion is ignored while integrity is degraded.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-014",
        "tests/test_guard_mdm_policy.py::test_native_machine_policy_source_rejects_insecure_provenance",
        "managed-policy",
        "Managed policy rejects an insecure machine-policy source.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-015",
        "tests/test_guard_command_backup_extensions.py::test_backup_rules_feed_runtime_hooks",
        "command-extension",
        "Backup mutation variants remain reviewable through inspection and runtime enforcement.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-016",
        "tests/test_guard_command_domain_extensions.py::test_domain_rules_feed_inspection_and_runtime_hooks",
        "command-extension",
        "Container, Kubernetes, and infrastructure mutation variants remain reviewable through both enforcement paths.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-017",
        "tests/test_guard_command_database_extensions.py::test_database_rules_feed_runtime_hooks",
        "command-extension",
        "Database mutation variants remain reviewable through inspection and runtime enforcement.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-018",
        "tests/test_guard_command_remote_extensions.py::test_remote_rules_feed_runtime_hooks",
        "command-extension",
        "Remote execution and overwrite variants remain reviewable through inspection and runtime enforcement.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-019",
        "tests/test_guard_command_storage_extensions.py::test_storage_rules_feed_runtime_hooks",
        "command-extension",
        "Object-storage deletion variants remain reviewable through inspection and runtime enforcement.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-020",
        "tests/test_guard_seeded_faults.py::test_seeded_command_parser_faults_remain_rejected_or_visible",
        "seeded-faults",
        "Curated parser security faults remain rejected or observable through canonical parsing.",
        ("security_critical", "regression", "parser", "release"),
    ),
    TestInvariant(
        "GUARD-INV-021",
        "tests/test_guard_command_critical_floors.py::test_security_critical_commands_retain_exact_floors",
        "command-floor-corpus",
        "Critical destructive, secret, managed-service, and self-protection command floors remain exact.",
        ("security_critical", "regression", "parser", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-022",
        "tests/test_guard_github_command_capabilities.py::test_guard_requires_confirmation_for_github_mutations_and_unverified_compositions",
        "github-command-corpus",
        "GitHub mutation and dynamically resolved command forms keep their exact confirmation floors.",
        ("security_critical", "regression", "parser", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-023",
        "tests/test_guard_data_flow.py::test_data_flow_exfiltration_detector_flags_malicious_shell_patterns",
        "data-flow-corpus",
        "Known secret-source to external-sink patterns keep their required data-flow signal.",
        ("security_critical", "regression", "policy", "release"),
    ),
    TestInvariant(
        "GUARD-INV-024",
        "tests/test_guard_data_flow.py::test_data_flow_exfiltration_detector_ignores_benign_shell_patterns",
        "data-flow-corpus",
        "Known benign shell patterns do not create false-positive data-flow signals.",
        ("security_critical", "regression", "policy", "release"),
    ),
)


def invariant_markers_for_nodeid(nodeid: str) -> tuple[str, ...]:
    """Return the deduplicated markers inherited from matching invariant records."""
    markers: list[str] = []
    for invariant in TEST_INVARIANTS:
        if nodeid != invariant.selector and not nodeid.startswith(f"{invariant.selector}["):
            continue
        for marker in invariant.markers:
            if marker not in markers:
                markers.append(marker)
    return tuple(markers)
