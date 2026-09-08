"""Capability contract for the decision-critical I/O ownership gate."""

from __future__ import annotations

from collections.abc import Iterable


def capability_contract(compatibility_modes: Iterable[str]) -> list[dict[str, object]]:
    return [
        {
            "id": "post_tool_source_read",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::read_bounded", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "sensitive_path_and_symlink_classification",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::classify_source_path", "guard_secure_fs::contains_symlink_component"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "pre_post_identity_and_equivalence",
            "authority": "rust",
            "rust_symbols": ["guard_secure_fs::FileIdentity", "guard_hook_core::review_post_tool"],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "archive_decode_package_inspection",
            "authority": "rust_when_hook_reachable",
            "rust_symbols": [
                "guard_command::pretool::evaluate_pre_tool_envelope",
                "guard_runtime::strict_json::parse",
                "guard_hook_core::extract_payload_output",
            ],
            "python_semantic_fallback": False,
            "compatibility_modes": sorted(compatibility_modes),
            "failure": "fail_closed",
        },
        {
            "id": "policy_snapshot_admission",
            "authority": "rust",
            "rust_symbols": [
                "guard_runtime::policy_store::PolicySnapshotStore",
                "guard_runtime::edge::evaluate_envelope_with_store",
            ],
            "python_semantic_fallback": False,
            "python_decision_time_disk_io": False,
            "failure": "fail_closed",
        },
    ]
