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
            "authority": "rust",
            "rust_symbols": [
                "guard_archive::inspect_path",
                "guard_secure_fs::open_immutable_blob",
                "guard_runtime::archive_inspect::evaluate_archive_inspection_bytes",
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
        {
            "id": "managed_structured_output_destination_mediation",
            "authority": "python_adapter_restrictive_layer",
            "python_files": [
                "src/codex_plugin_scanner/guard/runtime/secret_sensitivity.py",
                "src/codex_plugin_scanner/guard/runtime/structured_data_sensitivity.py",
                "src/codex_plugin_scanner/guard/runtime/structured_output_mediation.py",
            ],
            "python_operations": [
                "bounded_in_memory_json_decode_and_canonicalization",
                "secret_rule_version_fingerprint",
                "structured_content_sha256_binding",
            ],
            "rust_decision_and_receipt_remain_authoritative": True,
            "failure": "fail_closed",
        },
    ]
