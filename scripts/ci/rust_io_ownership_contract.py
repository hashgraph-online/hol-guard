"""Capability contract for the decision-critical I/O ownership gate."""

from __future__ import annotations

from collections.abc import Iterable

_GUARD = "src/codex_plugin_scanner/guard/"
# Each entry names a complete lexical function and only its observed primitive
# operations. Siblings, nested functions and new content operations stay closed.
_SCOPED_IO = {
    # The injected scope reader decodes only bytes from the shared held capture.
    # Its temporary exception repeats the existing metadata-only scope policy;
    # explicit callable roots keep this synchronous posture work inventoried.
    ("config.py", "_parse_toml", "decode"): (
        "asynchronous_policy",
        frozenset({"loads", "decode"}),
    ),
    ("runtime/local_temp_paths.py", "trusted_temporary_root_for_path", "filesystem"): (
        "asynchronous_policy",
        frozenset({"resolve"}),
    ),
    ("runtime/local_temp_paths.py", "_darwin_user_temporary_root", "filesystem"): (
        "asynchronous_policy",
        frozenset({"is_dir"}),
    ),
    ("runtime/local_temp_paths.py", "_owned_by_current_user", "filesystem"): (
        "asynchronous_policy",
        frozenset({"stat"}),
    ),
    # The held config reader serves both background policy publication and
    # synchronous posture reads. The gate's posture reachability walk promotes
    # these observations to synchronous_posture_config; they are not hidden as
    # cold-only work. Keep every exception lexical-function/primitive scoped.
    ("config_source_io.py", "_posix_parent_chain", "filesystem"): (
        "asynchronous_policy",
        frozenset({"open", "stat"}),
    ),
    ("config_source_io.py", "_read_descriptor", "filesystem"): ("asynchronous_policy", frozenset({"read"})),
    ("config_source_io.py", "_capture_in_parent", "filesystem"): ("asynchronous_policy", frozenset({"open"})),
    ("config_source_io.py", "_capture_in_parent.metadata", "filesystem"): (
        "asynchronous_policy",
        frozenset({"lstat", "stat"}),
    ),
    ("config_source_io.py", "_verify_missing_parent", "filesystem"): (
        "asynchronous_policy",
        frozenset({"lstat", "stat"}),
    ),
    ("config_source_io.py", "capture_guard_config", "filesystem"): (
        "asynchronous_policy",
        frozenset({"resolve", "stat"}),
    ),
}


def scoped_io_category(path: str, kind: str, function: str, operation: str = "") -> str | None:
    if not path.startswith(_GUARD):
        return None
    entry = _SCOPED_IO.get((path[len(_GUARD) :], function, kind))
    if entry is None or (operation and operation not in entry[1]):
        return None
    return entry[0]


def capability_contract(compatibility_modes: Iterable[str]) -> list[dict[str, object]]:
    return [
        {
            "id": "hook_posture_and_availability_response",
            "authority": "python_bridge",
            "python_decision_time_disk_io": True,
            "inventory_category": "synchronous_posture_config",
            "python_semantic_fallback": False,
            "failure": "event_specific_availability_contract",
        },
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
