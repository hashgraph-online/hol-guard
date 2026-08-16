from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "guard" / "contracts"


def _load(name: str) -> dict[str, object]:
    payload = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_native_capability_ownership_has_one_declared_owner_per_capability() -> None:
    payload = _load("rust-native-capability-ownership.v1.json")
    capabilities = payload["capabilities"]
    assert isinstance(capabilities, list)
    ids: set[str] = set()
    dead_duplicates = 0
    for item in capabilities:
        assert isinstance(item, dict)
        capability_id = item["id"]
        assert isinstance(capability_id, str) and capability_id not in ids
        ids.add(capability_id)
        assert item["authority"] in {
            "rust_eligible_python_reference",
            "python_authoritative_rust_shadow",
            "python_authoritative",
            "hook_worker_direct",
        }
        assert isinstance(item["python_owner"], str) and item["python_owner"]
        if item["python_removal_status"] in {"dead_duplicate_remove", "removed"}:
            dead_duplicates += 1
    assert dead_duplicates >= 1


def test_fail_safe_matrix_never_allows_unreviewed_output() -> None:
    payload = _load("rust-native-fail-safe-matrix.v1.json")
    conditions = payload["conditions"]
    assert isinstance(conditions, dict)
    for condition in conditions.values():
        assert isinstance(condition, dict)
        post_tool = condition["post_tool"]
        assert isinstance(post_tool, str)
        assert post_tool in {
            "python_reference_withhold_until_complete",
            "python_reference_within_deadline",
            "withhold_or_block",
            "not_valid_for_allow",
            "more_restrictive_output_action",
            "python_reference_or_block",
        }


def test_emergency_safe_profile_is_default_deny_and_has_no_network_capability() -> None:
    payload = _load("rust-emergency-safe-profile.v1.json")
    assert payload["default"] == "pause"
    prohibitions = payload["global_prohibitions"]
    assert isinstance(prohibitions, list)
    assert "network_access" in prohibitions
    assert "secret_or_sensitive_path_access" in prohibitions
    operations = payload["allowed_operations"]
    assert isinstance(operations, list) and operations
    for operation in operations:
        assert isinstance(operation, dict)
        argv = operation["exact_argv"]
        assert isinstance(argv, list) and all(isinstance(value, str) and value for value in argv)


def test_native_reason_codes_are_unique_and_privacy_safe() -> None:
    payload = _load("rust-native-reason-codes.v1.json")
    codes = payload["codes"]
    assert isinstance(codes, list)
    values = [item["code"] for item in codes if isinstance(item, dict)]
    assert len(values) == len(set(values))
    forbidden = ("path", "command", "prompt", "secret", "token", "proof", "output")
    assert all(not any(word in str(code) for word in forbidden) for code in values)


def test_hardening_source_documents_reference_the_current_backlog() -> None:
    migration = (ROOT / "docs" / "guard" / "rust-runtime-migration-todo.md").read_text(encoding="utf-8")
    hardening = (ROOT / "docs" / "guard" / "rust-runtime-hardening-todo.md").read_text(encoding="utf-8")
    prd = (ROOT / "docs" / "guard" / "rust-runtime-hardening-prd.md").read_text(encoding="utf-8")
    assert "rust-runtime-hardening-todo.md" in migration
    assert "NRH-T001" in hardening and "NRH-T129" in hardening
    assert "Definition of done" in prd


def test_dead_python_cleanup_is_an_explicit_release_gate() -> None:
    ownership = _load("rust-native-capability-ownership.v1.json")
    capabilities = ownership["capabilities"]
    assert isinstance(capabilities, list)
    selector = next(
        item for item in capabilities if isinstance(item, dict) and item.get("id") == "native_backend_response_selector"
    )
    assert selector["python_removal_status"] == "removed"
    evidence = selector["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["deletion_task"] == "NRH-T112"

    prd = (ROOT / "docs" / "guard" / "rust-runtime-hardening-prd.md").read_text(encoding="utf-8")
    todo = (ROOT / "docs" / "guard" / "rust-runtime-hardening-todo.md").read_text(encoding="utf-8")
    assert "replaced, unreachable, or untested python" in prd.lower()
    assert "NRH-T112" in todo and "choose_post_tool_response" in todo


def test_removed_native_selector_is_absent_from_the_package() -> None:
    from codex_plugin_scanner.guard import native_runtime

    assert not hasattr(native_runtime, "choose_post_tool_response")
    source = (ROOT / "src" / "codex_plugin_scanner" / "guard" / "native_runtime.py").read_text(encoding="utf-8")
    assert "def choose_post_tool_response" not in source
    assert '"choose_post_tool_response"' not in source
