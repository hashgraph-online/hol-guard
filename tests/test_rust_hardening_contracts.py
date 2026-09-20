from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "guard" / "contracts"


def _load(name: str) -> dict[str, object]:
    payload = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_hook_data_plane_ownership_v2_maps_every_supported_route() -> None:
    payload = _load("hook-data-plane-ownership.v2.json")
    assert payload["schema"] == "hol-guard.hook-data-plane-ownership.v2"
    harnesses = payload["supported_harnesses"]
    harness_routes = payload["harness_routes"]
    assert isinstance(harnesses, list)
    assert isinstance(harness_routes, dict)
    assert set(harnesses) == set(harness_routes)
    assert all(
        isinstance(route, dict) and set(route) == {"pre_tool_use", "post_tool_use"} for route in harness_routes.values()
    )

    routes = payload["routes"]
    assert isinstance(routes, list)
    assert {route["id"] for route in routes if isinstance(route, dict)} == {
        "http_pre_tool_use",
        "http_post_tool_use",
        "cli_pre_tool_use",
        "cli_post_tool_use",
    }
    assert all(
        isinstance(route, dict)
        and route["target_authority"] == "rust"
        and route["native_failure"] == "fail_closed"
        and route["python_semantic_fallback_target"] is False
        for route in routes
    )


def test_hook_data_plane_ownership_v2_has_one_declared_class_per_node() -> None:
    payload = _load("hook-data-plane-ownership.v2.json")
    nodes = payload["nodes"]
    assert isinstance(nodes, list)
    ids: set[str] = set()
    allowed_classes = {
        "rust_semantic",
        "rust_io",
        "python_semantic",
        "python_transport",
        "python_control",
        "persistence_only",
    }
    for node in nodes:
        assert isinstance(node, dict)
        node_id = node["id"]
        assert isinstance(node_id, str) and node_id not in ids
        ids.add(node_id)
        assert node["class"] in allowed_classes
        assert isinstance(node["paths"], list) and node["paths"]


def test_historical_fail_safe_matrix_retains_its_original_declarations() -> None:
    payload = _load("rust-native-fail-safe-matrix.v1.json")
    assert payload["status"] == "historical_superseded_for_current_delivery"
    assert payload["superseded_by"] == "../native-runtime-technical-contract-review.md"
    # Current delivery behavior is exercised by test_native_runtime_delivery_contract.py.
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
            "observe_continue",
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


def _required_ownership_steps(script: str) -> list[dict[str, object]]:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "rust-authority-ownership.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["ownership"]
    assert not job.get("continue-on-error", False)
    assert "if" not in job
    steps = [step for step in job["steps"] if script in step.get("run", "")]
    assert steps, f"ownership workflow does not run {script}"
    for step in steps:
        assert not step.get("continue-on-error", False)
        assert "if" not in step
    return steps


def test_hardening_contracts_are_enforced_by_the_ownership_workflow() -> None:
    for script in (
        "scripts/ci/rust_authority_ownership_gate.py",
        "scripts/ci/native_approval_contract_gate.py",
        "scripts/ci/python_hook_semantic_callgraph_gate.py",
        "scripts/ci/native_receipt_persistence_gate.py",
    ):
        _required_ownership_steps(script)


def test_dead_python_cleanup_is_an_explicit_release_gate() -> None:
    ownership = _load("hook-data-plane-ownership.v2.json")
    nodes = ownership["nodes"]
    assert isinstance(nodes, list)
    oracle = next(item for item in nodes if isinstance(item, dict) and item.get("id") == "python_reference_oracle")
    assert oracle["target"] == "differential tests only"

    cleanup = _load("python-capability-ownership.v1.json")
    classes = cleanup["classes"]
    assert isinstance(classes, list)
    assert set(classes) == {"required_control_plane", "named_reference_oracle", "dead_duplicate"}
    assert cleanup["package_excluded_candidates"] == ["src/codex_plugin_scanner/guard/native_runtime_resident.py"]
    steps = _required_ownership_steps("scripts/ci/python_capability_cleanup_gate.py")
    commands = "\n".join(str(step["run"]) for step in steps)
    assert "--root . --json python-capability-cleanup.json" in commands
    assert '--artifact "$BUILT_WHEEL"' in commands
    assert '--artifact "$BUILT_SDIST"' in commands


def test_removed_native_selector_is_absent_from_the_package() -> None:
    from codex_plugin_scanner.guard import native_runtime

    assert not hasattr(native_runtime, "choose_post_tool_response")
    source = (ROOT / "src" / "codex_plugin_scanner" / "guard" / "native_runtime.py").read_text(encoding="utf-8")
    assert "def choose_post_tool_response" not in source
    assert '"choose_post_tool_response"' not in source
