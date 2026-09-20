"""Scoped result decoding retains exact source, generation and receipt identity."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.native_hook_edge import _decode_edge
from tests.test_native_hook_edge import _edge_result


def _bound_result(*, observe: bool = False) -> tuple[dict[str, Any], dict[str, object]]:
    result: dict[str, Any] = _edge_result()
    result.update(
        schema="guard-hook-edge-result.v3",
        request_id="request-1",
        observed_policy_action=result["result"]["policy_action"] if observe else None,
    )
    binding = dict(
        policy_generation=7,
        policy_digest="b" * 64,
        source_input_digest="c" * 64,
        runtime_identity="d" * 64,
        resident_generation=3,
        selected_decision_id=8,
    )
    result["policy_binding"] = binding
    receipt = result["receipt"]
    receipt.update(
        policy_generation=7,
        policy_digest="b" * 64,
        runtime_identity="d" * 64,
        rule_digest="e" * 64,
        observe_mode=observe,
        observed_policy_action=result["observed_policy_action"],
    )
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    expected: dict[str, object] = dict(binding, generation=7, mode="observe" if observe else "enforce")
    expected.pop("policy_generation")
    expected.pop("selected_decision_id")
    return result, expected


@pytest.mark.parametrize("observe", [False, True])
def test_scoped_result_requires_exact_published_identity(observe: bool) -> None:
    result, binding = _bound_result(observe=observe)
    assert _decode_edge(result, snapshot_binding=binding) == result
    assert _decode_edge(result) is None
    for key in (
        "generation",
        "policy_digest",
        "source_input_digest",
        "runtime_identity",
        "resident_generation",
        "mode",
    ):
        changed = dict(binding)
        changed[key] = 999 if isinstance(changed[key], int) else "f" * 64
        assert _decode_edge(result, snapshot_binding=changed) is None


@pytest.mark.parametrize("action", ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"])
def test_observe_without_projection_retains_authenticated_receipt_mode(action: str) -> None:
    result, binding = _bound_result(observe=True)
    result["observed_policy_action"] = None
    decision = "allow" if action in {"allow", "warn"} else "deny"
    result["result"].update(
        policy_action=action, minimum_action=action, decision=decision, explicitly_benign=action == "allow"
    )
    receipt = result["receipt"]
    receipt.update(policy_action=action, decision=decision, observed_policy_action=None)
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    assert _decode_edge(result, snapshot_binding=binding) == result
    receipt["observe_mode"] = False
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    assert _decode_edge(result, snapshot_binding=binding) is None


@pytest.mark.parametrize("observed", [True, False, 0, 1, 1.0, "", "unknown", [], {}])
def test_optional_observe_projection_still_requires_finite_action(observed: object) -> None:
    result, binding = _bound_result(observe=True)
    result["observed_policy_action"] = observed
    assert _decode_edge(result, snapshot_binding=binding) is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_generation", True),
        ("policy_generation", 0),
        ("policy_generation", 7.0),
        ("resident_generation", 0),
        ("resident_generation", True),
        ("resident_generation", 3.0),
        ("selected_decision_id", True),
        ("selected_decision_id", 0),
        ("selected_decision_id", 8.0),
        ("selected_decision_id", 1 << 53),
        ("source_input_digest", "C" * 64),
        ("source_input_digest", None),
        ("policy_digest", "z" * 64),
        ("runtime_identity", "d" * 63),
    ],
)
def test_malformed_scoped_identity_is_not_authority(field: str, value: object) -> None:
    result, binding = _bound_result()
    result["policy_binding"][field] = value
    assert _decode_edge(result, snapshot_binding=binding) is None


def test_scoped_result_never_infers_missing_binding_or_receipt_fields() -> None:
    result, binding = _bound_result()
    for section in (None, "policy_binding", "receipt"):
        source = result if section is None else result[section]
        for key in source:
            changed = deepcopy(result)
            target = changed if section is None else changed[section]
            target.pop(key)
            assert _decode_edge(changed, snapshot_binding=binding) is None
        changed = deepcopy(result)
        target = changed if section is None else changed[section]
        target["extra"] = "ignored authority is forbidden"
        assert _decode_edge(changed, snapshot_binding=binding) is None


def test_recomputed_receipt_hash_does_not_replace_snapshot_binding() -> None:
    result, binding = _bound_result()
    for field, value in (("policy_generation", 8), ("policy_digest", "f" * 64), ("runtime_identity", "f" * 64)):
        changed = deepcopy(result)
        changed["receipt"][field] = value
        changed["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(changed["receipt"])).hexdigest()
        assert _decode_edge(changed, snapshot_binding=binding) is None
    result["policy_binding"]["selected_decision_id"] = None
    assert _decode_edge(result, snapshot_binding=binding) == result


@pytest.mark.parametrize(
    "fault", [None, "legacy", "duplicate", "partial-capabilities", "other-request", "other-harness", "other-rules"]
)
def test_scoped_transport_requires_complete_capability_and_unambiguous_response(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, fault: str | None
) -> None:
    import json

    from codex_plugin_scanner.guard import native_hook_edge as bridge
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    result, binding = _bound_result()
    identity = NativeRuntimeIdentity(path=tmp_path / "runtime", size=1, mtime_ns=1, sha256="d" * 64)
    features = {
        "hook-envelope-v3",
        "policy-snapshot-v4",
        "policy-scoped-authority-v1",
        "native-resident-client-v1",
        "pre-tool-generic-authority-v1",
    }
    if fault == "partial-capabilities":
        features.remove("policy-scoped-authority-v1")
    capabilities = NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="test",
        rule_digest="e" * 64,
        build_sha="f" * 40,
        target="test",
        features=tuple(features),
    )
    monkeypatch.setattr(
        bridge,
        "native_runtime_status",
        lambda: NativeRuntimeStatus(
            mode="force",
            available=True,
            compatible=True,
            reason="ready",
            identity=identity,
            capabilities=capabilities,
        ),
    )
    monkeypatch.setattr(bridge, "native_record_resident_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(bridge, "native_record_resident_success", lambda *args, **kwargs: None)
    requests = []

    def client(**kwargs: Any) -> bytes:
        requests.append(json.loads(kwargs["payload"]))
        if fault == "legacy":
            return json.dumps(_edge_result()).encode()
        result["request_id"] = requests[-1]["request_id"] if fault != "other-request" else "other-request-id"
        result["receipt"]["request_id"] = result["request_id"]
        if fault == "other-harness":
            result["harness"] = result["receipt"]["harness"] = result["result"]["action"]["harness"] = "pi"
        if fault == "other-rules":
            result["receipt"]["rule_digest"] = "f" * 64
        result["receipt"]["decision_id"] = hashlib.sha256(canonical_receipt_bytes(result["receipt"])).hexdigest()
        encoded = json.dumps(result)
        if fault == "duplicate":
            encoded = encoded.replace('"resident_generation": 3', '"resident_generation": 2, "resident_generation": 3')
        return encoded.encode()

    monkeypatch.setattr(bridge, "native_resident_client_request", client)
    actual = bridge.review_raw_hook_native(
        payload={"tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event="PreToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=None,
        policy_snapshot=binding,
    )
    assert (actual == result) if fault is None else actual is None
    assert len(requests) == (0 if fault == "partial-capabilities" else 1)
    if requests:
        assert requests[0]["policy_snapshot"] == {
            "generation": 7,
            "policy_digest": "b" * 64,
            "runtime_identity": "d" * 64,
            "source_input_digest": "c" * 64,
        }


@pytest.mark.parametrize("value", [True, 1.0])
def test_scoped_protocol_versions_require_integers(value: object) -> None:
    for section in ("result", "action"):
        result, binding = _bound_result()
        target = result["result"] if section == "result" else result["result"]["action"]
        target["version"] = value
        assert _decode_edge(result, snapshot_binding=binding) is None


@pytest.mark.parametrize("field,value", [("generation", 7.0), ("resident_generation", 3.0)])
def test_scoped_expected_generation_requires_integer(field: str, value: object) -> None:
    result, binding = _bound_result()
    binding[field] = value
    assert _decode_edge(result, snapshot_binding=binding) is None
