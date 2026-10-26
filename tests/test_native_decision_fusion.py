from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_consumer_artifact_compose, native_hook_artifact_compose
from codex_plugin_scanner.guard.runtime.decisions import project_native_authoritative_decision

_FIXTURES = Path(__file__).parent.parent / "rust/crates/guard-runtime/tests/fixtures"


@pytest.mark.usefixtures("native_approval_reuse_runtime")
@pytest.mark.parametrize("operation", ("hook", "consumer"))
def test_fused_decision_needs_one_existing_resident_call(
    monkeypatch: pytest.MonkeyPatch, native_approval_reuse_runtime: Path, operation: str
) -> None:
    from codex_plugin_scanner.guard import native_decisions

    def separate_decision(*args: object, **kwargs: object) -> object:
        pytest.fail("fused decision must not make a separate authority request")

    monkeypatch.setattr(native_decisions, "_request", separate_decision)
    client = native_hook_artifact_compose if operation == "hook" else native_consumer_artifact_compose
    original = client._resident_request
    calls: list[str] = []

    def tracked(*args: object, **kwargs: object):
        calls.append(str(kwargs.get("operation")))
        return original(*args, **kwargs)

    monkeypatch.setattr(client, "_resident_request", tracked)
    vectors = json.loads((_FIXTURES / f"{operation}_artifact_compose_vectors.json").read_text())
    if operation == "hook":
        copy = dict(next(vector["query"] for vector in vectors if vector["query"]["kind"] == "decision_copy"))
        copy.pop("kind")
        answer = client.native_hook_compose(
            "decision_build_copy",
            {"copy": copy, "reason": "fixture", "signals": []},
            guard_home=native_approval_reuse_runtime,
        )
        assert answer["decision_v2"]["guard_action"] == copy["policy_action"]
    else:
        vector = next(vector for vector in vectors if vector["query"]["kind"] == "runtime_decision")
        runtime = dict(vector["query"])
        runtime.pop("kind")
        answer = client.native_consumer_compose(
            "runtime_authoritative",
            {"runtime": runtime, "signals": []},
            guard_home=native_approval_reuse_runtime,
        )
        projected = project_native_authoritative_decision(cast("dict[str, Any]", answer["authoritative_decision"]))
        assert projected.action == vector["expected"]["policy_action"]
        assert projected.reason == vector["expected"]["decision_reason"]
    assert calls == [f"{operation}_artifact_compose"]


@pytest.mark.usefixtures("native_approval_reuse_runtime")
@pytest.mark.parametrize("operation", ("hook", "consumer"))
def test_repeated_semantic_refusals_keep_the_real_resident_available(
    native_approval_reuse_runtime: Path, operation: str
) -> None:
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.native_runtime_resilience import native_runtime_health_snapshot

    vectors = json.loads((_FIXTURES / f"{operation}_artifact_compose_vectors.json").read_text())
    if operation == "hook":
        copy = dict(next(v["query"] for v in vectors if v["query"]["kind"] == "decision_copy"))
        copy.pop("kind")
        copy["policy_action"] = "allow"
        for _ in range(3):
            with pytest.raises(native_hook_artifact_compose.NativeHookComposeValidationError):
                native_hook_artifact_compose.native_hook_compose(
                    "decision_build_copy",
                    {"copy": copy, "reason": "fixture", "signals": {}},
                    guard_home=native_approval_reuse_runtime,
                )
        assert (
            native_hook_artifact_compose.native_hook_compose(
                "tool_grant_apply", {}, guard_home=native_approval_reuse_runtime
            )["policy_action"]
            == "allow"
        )
    else:
        reference = json.loads((Path(__file__).parent / "fixtures/decision_authority_vectors.json").read_text())
        vector = next(
            v for v in reference["vectors"] if "consumer_runtime_query" in v and v["expected"]["status"] == "error"
        )
        runtime = dict(vector["consumer_runtime_query"])
        runtime.pop("kind")
        for _ in range(3):
            with pytest.raises(
                native_consumer_artifact_compose.NativeConsumerComposeValidationError, match="cannot be"
            ):
                native_consumer_artifact_compose.native_consumer_compose(
                    "runtime_authoritative",
                    {"runtime": runtime, "signals": []},
                    guard_home=native_approval_reuse_runtime,
                )
        healthy = next(v for v in vectors if v["query"]["kind"] == "current_action")
        fields = dict(healthy["query"])
        fields.pop("kind")
        assert (
            native_consumer_artifact_compose.native_consumer_compose(
                "current_action", fields, guard_home=native_approval_reuse_runtime
            )
            == healthy["expected"]
        )
    identity = native_runtime_status().identity
    assert identity is not None
    assert not native_runtime_health_snapshot(identity.sha256, native_approval_reuse_runtime).circuit_open
