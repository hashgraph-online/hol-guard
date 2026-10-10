"""Transport contract for resident package supply-chain evaluation.

Python only carries the artifact and hydrates the DTO. Every verdict comes from
the resident; a missing, unbound or malformed answer must become a block.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard import native_supply_chain_eval as transport
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_package_authority import _RESULT_SCHEMA


class _Artifact:
    artifact_id = "package:npm:left-pad"
    runtime_private_metadata: ClassVar[dict[str, object]] = {"k": "v"}

    def to_dict(self) -> dict[str, object]:
        return {"artifact_id": self.artifact_id}


def _store(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(guard_home=tmp_path, path=tmp_path / "guard.db")


def _payload() -> dict[str, object]:
    return {
        "decision": "allow",
        "policy_action": "allow",
        "enforcement": "free_local",
        "entitlement_state": "free",
        "cache_status": "miss",
        "package_intent_hash": "sha256:" + "0" * 64,
        "policy_version": "p",
        "reasons": [],
        "packages": [],
        "risk_summary": "ok",
        "user_copy": {"title": "Allowed", "summary": "ok", "harness_message": "ok"},
    }


def _bind(monkeypatch: pytest.MonkeyPatch, *, mutate=None) -> dict[str, object]:
    captured: dict[str, object] = {}
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)

    def resident(**kwargs: object) -> object:
        request = kwargs["request"]
        captured.update(kwargs)
        response: dict[str, object] = {
            "schema": _RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": _payload(),
        }
        if mutate is not None:
            mutate(response)
        return response

    monkeypatch.setattr(transport, "_resident_request", resident)
    return captured


def _evaluate(tmp_path: Path):
    return transport.evaluate_package_request_native(
        artifact=_Artifact(),
        store=_store(tmp_path),
        workspace_dir=tmp_path,
        now="2026-05-19T00:00:00Z",
    )


def test_request_is_bound_non_retaining_and_requires_feature(monkeypatch, tmp_path: Path) -> None:
    captured = _bind(monkeypatch)
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator

    persisted: list[object] = []
    monkeypatch.setattr(evaluator, "_persist_evidence", lambda **kwargs: persisted.append(kwargs["evaluation"]))
    result = _evaluate(tmp_path)
    assert result.decision == "allow"
    assert persisted == [result]
    assert captured["operation"] == "supply_chain_eval"
    assert captured["required_features"] == ("supply-chain-eval-v1",)
    request = captured["request"]
    assert request["retain_external_archive_blob"] is False
    assert request["runtime_private_metadata"] == {"k": "v"}
    assert request["store_path"] == str(tmp_path / "guard.db")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(request_id="other"),
        lambda r: r.update(request_sha256="sha256:" + "0" * 64),
        lambda r: r.update(status="error"),
        lambda r: r.update(code="denied"),
        lambda r: r.update(schema="wrong"),
        lambda r: r.update(extra="field"),
        lambda r: r.update(payload="nope"),
        lambda r: r.update(payload={"decision": "maybe"}),
        lambda r: r.update(payload={"decision": "allow"}),
        lambda r: r.update(payload={"decision": "allow", "policy_action": "allow"}),
        lambda r: r["payload"].pop("user_copy"),
        lambda r: r["payload"].update(reasons="none"),
        lambda r: r["payload"].update(policy_version=None),
    ],
)
def test_unbound_or_malformed_answer_blocks(monkeypatch, tmp_path: Path, mutate) -> None:
    _bind(monkeypatch, mutate=mutate)
    result = _evaluate(tmp_path)
    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "native_supply_chain_eval_unavailable"
    assert (result.enforcement, result.entitlement_state) == ("free_local", "free")


def test_absent_optional_fields_are_omitted_from_the_bound_request(monkeypatch, tmp_path: Path) -> None:
    captured = _bind(monkeypatch)
    result = transport.evaluate_package_request_native(
        artifact=_Artifact(),
        store=_store(tmp_path),
        workspace_dir=None,
    )
    request = captured["request"]
    assert "now" not in request
    assert "workspace_dir" not in request
    assert all(value is not None for value in request.values())
    assert result.decision == "allow"


@pytest.mark.parametrize("answer", [None, [], "text"])
def test_missing_resident_answer_blocks(monkeypatch, tmp_path: Path, answer) -> None:
    _bind(monkeypatch)
    monkeypatch.setattr(transport, "_resident_request", lambda **_: answer)
    assert _evaluate(tmp_path).decision == "block"


def test_unprovisioned_resident_blocks_before_any_request(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: False)
    monkeypatch.setattr(
        transport, "_resident_request", lambda **_: pytest.fail("no RPC without a provisioned resident")
    )
    assert _evaluate(tmp_path).decision == "block"


def test_store_without_paths_blocks(tmp_path: Path) -> None:
    result = transport.evaluate_package_request_native(
        artifact=_Artifact(),
        store=SimpleNamespace(guard_home="nope", path=None),
        workspace_dir=tmp_path,
    )
    assert result.decision == "block"
    assert result.policy_version == "native-unavailable"
