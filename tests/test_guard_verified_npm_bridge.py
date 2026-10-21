"""Reply validation and fail-closed behavior of the verified npm bridge."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_verified_npm as bridge


def _reply(monkeypatch: pytest.MonkeyPatch, payload: object, **overrides: object) -> list[dict[str, Any]]:
    """Record the requests the bridge sends and answer each with ``payload``."""

    sent: list[dict[str, Any]] = []

    def fake(**kwargs: Any) -> dict[str, object]:
        request = kwargs["request"]
        sent.append({**kwargs, "request": request})
        response = {
            "schema": bridge._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + bridge._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "payload": payload,
        }
        response.update(overrides)
        return response

    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(bridge, "_resident_request", fake)
    return sent


def _proof(tmp_path: Path, **kwargs: Any) -> tuple[str | None, bool]:
    return bridge.verified_npm_proof(
        {"environment_names": ["PATH"], "path": "/usr/bin"},
        workspace=tmp_path / "workspace",
        guard_home=tmp_path / "guard",
        **kwargs,
    )


def test_a_proven_version_is_returned_with_the_filter_verdict(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _reply(monkeypatch, {"version": "11.9.0", "filters_outside_workspace": True})

    assert _proof(tmp_path, filter_programs=["tail"]) == ("11.9.0", True)
    assert sent[0]["operation"] == "verified_npm"
    assert sent[0]["required_features"] == (bridge._VERIFIED_NPM_FEATURE,)
    assert sent[0]["request"]["filter_programs"] == ["tail"]
    assert sent[0]["request"]["schema"] == bridge._REQUEST_SCHEMA


def test_an_unproven_version_is_an_answer_not_a_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, {"version": None, "filters_outside_workspace": False})

    assert _proof(tmp_path) == (None, False)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": "11.9.0"},
        {"filters_outside_workspace": True},
        {"version": "11.9.0", "filters_outside_workspace": True, "extra": 1},
        {"version": "", "filters_outside_workspace": True},
        {"version": 11, "filters_outside_workspace": True},
        {"version": "11.9.0", "filters_outside_workspace": "yes"},
        {"version": "11.9.0", "filters_outside_workspace": None},
        "11.9.0",
    ],
)
def test_a_payload_that_is_not_the_contract_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: object
) -> None:
    _reply(monkeypatch, payload)

    with pytest.raises(bridge.NativeVerifiedNpmError):
        _proof(tmp_path)


@pytest.mark.parametrize(
    "override",
    [
        {"schema": "guard-other-result.v1"},
        {"request_id": "someone-elses"},
        {"request_sha256": "sha256:0"},
        {"status": "error"},
        {"code": "native_verified_npm_invalid"},
    ],
)
def test_a_reply_for_another_request_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, override: dict[str, object]
) -> None:
    _reply(monkeypatch, {"version": "11.9.0", "filters_outside_workspace": True}, **override)

    with pytest.raises(bridge.NativeVerifiedNpmError):
        _proof(tmp_path)


def test_a_resident_that_cannot_answer_proves_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)

    with pytest.raises(bridge.NativeVerifiedNpmError):
        _proof(tmp_path)


def test_an_unserializable_environment_proves_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _reply(monkeypatch, {"version": "11.9.0", "filters_outside_workspace": True})

    with pytest.raises(bridge.NativeVerifiedNpmError):
        bridge.verified_npm_proof(
            object(),
            workspace=tmp_path / "workspace",
            guard_home=tmp_path / "guard",
        )
