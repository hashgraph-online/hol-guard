from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import macos_code_signing
from codex_plugin_scanner.guard.mdm import runtime_request


def _answer_with(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def fake(feature: str, command: str, request: dict[str, object], **kwargs: object) -> dict[str, object] | None:
        assert (feature, command) == ("native-macos-code-signing-v1", "macos-code-signing")
        assert isinstance(kwargs["timeout_seconds"], float)
        requests.append(request)
        return answer

    monkeypatch.setattr(runtime_request, "runtime_answer", fake)
    return requests


def test_the_runtime_names_the_verified_team(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(macos_code_signing.sys, "platform", "darwin")
    requests = _answer_with(monkeypatch, {"team": "TEAMID"})
    team = macos_code_signing.verified_macos_signing_team(Path("/Applications/Guard.app"), deep=True, timeout=7.5)
    assert team == "TEAMID"
    assert requests == [
        {
            "schema": "macos-code-signing.v1",
            "op": "team",
            "path": "/Applications/Guard.app",
            "deep": True,
            "timeout_ms": 7500,
        }
    ]


@pytest.mark.parametrize("answer", [None, {}, {"team": None}, {"team": ""}, {"team": 7}])
def test_a_team_the_runtime_did_not_verify_is_none(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    monkeypatch.setattr(macos_code_signing.sys, "platform", "darwin")
    _ = _answer_with(monkeypatch, answer)
    assert macos_code_signing.verified_macos_signing_team(Path("/x")) is None


def test_other_platforms_have_no_team(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(macos_code_signing.sys, "platform", "linux")
    requests = _answer_with(monkeypatch, {"team": "TEAMID"})
    assert macos_code_signing.verified_macos_signing_team(Path("/x")) is None
    assert requests == []


@pytest.mark.parametrize(("answer", "sealed"), [({"sealed": True}, True), ({"sealed": False}, False), (None, False)])
def test_only_a_runtime_answered_seal_is_sealed(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None, sealed: bool
) -> None:
    requests = _answer_with(monkeypatch, answer)
    assert macos_code_signing.macos_bundle_sealed(Path("/t/hol-guard")) is sealed
    assert requests == [{"schema": "macos-code-signing.v1", "op": "sealed", "path": "/t/hol-guard"}]


@pytest.mark.parametrize(
    ("answer", "failure"),
    [
        ({"failure": None}, None),
        ({"failure": "desktop_core_signature_mismatch"}, "desktop_core_signature_mismatch"),
        (None, "desktop_core_signature_invalid"),
        ({}, "desktop_core_signature_invalid"),
        ({"failure": 3}, "desktop_core_signature_invalid"),
    ],
)
def test_a_tree_fails_closed_without_a_runtime_answer(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None, failure: str | None
) -> None:
    requests = _answer_with(monkeypatch, answer)
    assert macos_code_signing.macos_tree_signature_failure(Path("/t"), expected_team="TEAMID") == failure
    assert requests == [{"schema": "macos-code-signing.v1", "op": "tree", "path": "/t", "expected_team": "TEAMID"}]
