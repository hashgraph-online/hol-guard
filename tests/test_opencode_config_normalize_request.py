"""The OpenCode install snapshot asks the native `opencode_config_normalize` kind for each config."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters._modules.opencode import opencode_install_snapshot as snapshot
from codex_plugin_scanner.guard.adapters.base import HarnessContext


def _fake(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake_native(kind: str, request: dict[str, object], guard_home: Path | None = None, **_: object) -> object:
        assert kind == "opencode_config_normalize"
        assert str(guard_home) == request["guard_home"]
        sent.append(json.loads(json.dumps(request)))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def _normalize(tmp_path: Path, payload: dict[str, object]) -> dict[str, object]:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    return snapshot._normalized_config_payload(
        payload,
        context=context,
        scope="global",
        config_path=tmp_path / "opencode.json",
    )


def test_the_config_travels_as_json_text_and_returns_parsed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _fake(monkeypatch, {"config": '{"mcp": {"srv": {"command": ["node"]}}, "x": NaN}'})

    normalized = _normalize(tmp_path, {"mcp": {"hol-guard::srv": {}}, "x": 1})

    assert sent == [
        {
            "config": '{"mcp": {"hol-guard::srv": {}}, "x": 1}',
            "scope": "global",
            "config_path": str(tmp_path / "opencode.json"),
            "guard_home": str(tmp_path / "guard"),
            "cwd": os.getcwd(),
        }
    ]
    assert list(normalized) == ["mcp", "x"]
    assert normalized["mcp"] == {"srv": {"command": ["node"]}}


@pytest.mark.parametrize(
    "answer",
    [
        authority.NativeRunnerAuthorityError("native runtime unavailable"),
        {"config": "[]"},
        {"config": "{"},
        {"config": 1},
        {"config": "{}", "extra": True},
    ],
)
def test_a_failed_or_malformed_answer_refuses_the_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(snapshot.OpenCodeInstallSnapshotError, match="Could not read the OpenCode config"):
        _normalize(tmp_path, {"mcp": {}})


def _refreshable(tmp_path: Path, payload: dict[str, object]) -> list[str]:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")
    return snapshot._refreshable_proxy_names(
        payload,
        context=context,
        scope="project",
        config_path=tmp_path / "opencode.json",
    )


def test_the_refresh_asks_for_the_refreshable_companions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _fake(monkeypatch, {"names": '["hol-guard::a", "hol-guard::b"]'})

    names = _refreshable(tmp_path, {"mcp": {"hol-guard::a": {}}})

    assert sent == [
        {
            "config": '{"mcp": {"hol-guard::a": {}}}',
            "scope": "project",
            "config_path": str(tmp_path / "opencode.json"),
            "guard_home": str(tmp_path / "guard"),
            "cwd": os.getcwd(),
            "op": "refreshable",
        }
    ]
    assert names == ["hol-guard::a", "hol-guard::b"]


@pytest.mark.parametrize(
    "answer",
    [
        authority.NativeRunnerAuthorityError("native runtime unavailable"),
        {"names": "{}"},
        {"names": "[1]"},
        {"names": "["},
        {"names": 1},
        {"names": "[]", "config": "{}"},
    ],
)
def test_a_failed_or_malformed_refresh_answer_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(snapshot.OpenCodeInstallSnapshotError, match="Could not read the OpenCode config"):
        _refreshable(tmp_path, {"mcp": {}})
