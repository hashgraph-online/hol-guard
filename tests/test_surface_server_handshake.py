"""The surface server handshake comes from the native runtime."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime.surface_server import GuardSurfaceRuntime
from codex_plugin_scanner.guard.schemas import surface_server
from codex_plugin_scanner.guard.store import GuardStore

_CONTRACT = {"schema_version": "guard-surface-server.v1", "methods": ["initialize"]}


def _initialize(tmp_path: Path, versions: tuple[str, ...]) -> dict[str, object]:
    return GuardSurfaceRuntime(GuardStore(tmp_path / "guard")).initialize_client(
        client_name="adapter",
        client_title=None,
        version="1.0.0",
        surface="cli",
        capabilities=("approvals",),
        supported_protocol_versions=versions,
        include_sessions=False,
    )


def test_initialize_returns_the_native_handshake(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def fake_authority(kind: str, args: dict[str, object]) -> dict[str, object]:
        calls.append((kind, args))
        return {"contract": _CONTRACT, "protocol": {"negotiated_version": "1.1"}, "negotiated_version": "1.1"}

    monkeypatch.setattr(surface_server, "native_runner_authority", fake_authority)

    payload = _initialize(tmp_path, ("1.0",))

    assert calls == [("surface_server_handshake", {"supported_protocol_versions": ["1.0"]})]
    assert payload["protocol_version"] == "1.1"
    assert payload["schema_version"] == "guard-surface-server.v1"
    assert payload["schema"] == _CONTRACT
    assert payload["protocol"] == {"negotiated_version": "1.1"}


def test_initialize_refuses_a_version_the_runtime_could_not_negotiate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fake_authority(_kind: str, _args: dict[str, object]) -> dict[str, object]:
        return {"contract": _CONTRACT, "protocol": {"negotiated_version": None}, "negotiated_version": None}

    monkeypatch.setattr(surface_server, "native_runner_authority", fake_authority)

    with pytest.raises(ValueError, match="unsupported_protocol_version"):
        _ = _initialize(tmp_path, ("99.0",))


def test_the_contract_fails_closed_without_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(_kind: str, _args: dict[str, object]) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(surface_server, "native_runner_authority", unavailable)

    with pytest.raises(RuntimeError, match="surface server contract"):
        _ = surface_server.build_surface_server_contract()
