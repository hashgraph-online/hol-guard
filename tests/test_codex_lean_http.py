from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_lean_sessions as lean
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.daemon import codex_lean_http
from codex_plugin_scanner.guard.daemon import context_assistance_http as http


class _Handler:
    def __init__(self, guard_home: Path) -> None:
        self.server = SimpleNamespace(store=SimpleNamespace(guard_home=guard_home))
        self.calls: list[tuple[dict[str, object], int]] = []
        self.gate_errors: list[ApprovalGateError] = []

    def _write_json(self, data: dict[str, object], status: int = 200, extra_headers: object = None) -> None:
        assert extra_headers == {"Cache-Control": "no-store"}
        self.calls.append((data, status))

    def _write_approval_gate_error(self, error: ApprovalGateError) -> None:
        self.gate_errors.append(error)


@pytest.fixture
def homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home, guard = tmp_path / "home", tmp_path / "guard"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home, guard


@pytest.fixture
def approvals(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    seen: list[dict[str, object]] = []

    def high_risk(_home: Path, *, purpose: str, approval_gate_input: object) -> None:
        seen.append({"purpose": purpose, "input": approval_gate_input})

    monkeypatch.setattr(codex_lean_http, "require_high_risk", high_risk)
    monkeypatch.setattr(codex_lean_http, "require_settings_write", lambda *_args, **_kwargs: None)
    return seen


def test_the_route_reads_and_writes_through_the_dashboard_paths(
    homes: tuple[Path, Path], approvals: list[dict[str, object]]
) -> None:
    home, guard = homes
    assert http.READ_PATHS[codex_lean_http.PATH] == codex_lean_http.KIND
    assert http.WRITE_PATHS[codex_lean_http.PATH] == codex_lean_http.KIND
    handler = _Handler(guard)

    http.respond(handler, codex_lean_http.KIND)
    http.respond(handler, codex_lean_http.KIND, {"enabled": True})
    http.respond(handler, codex_lean_http.KIND, {"enabled": False})

    assert [(data["state"], status) for data, status in handler.calls] == [("off", 200), ("on", 200), ("off", 200)]
    assert [seen["purpose"] for seen in approvals] == ["settings_write", "settings_write"]
    assert lean.status(home, guard)["state"] == "off"


def test_a_write_without_a_true_or_false_changes_nothing(
    homes: tuple[Path, Path], approvals: list[dict[str, object]]
) -> None:
    home, guard = homes
    handler = _Handler(guard)

    http.respond(handler, codex_lean_http.KIND, {"enabled": "yes"})

    assert handler.calls == [({"error": "invalid_codex_lean_input"}, 400)]
    assert approvals == []
    assert not lean.config_path(home).exists()


def test_a_refused_approval_leaves_the_config_alone(homes: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    home, guard = homes
    refusal = ApprovalGateError("approval_gate_proof_required", "Approve this change.")

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise refusal

    monkeypatch.setattr(codex_lean_http, "require_high_risk", refuse)
    handler = _Handler(guard)

    http.respond(handler, codex_lean_http.KIND, {"enabled": True})

    assert handler.gate_errors == [refusal]
    assert handler.calls == []
    assert not lean.config_path(home).exists()


def test_an_unreadable_config_is_reported_not_overwritten(
    homes: tuple[Path, Path], approvals: list[dict[str, object]]
) -> None:
    home, guard = homes
    path = lean.config_path(home)
    path.parent.mkdir(parents=True)
    path.write_text("[broken\n", encoding="utf-8")
    handler = _Handler(guard)

    http.respond(handler, codex_lean_http.KIND, {"enabled": True})

    assert handler.calls == [({"error": "codex_lean_unavailable", "code": "codex_config_unreadable"}, 409)]
    assert path.read_text(encoding="utf-8") == "[broken\n"
