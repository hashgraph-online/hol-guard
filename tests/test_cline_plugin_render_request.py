"""The Cline plugin source is rendered natively from the values Python resolves."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import cline_plugin
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard")


def _capture(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    calls: list[tuple[str, dict[str, object]]] = []

    def authority(kind: str, args: dict[str, object], *, guard_home: Path | None = None) -> dict[str, object]:
        calls.append((kind, args))
        return answer

    monkeypatch.setattr(cline_plugin, "native_runner_authority", authority)
    return calls


def test_render_request_carries_the_cli_hook_and_state_paths(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    calls = _capture(monkeypatch, {"source": "// rendered\n"})

    assert cline_plugin._plugin_source(context, ["python", "guard"]) == "// rendered\n"

    proofs = context.guard_home / "managed" / "cline" / "proofs"
    assert calls == [
        (
            "cline_plugin_render",
            {
                "guard_cli": ["python", "guard"],
                "hook_argv": ["python", "guard", "--harness", "cline", "--json"],
                "adapter_state": str(context.guard_home / "managed" / "cline" / "adapter-state.json"),
                "proof_loaded": str(proofs / "plugin-loaded.json"),
                "proof_pretool": str(proofs / "plugin-pretool.json"),
                "proof_posttool": str(proofs / "plugin-posttool.json"),
            },
        )
    ]
    assert not context.guard_home.exists()


def test_bounded_hook_argv_replaces_the_default_hook(tmp_path: Path, monkeypatch) -> None:
    calls = _capture(monkeypatch, {"source": ""})

    cline_plugin._plugin_source(_context(tmp_path), ["python", "guard"], ["bridge", "--harness", "cline"])

    assert calls[0][1]["hook_argv"] == ["bridge", "--harness", "cline"]


def test_malformed_render_answer_is_refused(tmp_path: Path, monkeypatch) -> None:
    _capture(monkeypatch, {"source": None})

    with pytest.raises(RuntimeError, match="malformed"):
        cline_plugin._plugin_source(_context(tmp_path), ["python", "guard"])


def test_render_failure_is_a_runtime_error_the_install_can_fall_back_from(tmp_path: Path, monkeypatch) -> None:
    def authority(kind: str, args: dict[str, object], *, guard_home: Path | None = None) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(cline_plugin, "native_runner_authority", authority)

    with pytest.raises(RuntimeError, match="Cline plugin render failed: native_runner_authority_unavailable"):
        cline_plugin._plugin_source(_context(tmp_path), ["python", "guard"])
