from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.harness_context import HarnessContext


def _install(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: Exception,
    *,
    as_json: bool,
    output_stream: io.StringIO | None = None,
) -> int:
    def refuse(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise error

    monkeypatch.setattr(dispatch, "repair_native_runtime_if_missing", lambda **_kwargs: None)
    monkeypatch.setattr(dispatch, "_migrate_legacy_macos_secrets", lambda _store: None)
    monkeypatch.setattr(dispatch, "apply_managed_install", refuse)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=tmp_path / "guard")
    args = SimpleNamespace(dry_run=False, harness="codex", all=False, json=as_json)
    return dispatch._run_guard_install_command(  # type: ignore[arg-type]
        args, context=context, store=object(), output_stream=output_stream
    )


def test_json_install_reports_a_runtime_refusal_on_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    error = CodexHookIntegrityError("codex_hook_publication_pending", "Codex hook publication must be recovered.")

    assert _install(monkeypatch, tmp_path, error, as_json=True) == 1

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "status": "failed",
        "message": "Codex hook publication must be recovered.",
        "error": "codex_hook_publication_pending",
    }
    assert "must be recovered" in captured.err


def test_json_install_reports_an_invalid_request_on_stdout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _install(monkeypatch, tmp_path, ValueError("unknown harness"), as_json=True) == 2

    assert json.loads(capsys.readouterr().out) == {"status": "failed", "message": "unknown harness"}


def test_text_install_keeps_raising_runtime_refusals(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    error = CodexHookIntegrityError("codex_hook_publication_pending", "refused")

    with pytest.raises(CodexHookIntegrityError):
        _install(monkeypatch, tmp_path, error, as_json=False)


@pytest.mark.parametrize(
    ("error", "exit_code"),
    [(ValueError("unknown harness"), 2), (CodexHookIntegrityError("codex_hook_publication_pending", "refused"), 1)],
)
def test_json_install_failure_goes_to_the_supplied_stream(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
    exit_code: int,
) -> None:
    stream = io.StringIO()

    assert _install(monkeypatch, tmp_path, error, as_json=True, output_stream=stream) == exit_code

    assert json.loads(stream.getvalue())["status"] == "failed"
    assert capsys.readouterr().out == ""
