"""File-only policy commands never create the user's Guard home, yet the resident still needs one to answer."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context
from codex_plugin_scanner.guard.cli import commands_dispatch_policy_dx as dx


@pytest.fixture(autouse=True)
def _unbound_home():
    # Earlier tests in the same worker may leave a home bound for ambient digest calls.
    token = native_context.bind_context_digest_home(None, remember=False)
    yield
    native_context.reset_context_digest_home(token)


def _record_bound_home(monkeypatch: pytest.MonkeyPatch) -> list[Path | None]:
    seen: list[Path | None] = []

    def dispatch(command, args, output_stream, input_text):
        bound = native_context._BOUND_GUARD_HOME.get()
        seen.append(bound)
        assert bound is None or bound.is_dir()
        return 0

    monkeypatch.setattr(dx, "_dispatch_policy_file_command", dispatch)
    return seen


def test_without_a_guard_home_file_commands_use_a_scratch_home_that_is_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / ".hol-guard"
    monkeypatch.setattr(dx, "_resolve_digest_home", lambda guard_home: missing)
    seen = _record_bound_home(monkeypatch)
    before = native_context.context_digest_guard_home()

    assert dx.run_policy_file_command(SimpleNamespace(policy_command="validate")) == 0

    assert len(seen) == 1 and seen[0] is not None
    assert not seen[0].exists()
    assert not missing.exists()
    assert native_context._BOUND_GUARD_HOME.get() is None
    assert native_context.context_digest_guard_home() == before


def test_an_existing_guard_home_answers_file_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / ".hol-guard"
    home.mkdir()
    monkeypatch.setattr(dx, "_resolve_digest_home", lambda guard_home: home)
    seen = _record_bound_home(monkeypatch)

    assert dx.run_policy_file_command(SimpleNamespace(policy_command="check")) == 0

    assert seen == [None]
