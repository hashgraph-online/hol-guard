from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_lean_sessions as lean
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser

tomllib = lean.tomllib

USER_CONFIG = """# my Codex settings
model = "gpt-6-luna"  # keep this

[features]
hooks = true

[projects."/work/app"]
trust_level = "trusted"
"""


def homes(tmp_path: Path) -> tuple[Path, Path]:
    home, guard = tmp_path / "home", tmp_path / "guard"
    home.mkdir()
    return home, guard


def write_config(home: Path, text: str) -> Path:
    path = lean.config_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_on_adds_the_limit_and_keeps_the_users_file(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, USER_CONFIG)

    state = lean.enable(home, guard)

    assert state["state"] == "on"
    assert state["limit"] == lean.LIMIT
    text = path.read_text(encoding="utf-8")
    assert "# my Codex settings" in text
    assert 'model = "gpt-6-luna"  # keep this' in text
    parsed = tomllib.loads(text)
    assert parsed[lean.KEY] == lean.LIMIT
    assert parsed["features"] == {"hooks": True}
    assert parsed["projects"] == {"/work/app": {"trust_level": "trusted"}}
    assert lean.status(home, guard)["state"] == "on"


def test_off_removes_only_what_guard_wrote(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, USER_CONFIG)
    lean.enable(home, guard)

    state = lean.disable(home, guard)

    assert state["state"] == "off"
    assert tomllib.loads(path.read_text(encoding="utf-8")) == tomllib.loads(USER_CONFIG)
    assert "# my Codex settings" in path.read_text(encoding="utf-8")


def test_on_without_a_config_creates_one(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)

    assert lean.status(home, guard)["state"] == "off"
    lean.enable(home, guard)

    assert tomllib.loads(lean.config_path(home).read_text(encoding="utf-8")) == {lean.KEY: lean.LIMIT}


def test_a_limit_the_user_set_is_never_changed(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, f"{lean.KEY} = 80000\n" + USER_CONFIG)
    before = path.read_bytes()

    assert lean.enable(home, guard)["state"] == "yours"
    assert lean.disable(home, guard)["state"] == "yours"
    assert path.read_bytes() == before


def test_off_leaves_a_limit_the_user_changed_after_guard_set_it(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, USER_CONFIG)
    lean.enable(home, guard)
    path.write_text(path.read_text(encoding="utf-8").replace(str(lean.LIMIT), "45000"), encoding="utf-8")

    state = lean.disable(home, guard)

    assert state == {**state, "state": "yours", "limit": 45000}
    assert tomllib.loads(path.read_text(encoding="utf-8"))[lean.KEY] == 45000
    assert lean.status(home, guard)["state"] == "yours"


def test_a_config_guard_cannot_read_is_left_alone(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, "model = \n[broken\n")
    before = path.read_bytes()

    with pytest.raises(lean.LeanSessionsError) as raised:
        lean.enable(home, guard)

    assert raised.value.code == "codex_config_unreadable"
    assert path.read_bytes() == before


def test_codex_home_from_the_environment_is_the_config_changed(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    codex_home = tmp_path / "codex-home"
    environ = {"CODEX_HOME": str(codex_home)}

    state = lean.enable(home, guard, environ)

    assert state["config_path"] == str(codex_home / "config.toml")
    assert tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8")) == {lean.KEY: lean.LIMIT}
    assert not lean.config_path(home).exists()
    assert lean.disable(home, guard, environ)["state"] == "off"


def test_guards_value_in_one_codex_home_is_not_claimed_in_another(tmp_path: Path) -> None:
    home, guard = homes(tmp_path)
    environ = {"CODEX_HOME": str(tmp_path / "codex-home")}
    lean.enable(home, guard, environ)
    path = write_config(home, f"{lean.KEY} = {lean.LIMIT}\n")

    assert lean.status(home, guard)["state"] == "yours"
    assert lean.disable(home, guard)["state"] == "yours"
    assert tomllib.loads(path.read_text(encoding="utf-8")) == {lean.KEY: lean.LIMIT}
    assert lean.status(home, guard, environ)["state"] == "on"
    assert lean.disable(home, guard, environ)["state"] == "off"


def test_a_failed_config_write_leaves_no_ownership_record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, guard = homes(tmp_path)
    path = write_config(home, USER_CONFIG)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(lean, "_write_config", refuse)
    with pytest.raises(PermissionError):
        lean.enable(home, guard)

    assert lean._recorded(guard, path) is None
    assert path.read_text(encoding="utf-8") == USER_CONFIG


def test_an_interrupted_hook_install_stops_the_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import codex_hook_recovery
    from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError

    home, guard = homes(tmp_path)
    path = write_config(home, USER_CONFIG)

    def blocked(_home: Path) -> bool:
        raise CodexHookIntegrityError("codex_hook_recovery_config_conflict", "needs recovery")

    monkeypatch.setattr(codex_hook_recovery, "recover_hook_publication", blocked)
    with pytest.raises(lean.LeanSessionsError) as raised:
        lean.enable(home, guard)

    assert raised.value.code == "codex_hooks_need_recovery"
    assert path.read_text(encoding="utf-8") == USER_CONFIG
    assert lean._recorded(guard, path) is None


def run(argv: list[str], home: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, str]:
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setenv("USERPROFILE", str(home))
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    output = io.StringIO()
    code = commands_router.run_guard_command(parser.parse_args(argv), output_stream=output)
    return code, output.getvalue()


def test_cli_turns_lean_sessions_on_and_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, guard = homes(tmp_path)
    write_config(home, USER_CONFIG)

    code, text = run(["context", "lean", "on", "--guard-home", str(guard)], home, monkeypatch)
    assert code == 0
    assert "Lean Codex sessions: on" in text

    code, text = run(["context", "lean", "--guard-home", str(guard), "--json"], home, monkeypatch)
    assert code == 0
    assert json.loads(text)["state"] == "on"

    code, text = run(["context", "lean", "off", "--guard-home", str(guard)], home, monkeypatch)
    assert code == 0
    assert "Lean Codex sessions: off" in text


def test_cli_reports_an_unreadable_config_without_changing_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home, guard = homes(tmp_path)
    write_config(home, "[broken\n")

    code, text = run(["context", "lean", "on", "--guard-home", str(guard), "--json"], home, monkeypatch)

    assert code == 1
    assert json.loads(text)["code"] == "codex_config_unreadable"
