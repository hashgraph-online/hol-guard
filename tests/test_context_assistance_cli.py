from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context_assistance as native
from codex_plugin_scanner.guard.cli import commands_router
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_parser, add_guard_root_parser


def parser(nested: bool = False) -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    if nested:
        add_guard_parser(value.add_subparsers(dest="command"))
    else:
        add_guard_root_parser(value)
    return value


def state() -> dict[str, object]:
    return {
        "schema": "guard-context-assistance-status.v2",
        "availability": "off",
        "requested_enabled": False,
        "effective_enabled": False,
        "preferences": {},
        "effective_preferences": {},
        "restriction": None,
        "verification_permitted": True,
        "generation": "9007199254740993",
        "diagnostic": None,
        "runtime": None,
        "last_check": None,
        "qualification": None,
        "installation_options": None,
        "job": None,
    }


@pytest.mark.parametrize(
    ("name", "kind"),
    [("status", "status"), ("runtimes", "installations"), ("check", "recheck"), ("start", "activate"), ("off", "stop")],
)
@pytest.mark.parametrize("nested", [False, True])
def test_root_and_nested_cli_delegate_only_the_native_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    kind: str,
    nested: bool,
) -> None:
    calls = []

    def control(operation, *, guard_home, **kwargs):
        calls.append((operation, guard_home, kwargs))
        return state()

    def forbidden(*args, **kwargs):
        raise AssertionError("context status must not construct the general Guard store")

    monkeypatch.setattr(native, "control", control)
    monkeypatch.setattr(commands_router, "GuardStore", forbidden)
    args = parser(nested).parse_args(
        (["guard"] if nested else []) + ["context", "--guard-home", str(tmp_path), "--json", name]
    )
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 0
    assert calls == [(kind, tmp_path, {})]
    assert json.loads(output.getvalue()) == state()


def test_child_options_preserve_explicit_parent_guard_home(tmp_path: Path) -> None:
    args = parser().parse_args(["context", "--guard-home", str(tmp_path), "status", "--json"])
    assert args.guard_home == str(tmp_path)
    assert args.json is True


def test_public_hol_guard_entrypoint_reaches_the_context_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner import cli, install_integrity

    monkeypatch.setattr(sys, "argv", ["hol-guard"])
    monkeypatch.setattr(install_integrity, "warn_if_shadowed", lambda: None)
    monkeypatch.setattr(native, "control", lambda *args, **kwargs: state())
    assert cli.main(["context", "status", "--guard-home", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == state()


def test_native_failure_is_an_unavailable_result_without_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unavailable(*args, **kwargs):
        raise native.ContextAssistanceError("native_context_assistance_disabled")

    monkeypatch.setattr(native, "control", unavailable)
    args = parser().parse_args(["context", "start", "--guard-home", str(tmp_path), "--json"])
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 1
    result = json.loads(output.getvalue())
    assert result["status"] == "unavailable"
    assert result["code"] == "native_context_assistance_disabled"
    assert "effective_enabled" not in result, "failed transport must not invent native state"


def test_human_output_reports_pending_instead_of_claiming_activation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed = {
        **state(),
        "availability": "checking",
        "requested_enabled": True,
        "job": {"id": "3", "operation": "activate", "phase": "verifying"},
    }
    monkeypatch.setattr(native, "control", lambda *args, **kwargs: observed)
    args = parser().parse_args(["context", "start", "--guard-home", str(tmp_path)])
    output = io.StringIO()
    assert commands_router.run_guard_command(args, output_stream=output) == 0
    assert "checking" in output.getvalue()
    assert "Active: False" in output.getvalue()
    assert "CPython 3.14" in output.getvalue()


@pytest.mark.parametrize(
    "extra", [["enable"], ["start", "--python", "python3.14"], ["start", "--implementation", "cpython"]]
)
def test_cli_exposes_no_consent_or_runtime_facts_bypass(extra: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        parser().parse_args(["context", *extra])
    assert caught.value.code == 2


def test_parser_construction_never_imports_the_optional_control_transport() -> None:
    root = Path(__file__).resolve().parents[1]
    code = """
import argparse, sys
sys.path.insert(0, sys.argv[1])
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
add_guard_root_parser(argparse.ArgumentParser())
assert 'codex_plugin_scanner.guard.native_context_assistance' not in sys.modules
assert not any(name == 'cigar_sdk' or name.startswith('cigar_sdk.') for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root / "src")], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
