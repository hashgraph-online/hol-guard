import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.native_request_context import NativeRequestContextFailure
from codex_plugin_scanner.guard.runtime import restricted_pytest_validation as validation
from codex_plugin_scanner.guard.runtime.restricted_pytest import prepare_restricted_pytest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize(
    "reply",
    [
        None,
        {},
        {"value": True},
        {"value": [1]},
        {"value": ["python"], "extra": 1},
        {"reason_code": "allow", "message": "allowed"},
        NativeRequestContextFailure("native_request_context_unavailable"),
    ],
)
def test_unavailable_or_malformed_native_reply_cannot_prepare_execution(monkeypatch, reply):
    monkeypatch.setattr(transport, "_call", lambda *args, **kwargs: reply)
    with pytest.raises(RestrictedPytestError, match="execution was not started"):
        transport.restricted_native("normalized_command", {"command": ["python"]}, list)


def test_native_domain_refusal_keeps_reason_and_message(monkeypatch):
    monkeypatch.setattr(
        transport,
        "_call",
        lambda *args, **kwargs: {"reason_code": "pytest_restricted_invalid_command", "message": "Refused command."},
    )
    with pytest.raises(RestrictedPytestError, match="Refused command") as caught:
        transport.restricted_native("prepare", {}, dict)
    assert caught.value.reason_code == "pytest_restricted_invalid_command"


def test_transport_anchors_paths_and_forwards_caller_search_path(monkeypatch, tmp_path):
    observed = {}

    def call(action, **kwargs):
        observed.update(action)
        return {"value": ["pytest", "-q"]}

    monkeypatch.setattr(transport, "_call", call)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert transport.restricted_native("normalized_command", {"command": ["pytest", "-q"], "cwd": Path(".")}, list) == [
        "pytest",
        "-q",
    ]
    assert observed["body"]["input"]["cwd"] == str(Path.cwd())
    assert observed["body"]["input"]["search_path"] == str(tmp_path)


def test_native_preparation_is_one_call_with_no_python_verdict(monkeypatch, tmp_path):
    calls = []

    def call(action, **kwargs):
        calls.append(action)
        return {
            "value": {
                "profile_version": "pytest-readonly-v2",
                "backend": "macos-seatbelt",
                "backend_executable": "/usr/bin/true",
                "workspace": str(tmp_path),
                "cwd": str(tmp_path),
                "command": ["/usr/bin/python3", "-m", "pytest"],
                "executable": "/usr/bin/python3",
                "allowed_executables": ["/usr/bin/python3"],
                "denied_capabilities": ["network"],
            }
        }

    monkeypatch.setattr(transport, "_call", call)
    plan = prepare_restricted_pytest(["python3", "-m", "pytest"], workspace=tmp_path, read_only_workspace=True)
    assert plan.command == ("/usr/bin/python3", "-m", "pytest")
    assert len(calls) == 1
    assert calls[0]["body"]["operation"] == "prepare"
    assert "allow" not in calls[0]["body"]["input"]


@pytest.mark.skipif(os.name != "posix", reason="restricted execution uses Unix OS sandbox backends")
def test_real_native_preparation_preserves_validated_plan(native_context_digest, tmp_path):
    import sys

    workspace = Path.cwd()
    plan = prepare_restricted_pytest(
        [sys.executable, "-m", "pytest", "-q"],
        workspace=workspace,
        cwd=workspace,
        platform="darwin",
        backend_executable=Path("/usr/bin/true"),
    )
    assert plan.workspace == workspace.resolve()
    assert plan.command[1:] == ("-m", "pytest", "-q")
    assert "network" in plan.denied_capabilities


@pytest.mark.parametrize("failure", [OSError("unavailable"), ValueError("invalid"), RuntimeError("unavailable")])
def test_transport_exceptions_are_terminal_refusals(monkeypatch, failure):
    def call(*args, **kwargs):
        raise failure

    monkeypatch.setattr(transport, "_call", call)
    with pytest.raises(RestrictedPytestError, match="execution was not started"):
        transport.restricted_native("prepare", {}, dict)


def test_real_native_unsupported_backend_fails_closed(native_context_digest):
    with pytest.raises(RestrictedPytestError) as caught:
        transport.restricted_native("select_backend", {"platform": "win32", "backend_executable": None}, list)
    assert caught.value.reason_code == "pytest_restricted_sandbox_unavailable"


@pytest.mark.parametrize("wrapper", [validation._locate_executable, validation._resolve_executable])
@pytest.mark.parametrize("value", ["./node", "./git", "bin/python", "../bin/python"])
def test_executable_transport_preserves_explicit_relative_prefix(monkeypatch, tmp_path, wrapper, value):
    observed = {}

    def native(operation, fields, expected):
        observed.update(fields)
        return str(tmp_path / "tool")

    monkeypatch.setattr(validation, "restricted_native", native)
    assert wrapper(value, cwd=tmp_path) == tmp_path / "tool"
    assert observed["value"] == value


def test_prepare_expands_tilde_against_current_caller_home(monkeypatch, tmp_path):
    observed = {}

    def call(action, **kwargs):
        observed.update(action["body"]["input"])
        return {"value": {}}

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(transport, "_call", call)
    assert transport.restricted_native("prepare", {"command": ["~/bin/python", "-m", "pytest"]}, dict) == {}
    assert observed["command"] == [str(tmp_path / "bin/python"), "-m", "pytest"]
