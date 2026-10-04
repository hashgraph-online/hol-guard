"""Protected execution requires a private immutable request and fresh authority."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError


def payload() -> dict[str, object]:
    return {"hook_event_name": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "python3 -m pytest -q"}}


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only execution sink")
def test_private_request_snapshot_is_bound_to_bytes_and_workspace(tmp_path: Path) -> None:
    directory = tmp_path / "hol-guard-contained-test-example"
    directory.mkdir(mode=0o700)
    request = directory / "request.json"
    raw = json.dumps({"schema": "guard-contained-test-request.v1", "workspace": str(tmp_path), "payload": payload()})
    request.write_text(raw, encoding="utf-8")
    request.chmod(0o600)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    assert sink.read_contained_test_request(request, digest, workspace=tmp_path) == payload()
    with pytest.raises(RestrictedPytestError):
        sink.read_contained_test_request(request, "0" * 64, workspace=tmp_path)
    with pytest.raises(RestrictedPytestError):
        sink.read_contained_test_request(request, digest, workspace=tmp_path.parent)
    request.chmod(0o644)
    with pytest.raises(RestrictedPytestError):
        sink.read_contained_test_request(request, digest, workspace=tmp_path)
    request.chmod(0o600)
    real_file = directory / "moved.json"
    request.rename(real_file)
    request.symlink_to(real_file)
    with pytest.raises(RestrictedPytestError):
        sink.read_contained_test_request(request, digest, workspace=tmp_path)


def required_profile() -> dict[str, object]:
    return {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_pytest_readonly_containment_required",
        "required_execution_profile": "pytest-readonly-v2",
    }


def test_execution_authority_uses_the_prepared_test_working_directory(tmp_path, monkeypatch):
    import argparse

    from codex_plugin_scanner.guard.cli import commands_dispatch_local as cli
    from codex_plugin_scanner.guard.cli import commands_hook_native_authority as authority

    target = tmp_path / "selected"
    target.mkdir()
    calls = []
    original = {**payload(), "cwd": str(tmp_path)}
    monkeypatch.setattr(sink, "read_contained_test_request", lambda *args, **kwargs: original)
    monkeypatch.setattr(
        authority, "try_native_hook_authority", lambda **kwargs: calls.append(kwargs) or required_profile()
    )

    def execute(request, *, authorize, **kwargs):
        authorize(request)
        authorize({**request, "cwd": str(target)})
        return 0

    monkeypatch.setattr(sink, "run_authorized_contained_test", execute)
    args = argparse.Namespace(request_file="unused", request_sha256="unused", timeout_seconds=20, harness="omp")
    assert (
        cli._run_guard_execute_contained_test_command(
            args, guard_home=tmp_path, workspace=tmp_path, context=SimpleNamespace(home_dir=tmp_path), store=object()
        )
        == 0
    )
    assert [call["workspace"] for call in calls] == [tmp_path.resolve(), target.resolve()]


def test_snapshot_cannot_substitute_its_original_hook_working_directory(tmp_path):
    directory = tmp_path / "hol-guard-contained-test-cwd"
    directory.mkdir(mode=0o700)
    request = directory / "request.json"
    raw = json.dumps(
        {
            "schema": "guard-contained-test-request.v1",
            "workspace": str(tmp_path),
            "payload": {**payload(), "cwd": str(tmp_path.parent)},
        }
    ).encode()
    request.write_bytes(raw)
    request.chmod(0o600)
    with pytest.raises(RestrictedPytestError):
        sink.read_contained_test_request(request, hashlib.sha256(raw).hexdigest(), workspace=tmp_path)


def test_disappearing_execution_directory_rejects_cleanly(tmp_path, monkeypatch, capsys):
    import argparse

    from codex_plugin_scanner.guard.cli import commands_dispatch_local as cli

    original = {**payload(), "cwd": str(tmp_path)}
    monkeypatch.setattr(sink, "read_contained_test_request", lambda *args, **kwargs: original)

    def execute(request, *, authorize, **kwargs):
        authorize({**request, "cwd": str(tmp_path / "missing")})
        pytest.fail("missing directory must never execute")

    monkeypatch.setattr(sink, "run_authorized_contained_test", execute)
    args = argparse.Namespace(request_file="unused", request_sha256="unused", timeout_seconds=20, harness="omp")
    assert (
        cli._run_guard_execute_contained_test_command(
            args, guard_home=tmp_path, workspace=tmp_path, context=SimpleNamespace(home_dir=tmp_path), store=object()
        )
        == 126
    )
    assert "Execution directory is unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ("missing", "allow", "block", "review", "profile", "reason", "watch"))
def test_changed_or_missing_authority_never_starts_tests(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    executed = []
    monkeypatch.setattr(sink, "prepare_restricted_pytest", lambda *args, **kwargs: None)
    monkeypatch.setattr(sink, "run_restricted_pytest", lambda *args, **kwargs: executed.append(args))
    response = required_profile()
    if failure in {"allow", "block", "review"}:
        response["policy_action"] = failure
        response["decision"] = "allow" if failure == "allow" else "deny"
    elif failure == "profile":
        response["required_execution_profile"] = "pytest-restricted-v1"
    elif failure == "reason":
        response["reason_code"] = "native_policy_sandbox_required"
    elif failure == "watch":
        response["observe_mode"] = True
    with pytest.raises(RestrictedPytestError):
        sink.run_authorized_contained_test(
            payload(),
            workspace=tmp_path,
            timeout_seconds=20,
            authorize=lambda original: None if failure == "missing" else response,
        )
    assert executed == []


def test_authorized_original_input_runs_only_with_readonly_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = []
    monkeypatch.setattr(
        sink, "prepare_restricted_pytest", lambda *args, **kwargs: calls.append(("prepare", args, kwargs))
    )

    def authorize(original):
        assert original == payload()
        calls.append(("authorize", original))
        return required_profile()

    def execute(*args, **kwargs):
        calls.append(("execute", args, kwargs))
        assert args == (["python3", "-m", "pytest", "-q"],)
        assert kwargs["read_only_workspace"] is True
        assert kwargs["workspace"] == tmp_path
        return 0

    monkeypatch.setattr(sink, "run_restricted_pytest", execute)
    assert (
        sink.run_authorized_contained_test(payload(), workspace=tmp_path, timeout_seconds=20, authorize=authorize) == 0
    )
    assert [call[0] for call in calls] == ["prepare", "authorize", "execute"]


@pytest.mark.parametrize("fresh_profile", ["node-test-readonly-v1", "pytest-readonly-v2", "wrong"])
def test_node_requires_its_own_fresh_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fresh_profile: str
) -> None:
    from codex_plugin_scanner.guard.runtime import restricted_node_test as node

    executed = []
    monkeypatch.setattr(
        node,
        "prepare_restricted_node_test",
        lambda *args, **kwargs: SimpleNamespace(command=("/usr/bin/node", "--test", "tests/test.mjs")),
    )
    monkeypatch.setattr(node, "run_restricted_node_test", lambda *args, **kwargs: executed.append(args) or 0)
    original = payload()
    original["tool_input"] = {"command": "node --test tests/test.mjs"}
    response = required_profile()
    response["reason_code"] = "native_node_test_readonly_containment_required"
    response["required_execution_profile"] = fresh_profile
    if fresh_profile == "node-test-readonly-v1":
        assert (
            sink.run_authorized_contained_test(
                original, workspace=tmp_path, timeout_seconds=20, authorize=lambda value: response
            )
            == 0
        )
        assert executed == [(["node", "--test", "tests/test.mjs"],)]
    else:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                original, workspace=tmp_path, timeout_seconds=20, authorize=lambda value: response
            )
        assert executed == []
