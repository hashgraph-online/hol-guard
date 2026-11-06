"""Bound transport failures and original-vector replay through the resident client."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_execution
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from tests import native_shell_helpers_client as native_shell_helpers
from tests.shell_data_flow_test_support import (
    native_command_segments,
    native_input_redirects,
    native_pipes,
)
from tests.shell_wrapper_test_support import native_shell_normalization


def _masked(action: str, command: str, heredocs: list[dict[str, object]]) -> str:
    spans = [(h["operator_start"], h["declaration_end"], h["body_start"], h["end"]) for h in heredocs]
    return native_shell_helpers.call(action, command, spans=spans)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "request_id",
        "request_sha256",
        "schema",
        "status",
        "code",
        "code_object",
        "extra",
        "wrong_type",
        "bool_index",
    ],
)
def test_transport_rejects_unbound_or_malformed_answers(monkeypatch, tmp_path, fault):
    from codex_plugin_scanner.guard import native_context

    monkeypatch.setattr(native_context, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_context, "_native_runtime_status_memo", lambda: None)

    def reply(**kwargs):
        request = kwargs["request"]
        result = {
            "schema": "guard-shell-helpers-result.v1",
            "request_id": request["request_id"],
            "request_sha256": _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "result": ["echo"],
        }
        if fault == "missing":
            return None
        if fault == "extra":
            result["extra"] = True
        elif fault == "wrong_type":
            result["result"] = [False]
        elif fault == "bool_index":
            result["result"] = [[True, 1, None, 0, False, True]]
        elif fault == "code_object":
            result["code"] = {}
        else:
            result[fault] = "invalid"
        return result

    monkeypatch.setattr(native_execution, "_resident_request", reply)
    with pytest.raises(native_shell_helpers.NativeShellHelpersError):
        native_shell_helpers.call("trace" if fault == "bool_index" else "segments", "echo")


def test_unrepresentable_wire_claims_never_reach_or_fault_the_resident(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_context

    monkeypatch.setattr(native_context, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_context, "_native_runtime_status_memo", lambda: None)
    sent = []
    monkeypatch.setattr(native_execution, "_resident_request", lambda **kwargs: sent.append(kwargs))
    with pytest.raises(native_shell_helpers.NativeShellHelpersError, match="shell_helpers_invalid"):
        native_shell_helpers.call("segments", "\ud800")
    with pytest.raises(native_shell_helpers.NativeShellHelpersError, match="shell_helpers_request_bounds"):
        native_shell_helpers.call("segments", "x" * (6 * 1024 * 1024))
    assert sent == []


def test_bad_binding_records_failures_without_success_resets(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_context

    failed, successful = [], []
    monkeypatch.setattr(native_context, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(
        native_context,
        "_native_runtime_status_memo",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64)),
    )
    monkeypatch.setattr(native_execution, "native_record_resident_failure", lambda *a, **kw: failed.append(kw))
    monkeypatch.setattr(native_execution, "native_record_resident_success", lambda *a, **kw: successful.append(kw))

    def bad_reply(**kwargs):
        assert kwargs["record_success"] is False
        return {
            "schema": "guard-shell-helpers-result.v1",
            "request_id": kwargs["request"]["request_id"],
            "request_sha256": "b" * 64,
            "status": "ok",
            "code": "ok",
            "result": ["echo"],
        }

    monkeypatch.setattr(native_execution, "_resident_request", bad_reply)
    for _ in range(3):
        with pytest.raises(native_shell_helpers.NativeShellHelpersError, match="binding"):
            native_shell_helpers.call("segments", "echo")
    assert len(failed) == 3
    assert successful == []


@pytest.mark.parametrize("code", ["shell_helpers_deadline", "shell_helpers_response_bounds"])
def test_native_budget_failures_record_faults_without_health_resets(monkeypatch, tmp_path, code):
    from codex_plugin_scanner.guard import native_context

    failures, successes = [], []
    monkeypatch.setattr(native_context, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(
        native_context,
        "_native_runtime_status_memo",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="a" * 64)),
    )
    monkeypatch.setattr(
        native_execution, "native_record_resident_failure", lambda *a, **kw: failures.append(kw["reason"])
    )
    monkeypatch.setattr(native_execution, "native_record_resident_success", lambda *a, **kw: successes.append(True))

    def reply(**kwargs):
        assert 0 < kwargs["request"]["timeout_ms"] <= 8000
        assert 0 < kwargs["timeout_seconds"] <= 8
        return {
            "schema": "guard-shell-helpers-result.v1",
            "request_id": kwargs["request"]["request_id"],
            "request_sha256": _canonical_request_sha256(kwargs["request"]),
            "status": "ok",
            "code": code,
            "result": None,
        }

    monkeypatch.setattr(native_execution, "_resident_request", reply)
    with pytest.raises(native_shell_helpers.NativeShellHelpersError, match=code):
        native_shell_helpers.call("segments", "echo hi")
    assert failures == ["native_" + code]
    assert successes == []


def test_public_helpers_replay_original_python_vectors(native_hook_force, monkeypatch, tmp_path):
    monkeypatch.setenv("HOL_GUARD_HOME", str(tmp_path / "guard"))
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    for vector in (fixture["vectors"][i] for i in (5, 8, 9, 13)):
        command, expected = vector["command"], vector["expected"]
        heredocs = native_shell_helpers.call("heredocs", command)
        assert list(native_command_segments(command)) == expected["segments"]
        assert list(native_input_redirects(command)) == expected["redirects"]
        assert [asdict(p) for p in native_pipes(command)] == expected["pipes"]
        assert heredocs == expected["heredocs"]
        assert native_shell_helpers.call("substitutions", command) == expected["substitutions"]
        assert _masked("masked_complete", command, heredocs) == expected["masked_complete"]
        result = asdict(native_shell_normalization(command))
        result["wrapper_chain"] = list(result["wrapper_chain"])
        assert result == expected["normalization"]


def test_fresh_process_provisions_resident_before_public_helper(native_hook_force, tmp_path):
    environment = os.environ.copy()
    environment["SHELL_HELPER_TEST_HOME"] = str(tmp_path / "fresh-guard")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os
from pathlib import Path
from codex_plugin_scanner.guard.native_context import bind_context_digest_home
from tests.native_shell_helpers_client import call
bind_context_digest_home(Path(os.environ["SHELL_HELPER_TEST_HOME"]))
result = call("normalization", "bash --init-file /dev/null -c 'echo value'", cwd=None, home_dir=None)
assert result["normalized_command"] == "echo value"
assert result["wrapper_chain"] == ["bash"]
""",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_large_escaped_heredoc_replays_across_resident_wire(native_hook_force):
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    vector = next(v for v in fixture["vectors"] if len(v["command"]) > 65_536 and "\u001c" in v["command"])
    command, expected = vector["command"], vector["expected"]
    heredocs = native_shell_helpers.call("heredocs", command)
    assert heredocs == expected["heredocs"]
    assert _masked("masked_bodies", command, heredocs) == expected["masked_bodies"]
    assert _masked("masked_complete", command, heredocs) == expected["masked_complete"]


def test_prerequisite_time_consumes_the_same_transport_deadline(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_context

    ticks = iter((0.0, 11.0))
    monkeypatch.setattr(native_shell_helpers, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(native_context, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(native_context, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(native_context, "_native_runtime_status_memo", lambda: None)
    with pytest.raises(native_shell_helpers.NativeShellHelpersError, match="deadline"):
        native_shell_helpers.call("segments", "echo value")


def test_dense_heredocs_replay_across_native_pages_and_masking_wire(native_hook_force):
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    vector = next(v for v in fixture["vectors"] if v["command"].startswith(":<<E\nE\n"))
    command, expected = vector["command"], vector["expected"]
    heredocs = native_shell_helpers.call("heredocs", command)
    assert heredocs == expected["heredocs"]
    assert _masked("masked_bodies", command, heredocs) == expected["masked_bodies"]
    assert _masked("masked_complete", command, heredocs) == expected["masked_complete"]


def test_rejected_inputs_do_not_poison_shared_native_health(native_hook_force, monkeypatch):
    failures = []
    monkeypatch.setattr(
        native_execution, "native_record_resident_failure", lambda *args, **kwargs: failures.append(kwargs)
    )
    for _ in range(3):
        with pytest.raises(native_shell_helpers.NativeShellHelpersError, match="shell_helpers_invalid"):
            native_shell_helpers.call("masked_bodies", "echo", heredocs=[{}])
    text = "x" * 1_500_000
    assert native_shell_helpers.call("normalization", text)["normalized_command"] == text
    assert native_command_segments("echo healthy") == ("echo healthy",)
    assert failures == []


def test_large_heredoc_and_mask_results_replay_across_byte_pages(native_hook_force):
    fixture = json.loads((Path(__file__).parent / "fixtures/shell-helper-python.v1.json").read_text())
    vector = next(v for v in fixture["vectors"] if len(v["command"]) > 2_000_000)
    command, expected = vector["command"], vector["expected"]
    heredocs = native_shell_helpers.call("heredocs", command)
    assert heredocs == expected["heredocs"]
    assert _masked("masked_bodies", command, heredocs) == expected["masked_bodies"]
    assert _masked("masked_complete", command, heredocs) == expected["masked_complete"]
