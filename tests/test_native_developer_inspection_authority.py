"""Hosted transport regressions for native whole-command developer proofs."""

import pickle
from dataclasses import asdict
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_developer_inspection_authority as native
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.runtime.secret_file_request_services import developer_inspection, source_edit_context


@pytest.fixture
def bridge(monkeypatch):
    calls = []
    response = {"value": None}

    def answer(kind, request, home):
        calls.append((kind, request, home))
        return response

    monkeypatch.setattr(native, "native_runner_authority", answer)
    monkeypatch.setattr(native, "_facts", lambda cwd, home: {"cwd": str(cwd), "home_dir": str(home)})
    monkeypatch.setattr(native, "_environment_snapshot", lambda: {"RIPGREP_CONFIG_PATH": "synthetic-config"})
    monkeypatch.setattr(native.native_git_execution_safety, "_process_groups", lambda: [])
    monkeypatch.setattr(native.native_git_execution_safety, "_account_home_directory", lambda: None)
    monkeypatch.setattr(native, "_resolve_digest_home", lambda _: Path("/guard"))
    return calls, response


def test_whole_command_composes_existing_services_once(bridge):
    calls, _ = bridge
    assert (
        source_edit_context.low_risk_compound_developer_execution_context(
            "cd /workspace && rg needle .", cwd=Path("/workspace"), home_dir=Path("/home")
        )
        is None
    )
    assert len(calls) == 1
    kind, request, _ = calls[0]
    assert kind == "developer_inspection_authority"
    assert request["entry"] == "low_risk_compound_developer_execution_context"
    assert request["direct_facts"] == {"cwd": "/workspace", "home_dir": "/home"}
    assert request["facts"]["environment"]["RIPGREP_CONFIG_PATH"] == "synthetic-config"


def test_graph_observation_is_presented_from_native_authority(bridge):
    calls, response = bridge
    response["value"] = {
        "context": {
            "context": {
                "command_text": "rg needle .",
                "initial_cwd": "/workspace",
                "workspace_root": "/workspace",
                "workspace_identity": None,
                "segments": [],
                "complete": True,
                "reason_code": None,
                "directory_change_present": False,
            },
            "context_hash": "a" * 64,
            "segment_hashes": [],
            "metadata": {},
        },
        "segments": [{"index": 0, "command_name": "gh", "effect": "remote-read"}],
        "has_observation": False,
    }
    graph = developer_inspection._compound_developer_effect_graph("rg needle .", home_dir=Path("/home"))
    assert graph is not None
    assert graph.has_observation is False
    assert graph.context.native is not None
    assert len(calls) == 1
    assert set(asdict(graph)) == {"context", "segments"}
    assert pickle.loads(pickle.dumps(graph)) == graph


def test_filesystem_proofs_are_never_cached(bridge):
    calls, _ = bridge
    for _ in range(2):
        source_edit_context._bounded_verified_source_edit_execution_context(
            "cd /workspace && sed -i '' s/a/b/ app.py && cat app.py", home_dir=Path("/home")
        )
    assert len(calls) == 2


def test_native_failure_never_recomputes_a_python_verdict(bridge, monkeypatch):
    def refuse(*args, **kwargs):
        raise NativeRunnerAuthorityError("native_developer_inspection_unavailable")

    monkeypatch.setattr(native, "native_runner_authority", refuse)
    with pytest.raises(NativeRunnerAuthorityError):
        developer_inspection._static_shell_segment_is_safe(["literal"])
