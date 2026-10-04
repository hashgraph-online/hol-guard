"""The native heap-option contract survives preparation and protected dispatch."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_node_test as node_test
from codex_plugin_scanner.guard.runtime import restricted_vitest as vitest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize("kind", ["eval", "test", "vitest"])
@pytest.mark.parametrize("blocked", [False, True])
def test_heap_option_reaches_prepared_sink_only_after_native_authorization(tmp_path, monkeypatch, kind, blocked):
    (tmp_path / "package.json").write_text("{}")
    node = tmp_path / "node"
    node.write_bytes(b"\x7fELF" + b"fixture-not-executed")
    node.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(node_test, "_select_backend", lambda **kwargs: ("macos-seatbelt", Path("/sandbox-exec")))
    entry = tmp_path / "node_modules/vitest/vitest.mjs"
    entry.parent.mkdir(parents=True)
    entry.write_text("// validated entrypoint fixture\n")
    (entry.parent / "package.json").write_text(json.dumps({"name": "vitest", "version": "4.1.11"}))
    suffix = {"eval": ["-e", "console.log(1)"], "test": ["--test", "test.mjs"], "vitest": [str(entry), "run"]}[kind]
    argv = [str(node), "--max-old-space-size=4096", *suffix]
    profile = {"eval": "node-eval-readonly-v1", "test": "node-test-readonly-v1", "vitest": "vitest-readonly-v1"}[kind]
    reason = {
        "eval": "native_node_eval_readonly_containment_required",
        "test": "native_node_test_readonly_containment_required",
        "vitest": "native_vitest_readonly_containment_required",
    }[kind]
    checked, executed = [], []

    def authorize(payload):
        checked.append(shlex.split(payload["tool_input"]["command"]))
        return {
            "decision": "deny",
            "policy_action": "block" if blocked and len(checked) == 2 else "sandbox-required",
            "reason_code": reason,
            "required_execution_profile": profile,
        }

    def run_plan(plan, **kwargs):
        assert plan.profile_version == profile
        assert list(plan.command[: len(argv)]) == argv
        executed.append(plan)
        return 0

    def run_prepared(command, *, prepared_plan, **kwargs):
        return run_plan(prepared_plan)

    monkeypatch.setattr(sink, "run_restricted_inline_eval", run_plan)
    monkeypatch.setattr(node_test, "run_restricted_node_test", run_prepared)
    monkeypatch.setattr(vitest, "run_restricted_vitest", run_prepared)
    payload: dict[str, object] = {
        "tool_name": "bash",
        "cwd": str(tmp_path),
        "tool_input": {"command": shlex.join(argv)},
    }
    if blocked:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
        assert executed == []
    else:
        assert (
            sink.run_authorized_contained_test(payload, workspace=tmp_path, authorize=authorize, timeout_seconds=20)
            == 0
        )
        assert len(executed) == 1
    assert len(checked) == 2
    assert all(args[1] == "--max-old-space-size=4096" for args in checked)
