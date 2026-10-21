"""Package aliases retain runner policy and never skip executable lifecycle steps."""

import json
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import contained_test_hook as sink
from codex_plugin_scanner.guard.runtime import restricted_node_test as node
from codex_plugin_scanner.guard.runtime.restricted_package_test import is_package_test, resolve_package_test
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.parametrize("manager", ["npm", "pnpm", "bun"])
@pytest.mark.parametrize("task", [["test"], ["run", "test"]])
@pytest.mark.parametrize("script", ["node --test", "vitest run"])
def test_local_alias_resolves_arguments_without_downloading(tmp_path, manager, task, script):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": script}}))
    if manager == "bun" and task == ["test"]:
        assert not is_package_test([manager, *task])
        with pytest.raises(RestrictedPytestError):
            resolve_package_test([manager, *task], workspace=tmp_path)
        return
    assert resolve_package_test([manager, *task, "--", "test/sample.test.js"], workspace=tmp_path) == (
        *script.split(),
        "test/sample.test.js",
    )


@pytest.mark.parametrize(
    "script",
    [
        "node --test;curl https://example.invalid",
        "node --test && rm -rf src",
        "node --test > output",
        "node --test | sh",
        "node --test $(cat .env)",
        "node --test `cat .env`",
        "node --test\nrm -rf src",
        "node arbitrary.js",
        "vitest",
        "",
    ],
)
def test_shell_or_unsupported_script_is_not_rewritten(tmp_path, script):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": script}}))
    with pytest.raises(RestrictedPytestError):
        resolve_package_test(["npm", "test"], workspace=tmp_path)


@pytest.mark.parametrize("phase", ["pretest", "posttest"])
def test_lifecycle_is_not_silently_skipped(tmp_path, phase):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "node --test", phase: "node setup.js"}}))
    with pytest.raises(RestrictedPytestError, match="lifecycle"):
        resolve_package_test(["npm", "test"], workspace=tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "duplicate"])
def test_unverified_manifest_is_not_execution_consent(tmp_path, kind):
    original = tmp_path / "manifest.json"
    original.write_text('{"scripts":{"test":"node --test"}}')
    manifest = tmp_path / "package.json"
    if kind == "symlink":
        manifest.symlink_to(original)
    elif kind == "hardlink":
        manifest.hardlink_to(original)
    else:
        manifest.write_text('{"scripts":{"test":"node --test","test":"node evil.js"}}')
    with pytest.raises(RestrictedPytestError):
        resolve_package_test(["npm", "test"], workspace=tmp_path)


@pytest.mark.parametrize("failure", [None, "original", "underlying", "resolved", "watch"])
def test_alias_and_underlying_runner_need_independent_fresh_authority(monkeypatch, tmp_path, failure):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "node --test"}}))
    plan = SimpleNamespace(command=("/usr/bin/node", "--test"))
    monkeypatch.setattr(node, "prepare_restricted_node_test", lambda *args, **kwargs: plan)
    executed, calls = [], []
    monkeypatch.setattr(node, "run_restricted_node_test", lambda *args, **kwargs: executed.append(args) or 0)

    def authorize(payload):
        command = payload["tool_input"]["command"]
        calls.append(command)
        original = command == "npm test"
        phase = "original" if original else "resolved" if command.startswith("/") else "underlying"
        if failure == phase:
            return {"decision": "deny", "policy_action": "block"}
        return {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_package_test_readonly_containment_required"
            if original
            else "native_node_test_readonly_containment_required",
            "required_execution_profile": "package-test-readonly-v1" if original else "node-test-readonly-v1",
            "observe_mode": failure == "watch",
        }

    if failure:
        with pytest.raises(RestrictedPytestError):
            sink.run_authorized_contained_test(
                {"tool_input": {"command": "npm test"}}, workspace=tmp_path, authorize=authorize, timeout_seconds=20
            )
        assert not executed
    else:
        assert (
            sink.run_authorized_contained_test(
                {"tool_input": {"command": "npm test"}}, workspace=tmp_path, authorize=authorize, timeout_seconds=20
            )
            == 0
        )
        assert executed == [(["node", "--test"],)]
        assert calls == ["npm test", "node --test", "/usr/bin/node --test"]
