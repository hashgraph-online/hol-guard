"""Node option discovery is bounded, private and cannot inherit host preloads."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import restricted_node_capabilities as capabilities
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    NODE_BUILD_OUTPUT_PROFILE_VERSION,
    NODE_TEST_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)


def _plan(root, backend="linux-bubblewrap"):
    return RestrictedPytestPlan(
        profile_version=NODE_BUILD_OUTPUT_PROFILE_VERSION,
        backend=backend,
        backend_executable=Path("/usr/bin/bwrap"),
        workspace=root,
        cwd=root,
        command=("/usr/bin/node", "script.mjs"),
        executable=Path("/usr/bin/node"),
        allowed_executables=(Path("/usr/bin/node"),),
        output_roots=(root / "dist",),
        denied_capabilities=("workspace-credential-read", "network"),
    )


@pytest.mark.parametrize(
    "help_text, supported",
    [
        (b"  --disable-wasm-trap-handler  use inline checks\n", True),
        (b"  --version  show version\n", False),
        (b"ordinary text mentions --disable-wasm-trap-handler\n", False),
        (b"  --disable-wasm-trap-handler-extra\n", False),
    ],
)
def test_fixed_supported_option_is_detected_under_the_readonly_boundary(monkeypatch, tmp_path, help_text, supported):
    plan = _plan(tmp_path)
    inspected = []
    authorized = []

    def backend(helper, *, private_root):
        assert helper.profile_version == NODE_TEST_READ_ONLY_PROFILE_VERSION
        assert helper.command == ("/usr/bin/node", "--help")
        assert helper.allowed_executables == plan.allowed_executables
        assert helper.output_roots == ()
        assert private_root.parent == tmp_path
        assert authorized == [helper.command]
        inspected.append(helper)
        return ["protected-help"]

    def execute(argv, *, env, timeout_seconds, cwd, stdout_capture):
        assert "NODE_OPTIONS" not in env and "NODE_PATH" not in env
        assert timeout_seconds == 10
        assert cwd == tmp_path
        stdout_capture.extend(help_text)
        return 0

    monkeypatch.setattr(capabilities, "_backend_argv", backend)
    monkeypatch.setattr(capabilities, "_run_backend_process", execute)
    result = capabilities.linux_node_environment(
        plan,
        private_root=tmp_path,
        environment={"NODE_OPTIONS": "--require malicious", "NODE_PATH": "/host"},
        timeout_seconds=60,
        authorize_capability=authorized.append,
    )
    assert result == ({"NODE_OPTIONS": "--disable-wasm-trap-handler"} if supported else {})
    assert len(inspected) == 1
    assert plan.command == ("/usr/bin/node", "script.mjs")


def test_unsupported_platform_does_not_probe_or_copy_host_node_options(monkeypatch, tmp_path):
    monkeypatch.setattr(capabilities, "_run_backend_process", lambda *args, **kwargs: pytest.fail("must not execute"))
    assert (
        capabilities.linux_node_environment(
            _plan(tmp_path, "macos-seatbelt"),
            private_root=tmp_path,
            environment={"NODE_OPTIONS": "--require malicious"},
            timeout_seconds=20,
        )
        == {}
    )


def test_failed_protected_help_cannot_fall_back_to_an_unprotected_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(capabilities, "_backend_argv", lambda *args, **kwargs: ["protected-help"])
    monkeypatch.setattr(capabilities, "_run_backend_process", lambda *args, **kwargs: 126)
    with pytest.raises(RestrictedPytestError, match="capability discovery"):
        capabilities.linux_node_environment(_plan(tmp_path), private_root=tmp_path, environment={}, timeout_seconds=20)


def test_capability_policy_deny_prevents_even_the_protected_probe(monkeypatch, tmp_path):
    monkeypatch.setattr(capabilities, "_backend_argv", lambda *args, **kwargs: pytest.fail("must not prepare"))

    def deny(argv):
        raise RestrictedPytestError("denied", "capability denied")

    with pytest.raises(RestrictedPytestError, match="capability denied"):
        capabilities.linux_node_environment(
            _plan(tmp_path),
            private_root=tmp_path,
            environment={},
            timeout_seconds=20,
            authorize_capability=deny,
        )
