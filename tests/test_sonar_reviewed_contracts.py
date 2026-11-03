"""Runtime counterexamples for reviewed static-analysis false positives."""

from __future__ import annotations

import math
from pathlib import Path
from typing import get_args
from unittest.mock import MagicMock, Mock

import pytest

from codex_plugin_scanner.ecosystems.kimi import _path_values
from codex_plugin_scanner.guard import action_lattice
from codex_plugin_scanner.guard.adapters.claude_hook_config import handler_identity
from codex_plugin_scanner.guard.approval_scope_support import package_request_portable_workspace_scope
from codex_plugin_scanner.guard.daemon import client
from codex_plugin_scanner.guard.models import GUARD_ACTION_VALUES, GuardAction, GuardArtifact
from codex_plugin_scanner.guard.package_execution_context import (
    PackageExecutionContext,
    build_package_execution_context,
)
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store_workflow_capability_secret_control import (
    StoreWorkflowCapabilitySecretControlMixin,
)


@pytest.mark.parametrize(
    "value,expected", [(None, ()), ("one", ("one",)), (["one", "two", 3, "three"], ("one", "two", "three"))]
)
def test_manifest_paths_are_a_variadic_collection(value, expected) -> None:
    assert _path_values(value) == expected


def test_handler_identity_is_a_hashable_tagged_key_not_an_unpacking_record() -> None:
    identities = {
        handler_identity({"type": "http", "url": "http://localhost/hook"}),
        handler_identity({"type": "command", "command": "guard", "args": []}),
        handler_identity({"type": "command", "command": "guard", "args": ["hook", "--json"]}),
        handler_identity({"type": "command", "command": "guard hook", "shell": "bash"}),
    }
    assert len(identities) == 4
    assert {len(identity) for identity in identities} == {2, 3, 5}


class _SecretControl(StoreWorkflowCapabilitySecretControlMixin):
    def __init__(self, available: bool, skip: bool) -> None:
        self.storage = Mock() if available else None
        self.skip = skip
        self.loaded = []

    @property
    def _policy_integrity_secret_store(self):
        return self.storage

    def _should_skip_policy_integrity_keychain_access(self, secret_store) -> bool:
        assert secret_store is self.storage
        return self.skip

    def _build_scoped_secret_ref(self, prefix: str) -> str:
        return "scope:" + prefix

    def _get_policy_integrity_secret_from_store(self, secret_id: str) -> str:
        self.loaded.append(secret_id)
        return "authenticated-control"


@pytest.mark.parametrize(
    "available,skip,expected", [(False, False, None), (True, True, None), (True, False, "authenticated-control")]
)
def test_secret_control_overrides_reach_the_real_credential_store(available: bool, skip: bool, expected) -> None:
    store = _SecretControl(available, skip)
    assert store._load_workflow_capability_control() == expected
    assert store.loaded == (["scope:guard-workflow-capability-control"] if expected else [])


def test_action_lattice_import_guard_is_false_for_consistent_declarations() -> None:
    declared = frozenset(action_lattice.GUARD_ACTION_LATTICE)
    assert declared == frozenset(GUARD_ACTION_VALUES)
    assert declared == frozenset(get_args(GuardAction))
    assert declared != frozenset((*GUARD_ACTION_VALUES, "unrecognized_future_action"))


def _portable_package_context(tmp_path: Path) -> PackageExecutionContext:
    """A context the resident accepts.

    The resident rebuilds the context digest from the components it is handed
    and drops any evidence that does not reproduce it, so a hand-written
    ``PackageExecutionContext`` never survives the trip.  This builds a real
    one the same way the package request path does.
    """

    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / ".git").mkdir()
    (workspace_dir / ".git" / "config").write_text('[remote "origin"]\nurl = https://example.test/app.git\n')
    (workspace_dir / "package.json").write_text('{"name":"sonar-contract"}\n')
    executable = tmp_path / "bin" / "npm"
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o755)
    (tmp_path / "home").mkdir()
    context = build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=GuardArtifact(
            artifact_id="guard-cli:project:package-request:fixture",
            name="npm install left-pad",
            harness="guard-cli",
            artifact_type="package_request",
            source_scope="project",
            config_path=str(workspace_dir / "hol-guard.toml"),
            metadata={
                "package_manager": "npm",
                "package_executable": "npm",
                "manifest_paths": ["package.json"],
                "lockfile_paths": [],
            },
        ),
        environment={"HOME": str(tmp_path / "home"), "PATH": str(executable.parent)},
    )
    assert context.portable is True
    return context


@pytest.mark.parametrize("artifact_hash", [None, "", "  ", "unknown", "a" * 64])
def test_optional_package_hash_guard_rejects_only_invalid_hashes(
    artifact_hash: str | None,
    tmp_path: Path,
    package_workspace_scope_native: Path,
) -> None:
    scope = package_request_portable_workspace_scope(
        artifact_id="guard-cli:project:package-request:fixture",
        artifact_type="package_request",
        artifact_hash=artifact_hash,
        execution_context=_portable_package_context(tmp_path),
    )
    if artifact_hash == "a" * 64:
        assert scope is not None and scope.startswith("package-request-workspace:v2:")
    else:
        assert scope is None


@pytest.mark.parametrize(
    "timeout,is_default",
    [(1.0, True), (math.nextafter(1.0, 0.0), False), (math.nextafter(1.0, 2.0), False), (0.25, False)],
)
def test_identity_timeout_default_is_exact_not_approximate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, timeout: float, is_default: bool
) -> None:
    loader = Mock(return_value=("http://127.0.0.1:5474", "fixture-token"))
    monkeypatch.setattr(client, "load_running_guard_daemon_identity", loader)
    client.load_running_guard_surface_daemon_client(tmp_path, identity_timeout=timeout)
    if is_default:
        loader.assert_called_once_with(tmp_path)
    else:
        loader.assert_called_once_with(tmp_path, health_timeout=timeout)


def test_route_probe_does_not_transmit_application_data(monkeypatch: pytest.MonkeyPatch) -> None:
    socket = MagicMock()
    socket.__enter__.return_value = socket
    socket.getsockname.return_value = ("10.0.0.2", 12345)
    monkeypatch.setattr(runner.socket, "socket", Mock(return_value=socket))
    assert runner._safe_private_ip() == "10.0.0.2"
    socket.send.assert_not_called()
    socket.sendto.assert_not_called()
    socket.sendall.assert_not_called()
