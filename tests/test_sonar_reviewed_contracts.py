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
from codex_plugin_scanner.guard.cli import commands_support_interaction as interaction
from codex_plugin_scanner.guard.daemon import client
from codex_plugin_scanner.guard.models import GUARD_ACTION_VALUES, GuardAction
from codex_plugin_scanner.guard.package_execution_context import PackageExecutionContext
from codex_plugin_scanner.guard.runtime import js_semver, runner
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


@pytest.mark.parametrize(
    "selector,version,expected",
    [
        ("*", "10.0.0", True),
        ("^*", "10.0.0", True),
        ("~*", "10.0.0", True),
        ("^1.2.3", "1.9.0", True),
        ("^1.2.3", "2.0.0", False),
        ("~1.2.3", "1.3.0", False),
    ],
)
def test_variable_comparator_counts_preserve_range_semantics(selector: str, version: str, expected: bool) -> None:
    assert js_semver.version_matches_js_selector(version, selector) is expected


@pytest.mark.parametrize("matches", [False, True])
def test_browser_wait_identity_branch_is_reachable(monkeypatch: pytest.MonkeyPatch, matches: bool) -> None:
    identity = {"pid": 42, "startToken": "fixture"}
    check = Mock(return_value=matches)
    monkeypatch.setattr(interaction, "process_identity_matches", check)
    result = interaction._codex_bridge_wait_process({interaction.CODEX_BROWSER_WAIT_PROCESS_KEY: identity})
    assert result is (identity if matches else None)
    check.assert_called_once_with(identity)


@pytest.mark.parametrize("payload", [None, {}, {interaction.CODEX_BROWSER_WAIT_PROCESS_KEY: "not-an-identity"}])
def test_browser_wait_rejects_missing_or_non_dict_identity(monkeypatch: pytest.MonkeyPatch, payload) -> None:
    check = Mock(side_effect=AssertionError("malformed identity reached matcher"))
    monkeypatch.setattr(interaction, "process_identity_matches", check)
    assert interaction._codex_bridge_wait_process(payload) is None
    check.assert_not_called()


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


@pytest.mark.parametrize("artifact_hash", [None, "", "  ", "unknown", "a" * 64])
def test_optional_package_hash_guard_rejects_only_invalid_hashes(artifact_hash: str | None) -> None:
    scope = package_request_portable_workspace_scope(
        artifact_id="guard-cli:project:package-request:fixture",
        artifact_type="package_request",
        artifact_hash=artifact_hash,
        execution_context=PackageExecutionContext("b" * 64, True, ()),
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
