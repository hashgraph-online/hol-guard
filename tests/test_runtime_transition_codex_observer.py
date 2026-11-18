from __future__ import annotations

import threading
import time
import uuid

import pytest

from codex_plugin_scanner.guard import runtime_transition_codex_observer as observer
from codex_plugin_scanner.guard.codex_harness_lifecycle import CodexHarnessAdapter
from codex_plugin_scanner.guard.harness.base import HarnessContext
from codex_plugin_scanner.guard.native_owned import codex_install_transaction
from codex_plugin_scanner.guard.native_process_stop_scope import native_process_stop_scope
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_hook_paths_support import hook_manifest_path
from tests.codex_legacy_roles import without_package_roles
from tests.command_activity_correlation_key_support import write_correlation_key
from tests.python_oracles.command_activity_correlation import (
    COMMAND_ACTIVITY_CORRELATION_KEY_FILE,
)


def installed_context(tmp_path):
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    home.mkdir()
    workspace.mkdir()
    context = HarnessContext(
        home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard", home_override_explicit=True
    )
    store = GuardStore(context.guard_home)
    CodexHarnessAdapter().install(context)
    return context, workspace, store


def _identity(tmp_path):
    return NativeRuntimeIdentity(tmp_path / "fixture-native", 1, 1, "d" * 64)


def observe(context, workspace, identity, deadline, receipt_store=None):
    config = context.home_dir / ".codex" / "config.toml"
    with codex_install_transaction(context.guard_home, config, actor="transition-probe", deadline=deadline):
        return observer.observe_configured_codex_hook(
            operation_id=str(uuid.uuid4()),
            artifact_generation="candidate",
            expected_runtime=identity,
            guard_home=context.guard_home,
            config_path=config,
            workspace=workspace,
            deadline_monotonic=deadline,
            receipt_store=receipt_store,
        )


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("no_store", "legacy_probe_store_unavailable"),
        ("missing_key", "legacy_probe_correlation_unavailable"),
        ("unsafe_key", "legacy_probe_correlation_unavailable"),
        ("malformed_key", "legacy_probe_correlation_invalid"),
    ],
)
def test_legacy_observer_refuses_unverified_state_before_any_launch(
    native_hook_force, tmp_path, monkeypatch, fault, reason
):
    # The receipt lookup, key-change and deadline faults need a launched hook; the native
    # op's Rust tests (``tests_publication_observe.rs``) cover them.
    with without_package_roles(monkeypatch, {"hook_probe", "native_receipt"}):
        context, workspace, store = installed_context(tmp_path)
    identity = NativeRuntimeIdentity(tmp_path / "fixture-native", 1, 1, "d" * 64)
    if fault != "missing_key" and fault != "no_store":
        write_correlation_key(context.guard_home)
    key_file = context.guard_home / COMMAND_ACTIVITY_CORRELATION_KEY_FILE
    if fault == "unsafe_key":
        key_file.chmod(0o644)
    elif fault == "malformed_key":
        key_file.write_text('{"invalid":"fixture"}')
    with pytest.raises(TransitionError, match=reason):
        observe(
            context,
            workspace,
            identity,
            time.monotonic() + 5,
            receipt_store=None if fault == "no_store" else store,
        )
    if fault == "missing_key":
        assert not key_file.exists()
    if fault == "unsafe_key":
        assert key_file.stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("fault", ["disabled", "argv", "missing_manifest", "expired"])
def test_invalid_configuration_never_launches_a_child(tmp_path, fault):
    context, workspace, _store = installed_context(tmp_path)
    config = context.home_dir / ".codex" / "config.toml"
    if fault == "disabled":
        config.write_text(config.read_text().replace("hooks = true", "hooks = false"))
    elif fault == "argv":
        config.write_text(config.read_text().replace("codex-hook-bridge", "foreign-bridge"))
    elif fault == "missing_manifest":
        hook_manifest_path(context.guard_home, config).unlink()
    deadline = time.monotonic() + (5 if fault != "expired" else -1)

    # Expiry is tested before acquiring the transaction so this exercises the
    # observer boundary rather than the installer lock's own deadline check.
    with (
        codex_install_transaction(context.guard_home, config, actor="transition-probe"),
        pytest.raises(TransitionError),
    ):
        observer.observe_configured_codex_hook(
            operation_id=str(uuid.uuid4()),
            artifact_generation="candidate",
            expected_runtime=_identity(tmp_path),
            guard_home=context.guard_home,
            config_path=config,
            workspace=workspace,
            deadline_monotonic=deadline,
        )


def test_a_set_stop_scope_refuses_before_the_native_observation_starts(tmp_path, monkeypatch):
    context, workspace, _store = installed_context(tmp_path)
    config = context.home_dir / ".codex" / "config.toml"
    calls = []
    monkeypatch.setattr(observer, "publication", lambda *args, **kwargs: calls.append(args))
    stop = threading.Event()
    stop.set()
    # The transaction is taken first: its own native call would be refused by a
    # set stop scope, and what is under test is the observation's refusal.
    with (
        codex_install_transaction(context.guard_home, config, actor="transition-probe"),
        native_process_stop_scope(stop),
        pytest.raises(TransitionError) as refused,
    ):
        observer.observe_configured_codex_hook(
            operation_id=str(uuid.uuid4()),
            artifact_generation="candidate",
            expected_runtime=_identity(tmp_path),
            guard_home=context.guard_home,
            config_path=config,
            workspace=workspace,
            deadline_monotonic=time.monotonic() + 5,
        )
    assert refused.value.reason == "admission_hook_launch_failed"
    assert calls == []
