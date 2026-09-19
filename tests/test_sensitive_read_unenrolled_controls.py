"""Keep first-run sensitive Read review distinct from broken enrolled controls."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.sensitive_read_controls import sensitive_read_control_is_terminal
from codex_plugin_scanner.guard.store import GuardStore
from tests import native_sensitive_read_policy_vectors as vectors
from tests.native_managed_source_support import managed_store
from tests.test_native_sensitive_read_sources import produce_sensitive_read


def _source(tmp_path: Path, store: GuardStore) -> dict[str, object]:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return {
        "harness": "codex",
        "source": {
            "home_dir": str(home),
            "cwd": str(workspace),
            "guard_home": str(store.guard_home),
        },
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(workspace / ".npmrc")},
        },
    }


@pytest.mark.parametrize(
    ("risk", "expected"),
    [(None, "require-reapproval"), ("block", "block"), ("allow", "warn")],
)
def test_unenrolled_real_store_preserves_sensitive_read_policy(
    tmp_path: Path, risk: GuardAction | None, expected: GuardAction
) -> None:
    store = GuardStore(tmp_path / "guard")
    view = store.read_extension_control_authority_for_registry(REGISTRY)
    assert view.health is AuthorityHealth.UNENROLLED
    assert view.layers == ()
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    source = _source(tmp_path, store)
    with use_extension_control_snapshot(snapshot):
        artifact = produce_sensitive_read(source)
        result = vectors.evaluate_case(
            source,
            vectors.Configuration("unenrolled", default_action="warn", risk_action=risk),
            "enforce",
            store.guard_home,
        )
    evaluated = result["expected"]
    assert isinstance(evaluated, dict)
    assert evaluated["evaluatedPolicyAction"] == expected
    assert not sensitive_read_control_is_terminal(artifact.metadata)
    assert "extension_control_resolution" not in artifact.metadata
    # Merely reviewing a Read must not fabricate an enrolled authority.
    after = store.read_extension_control_authority_for_registry(REGISTRY)
    assert after.health is AuthorityHealth.UNENROLLED
    assert after.layers == ()


@pytest.mark.parametrize("lockdown", [False, True])
def test_real_protected_controls_preserve_sensitive_read_lockdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lockdown: bool
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=True, lockdown=lockdown)
    view = store.read_extension_control_authority_for_registry(REGISTRY)
    assert view.health is AuthorityHealth.PROTECTED
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    assert snapshot.authority_failure is None
    source = _source(tmp_path, store)

    # Retain the real enrolled store and its isolated instance-bound keyring.
    def same_store(guard_home: Path) -> GuardStore:
        assert guard_home == store.guard_home
        return store

    monkeypatch.setattr(vectors, "GuardStore", same_store)
    with use_extension_control_snapshot(snapshot):
        artifact = produce_sensitive_read(source)
        result = vectors.evaluate_case(
            source,
            vectors.Configuration("protected", default_action="warn"),
            "enforce",
            store.guard_home,
        )
    evaluated = result["expected"]
    assert isinstance(evaluated, dict)
    assert evaluated["evaluatedPolicyAction"] == ("block" if lockdown else "require-reapproval")
    assert sensitive_read_control_is_terminal(artifact.metadata) is lockdown
    if lockdown:
        resolution = artifact.metadata["extension_control_resolution"]
        assert isinstance(resolution, dict)
        assert resolution["blocked"] is True
        assert resolution["failures"] == []


@pytest.mark.parametrize(
    "health",
    [
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
        AuthorityHealth.DEGRADED_ACKNOWLEDGED,
        AuthorityHealth.TAMPERED,
        AuthorityHealth.RECOVERY_REQUIRED,
    ],
)
def test_enrolled_unhealthy_snapshots_remain_terminal_for_sensitive_reads(
    tmp_path: Path, health: AuthorityHealth
) -> None:
    store = GuardStore(tmp_path / "guard")
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(health, 1, REGISTRY.catalog_digest, ())
    )
    failure = snapshot.authority_failure
    assert failure is not None
    with use_extension_control_snapshot(snapshot):
        artifact = produce_sensitive_read(_source(tmp_path, store))
    assert sensitive_read_control_is_terminal(artifact.metadata)
    assert artifact.metadata["command_action_floor"] == "block"
    resolution = artifact.metadata["extension_control_resolution"]
    assert isinstance(resolution, dict)
    assert resolution["blocked"] is True
    assert resolution["failures"] == [failure.value]
