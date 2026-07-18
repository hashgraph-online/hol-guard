from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import lifecycle
from codex_plugin_scanner.guard.mdm.contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
)


def _machine_paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", None, root / "logs", root / "manifest")


def _managed_policy() -> ManagedPolicyState:
    policy = ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings={},
        locked_settings=frozenset(),
        required_harnesses=("codex",),
        update=ManagedUpdatePolicy(owner="mdm"),
    )
    return ManagedPolicyState("active", "native", policy, reason_code="managed_policy_active")


def test_managed_activation_registers_aggregate_harness_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installs = [{"active": True, "harness": "codex", "manifest": {"config_path": str(tmp_path / "config")}}]
    registrations: list[tuple[Path, Path, list[dict[str, object]]]] = []

    class FakeStore:
        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return installs

    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", lambda *_args, **_kwargs: {"managed_installs": installs})
    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(lifecycle, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(
        lifecycle,
        "register_user_harnesses",
        lambda machine_paths, home, active: registrations.append((machine_paths, home, active)),
    )

    lifecycle.activate_user(tmp_path, "developer")

    assert registrations == [(paths, tmp_path, installs)]


def test_partial_activation_rolls_back_new_harnesses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True}] if self.active else []

    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        if command == "install":
            FakeStore.active = True
            raise RuntimeError("interrupted")
        FakeStore.active = False
        return {}

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)

    with pytest.raises(RuntimeError, match="interrupted"):
        lifecycle.activate_user(tmp_path, "developer")

    assert commands == ["install", "uninstall"]
    assert FakeStore.active is False


def test_managed_activation_rolls_back_when_machine_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True, "manifest": {}}] if self.active else []

    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        FakeStore.active = command == "install"
        return {}

    def fail_registration(*_args: object) -> None:
        raise OSError("machine registry unavailable")

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(lifecycle, "register_user_harnesses", fail_registration)

    with pytest.raises(OSError, match="machine registry unavailable"):
        lifecycle.activate_user(tmp_path, "developer")

    assert commands == ["install", "uninstall"]
    assert FakeStore.active is False
