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


def _write_activation_marker(home: Path) -> None:
    guard_home = home / ".hol-guard"
    guard_home.mkdir(exist_ok=True)
    marker = guard_home / "mdm-activation.json"
    marker.write_text("{}")
    marker.chmod(0o600)


def test_user_activation_never_mutates_machine_harness_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installs = [{"active": True, "harness": "codex", "manifest": {"config_path": str(tmp_path / "config")}}]

    class FakeStore:
        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return installs

        def reconcile_managed_policy_bundle_keyring_state(self, **_kwargs: object) -> bool:
            return False

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", lambda *_args, **_kwargs: {"managed_installs": installs})
    monkeypatch.setattr(
        lifecycle,
        "register_user_harnesses",
        lambda *_args: pytest.fail("user activation attempted a privileged registry mutation"),
    )

    lifecycle.activate_user(tmp_path, "developer")

    assert (tmp_path / ".hol-guard" / "mdm-activation.json").is_file()
    assert (tmp_path / ".hol-guard" / "mdm-harness-coverage-request.json").is_file()


def test_device_context_registers_aggregate_harness_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    installs = [{"active": True, "harness": "codex", "manifest": {"config_path": str(tmp_path / "config")}}]
    registrations: list[tuple[Path, Path, list[dict[str, object]]]] = []

    paths = _machine_paths(tmp_path)
    _write_activation_marker(tmp_path)
    lifecycle._write_coverage_request(tmp_path, installs)
    monkeypatch.setattr(
        lifecycle,
        "GuardStore",
        lambda *_args: pytest.fail("device reconciliation opened the user SQLite store"),
    )
    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(lifecycle, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(lifecycle, "_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        lifecycle,
        "register_user_harnesses",
        lambda machine_paths, home, active: registrations.append((machine_paths, home, active)),
    )

    payload = lifecycle.register_user_coverage(tmp_path, "developer")

    assert registrations == [(paths, tmp_path, installs)]
    assert payload["operation"] == "harness-coverage-register"


def test_device_registration_rejects_symlinked_user_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_activation_marker(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text('{"schemaVersion":"hol-guard-harness-coverage-request.v1","installs":[]}')
    lifecycle._coverage_request_path(tmp_path).symlink_to(outside)
    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(
        lifecycle,
        "register_user_harnesses",
        lambda *_args: pytest.fail("symlinked request was registered"),
    )

    with pytest.raises(PermissionError, match="harness_coverage_request_acl_invalid"):
        lifecycle.register_user_coverage(tmp_path, "developer")


def test_device_registration_reports_absent_user_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_activation_marker(tmp_path)
    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(
        lifecycle,
        "register_user_harnesses",
        lambda *_args: pytest.fail("absent request was registered"),
    )

    with pytest.raises(ValueError, match="harness_coverage_request_absent"):
        lifecycle.register_user_coverage(tmp_path, "developer")


def test_partial_activation_rolls_back_new_harnesses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True}] if self.active else []

        def reconcile_managed_policy_bundle_keyring_state(self, **_kwargs: object) -> bool:
            return False

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


def test_activation_marker_failure_removes_evidence_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeStore:
        active = False

        def __init__(self, _guard_home: Path) -> None:
            pass

        def list_managed_installs(self) -> list[dict[str, object]]:
            return [{"harness": "codex", "active": True}] if self.active else []

        def reconcile_managed_policy_bundle_keyring_state(self, **_kwargs: object) -> bool:
            return False

    commands: list[str] = []

    def fake_install(command: str, *_args: object, **_kwargs: object) -> dict[str, object]:
        commands.append(command)
        FakeStore.active = command == "install"
        return {}

    original_write_text = Path.write_text

    def fail_marker(path: Path, data: str, *, encoding: str | None = None, errors: str | None = None) -> int:
        if path.name == "mdm-activation.json":
            raise OSError("marker unavailable")
        return original_write_text(path, data, encoding=encoding, errors=errors)

    monkeypatch.setattr(lifecycle, "GuardStore", FakeStore)
    monkeypatch.setattr(lifecycle, "apply_managed_install", fake_install)
    monkeypatch.setattr(Path, "write_text", fail_marker)

    with pytest.raises(OSError, match="marker unavailable"):
        lifecycle.activate_user(tmp_path, "developer")

    assert commands == ["install", "uninstall"]
    assert FakeStore.active is False
    assert not (tmp_path / ".hol-guard" / "mdm-activation.json").exists()
    assert not lifecycle._coverage_request_path(tmp_path).exists()


def test_device_registration_failure_never_rolls_back_completed_user_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    installs = [{"harness": "codex", "active": True, "manifest": {}}]
    _write_activation_marker(tmp_path)
    lifecycle._write_coverage_request(tmp_path, installs)

    def fail_registration(*_args: object) -> None:
        raise OSError("machine registry unavailable")

    monkeypatch.setattr(lifecycle, "load_managed_policy", _managed_policy)
    monkeypatch.setattr(lifecycle, "register_user_harnesses", fail_registration)

    with pytest.raises(OSError, match="machine registry unavailable"):
        lifecycle.register_user_coverage(tmp_path, "developer")

    assert lifecycle._coverage_request_path(tmp_path).is_file()


def test_device_context_unregisters_coverage_after_user_deactivation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    removals: list[tuple[Path, Path]] = []

    paths = _machine_paths(tmp_path)
    monkeypatch.setattr(lifecycle, "default_machine_paths", lambda: paths)
    monkeypatch.setattr(lifecycle, "_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        lifecycle,
        "unregister_user_harnesses",
        lambda machine_paths, home: removals.append((machine_paths.state_root, home)),
    )

    payload = lifecycle.unregister_user_coverage(tmp_path, "developer")

    assert removals == [(paths.state_root, tmp_path)]
    assert payload["operation"] == "harness-coverage-unregister"


def test_device_context_refuses_to_unregister_active_user_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / ".hol-guard"
    guard_home.mkdir()
    (guard_home / "mdm-activation.json").write_text("{}")
    monkeypatch.setattr(
        lifecycle,
        "unregister_user_harnesses",
        lambda *_args: pytest.fail("active coverage was removed"),
    )

    with pytest.raises(RuntimeError, match="harness_coverage_deactivation_incomplete"):
        lifecycle.unregister_user_coverage(tmp_path, "developer")
