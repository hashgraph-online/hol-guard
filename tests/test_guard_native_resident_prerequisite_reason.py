"""The resident prerequisite fails closed and says why, without leaking paths or secrets."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_context, native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_resident_prerequisite_reason import (
    prerequisite_failure_for_home,
    prerequisite_unavailable_code,
)


@pytest.fixture(autouse=True)
def _fresh_prerequisite_state() -> None:
    native_context._RESIDENT_PREREQUISITE_HOMES.clear()  # pyright: ignore[reportPrivateUsage]


def test_fresh_home_provisions_its_own_verifier_key(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    provisioned = native_context.ensure_resident_prerequisite(home)
    # The reason is the CI diagnostic for platforms where provisioning is refused.
    assert provisioned, prerequisite_failure_for_home(home)
    assert prerequisite_unavailable_code("native_guard_store_prerequisite_unavailable", home) == (
        "native_guard_store_prerequisite_unavailable"
    )


def test_prerequisite_provisioning_never_refreshes_policy_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    refreshed: list[bool] = []

    def refresh(*args: object, **kwargs: object) -> None:
        refreshed.append(True)
        raise AssertionError("resident prerequisite must not refresh policy decisions")

    monkeypatch.setattr(GuardStore, "_refresh_policy_integrity_state", refresh)
    home = tmp_path / "prerequisite-home"
    assert native_context.ensure_resident_prerequisite(home), prerequisite_failure_for_home(home)
    assert refreshed == []
    assert (home / "native-runtime" / "policy-verifier.key").is_file()


def test_provisioning_failure_stays_closed_and_names_a_bounded_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "guard-home"
    secret_path = str(tmp_path / "very-secret-location")

    def refuse(_store: object) -> None:
        raise PermissionError(13, f"denied {secret_path}")

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", refuse)

    assert native_context.ensure_resident_prerequisite(home) is False
    code = prerequisite_unavailable_code("native_guard_store_prerequisite_unavailable", home)
    assert code == "native_guard_store_prerequisite_unavailable:provision_key:PermissionError:e13"
    assert secret_path not in code


def test_machine_codes_are_carried_but_free_form_messages_are_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "guard-home"

    def refuse(_store: object) -> None:
        raise RuntimeError("could not write C:\\Users\\someone\\state")

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", refuse)

    assert native_context.ensure_resident_prerequisite(home) is False
    assert prerequisite_failure_for_home(home) == "provision_key:RuntimeError"


def test_recovered_provisioning_clears_the_recorded_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "guard-home"
    real = native_policy_snapshot_publisher.provision_native_verifier_key_for_store
    calls = {"count": 0}

    def flaky(store: object) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError(5, "io")
        real(store)  # type: ignore[arg-type]

    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", flaky)

    assert native_context.ensure_resident_prerequisite(home) is False
    assert prerequisite_failure_for_home(home) == "provision_key:OSError:e5"
    assert native_context.ensure_resident_prerequisite(home) is True
    assert prerequisite_failure_for_home(home) is None


@pytest.mark.parametrize("detail", ["a" * 64, "deadbeef" * 8, "0123456789abcdef", "token"])
def test_secret_shaped_error_args_are_not_carried(detail: str) -> None:
    from codex_plugin_scanner.guard.native_resident_prerequisite_reason import prerequisite_failure_reason

    assert prerequisite_failure_reason("provision_key", RuntimeError(detail)) == "provision_key:RuntimeError"


def test_untrusted_exception_with_code_shaped_message_is_not_carried() -> None:
    from codex_plugin_scanner.guard.native_resident_prerequisite_reason import prerequisite_failure_reason

    assert prerequisite_failure_reason("provision_key", RuntimeError("api_key_hunter2")) == "provision_key:RuntimeError"


def test_snapshot_layer_machine_code_is_carried() -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
    from codex_plugin_scanner.guard.native_resident_prerequisite_reason import prerequisite_failure_reason

    error = NativePolicySnapshotError("native_policy_snapshot_integrity_key_unavailable")
    assert prerequisite_failure_reason("provision_key", error) == (
        "provision_key:NativePolicySnapshotError:native_policy_snapshot_integrity_key_unavailable"
    )


def test_suffixed_prerequisite_reason_still_counts_dropped_events_locally() -> None:
    from codex_plugin_scanner.guard.store_command_activity_lifecycle import _PRE_SEND_REASONS  # pyright: ignore

    reason = "native_guard_store_prerequisite_unavailable:provision_key:PermissionError:e13"
    assert reason.partition(":")[0] in _PRE_SEND_REASONS
