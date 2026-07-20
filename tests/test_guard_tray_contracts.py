"""Contract tests for the HOL Guard tray icon typed contracts.

Validates that all tray contracts, enums, state machines, and locator
serialization are correct, redact secrets, and handle unknown schemas
safely. These tests defend the stable JSON contract consumed by the
CLI, dashboard API, and settings UI.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.tray.contracts import (
    LOCATOR_SCHEMA_VERSION,
    MAX_CRASH_RETRIES,
    TRAY_REGISTRATION_LABEL,
    TrayBackend,
    TrayCapability,
    TrayLifecycleResult,
    TrayLocator,
    TrayPlatform,
    TrayProcessIdentity,
    TrayReasonCode,
    TrayRegistration,
    TrayState,
    TrayStatus,
    _coerce_int,
    _parse_datetime,
    utcnow,
)


class TestTrayPlatform:
    def test_current_returns_macos_on_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "darwin")
        assert TrayPlatform.current() == TrayPlatform.MACOS

    def test_current_returns_windows_on_win32(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "win32")
        assert TrayPlatform.current() == TrayPlatform.WINDOWS

    def test_current_returns_linux_on_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "linux")
        assert TrayPlatform.current() == TrayPlatform.LINUX

    def test_current_returns_none_on_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.platform", "freebsd7")
        assert TrayPlatform.current() is None


class TestTrayStateMachine:
    @pytest.mark.parametrize(
        ("from_state", "to_state", "expected"),
        [
            (TrayState.ABSENT, TrayState.SUPPORTED, True),
            (TrayState.ABSENT, TrayState.UNSUPPORTED, True),
            (TrayState.ABSENT, TrayState.RUNNING, False),
            (TrayState.SUPPORTED, TrayState.INSTALLED, True),
            (TrayState.INSTALLED, TrayState.STARTING, True),
            (TrayState.STARTING, TrayState.RUNNING, True),
            (TrayState.RUNNING, TrayState.STOPPING, True),
            (TrayState.RUNNING, TrayState.INSTALLED, False),
            (TrayState.STOPPING, TrayState.INSTALLED, True),
            (TrayState.STALE, TrayState.REPAIR_REQUIRED, True),
            (TrayState.REPAIR_REQUIRED, TrayState.INSTALLED, True),
            (TrayState.UNSUPPORTED, TrayState.ABSENT, True),
            (TrayState.UNSUPPORTED, TrayState.RUNNING, False),
            (TrayState.FAILED, TrayState.STARTING, True),
            (TrayState.FAILED, TrayState.RUNNING, False),
        ],
    )
    def test_transition_validity(self, from_state: TrayState, to_state: TrayState, expected: bool) -> None:
        assert from_state.can_transition_to(to_state) is expected

    def test_all_states_have_transitions(self) -> None:
        for state in TrayState:
            transitions = TrayState.valid_transitions(state)
            assert isinstance(transitions, frozenset)

    def test_running_can_reach_failed(self) -> None:
        assert TrayState.RUNNING.can_transition_to(TrayState.FAILED)


class TestTrayReasonCode:
    def test_all_reason_codes_are_unique_strings(self) -> None:
        values = [code.value for code in TrayReasonCode]
        assert len(values) == len(set(values))

    def test_reason_codes_are_snake_case(self) -> None:
        import re

        for code in TrayReasonCode:
            assert re.match(r"^[a-z][a-z0-9_]*$", code.value), f"{code.value} is not snake_case"


class TestTrayCapability:
    def test_supported_capability_payload(self) -> None:
        cap = TrayCapability(
            platform=TrayPlatform.MACOS,
            backend=TrayBackend.APPKIT,
            supported=True,
            reason=TrayReasonCode.OK,
            details="macOS Aqua session with AppKit backend",
        )
        payload = cap.to_payload()
        assert payload["platform"] == "macos"
        assert payload["backend"] == "appkit"
        assert payload["supported"] is True
        assert payload["reason"] == "ok"
        assert payload["details"] == "macOS Aqua session with AppKit backend"

    def test_unsupported_capability_payload(self) -> None:
        cap = TrayCapability(
            platform=None,
            backend=TrayBackend.NONE,
            supported=False,
            reason=TrayReasonCode.UNSUPPORTED_PLATFORM,
            details="FreeBSD is not supported",
        )
        payload = cap.to_payload()
        assert payload["platform"] is None
        assert payload["backend"] == "none"
        assert payload["supported"] is False

    def test_payload_is_json_serializable(self) -> None:
        cap = TrayCapability(
            platform=TrayPlatform.LINUX,
            backend=TrayBackend.APPINDICATOR,
            supported=True,
            reason=TrayReasonCode.OK,
        )
        assert json.dumps(cap.to_payload()) is not None


class TestTrayProcessIdentity:
    def _identity(self, **overrides: object) -> TrayProcessIdentity:
        defaults: dict[str, object] = {
            "pid": 12345,
            "process_start_fingerprint": "2024-01-01T00:00:00",
            "executable": "/usr/bin/python3",
            "command": "python3 -m hol-guard tray run",
            "guard_home": "/tmp/guard",
            "package_version": "2.0.0",
            "backend": TrayBackend.APPKIT,
            "registration_generation": 1,
        }
        defaults.update(overrides)
        return TrayProcessIdentity(**defaults)  # type: ignore[arg-type]

    def test_matching_identities(self) -> None:
        a = self._identity()
        b = self._identity()
        assert a.matches(b)

    def test_non_matching_pid(self) -> None:
        a = self._identity(pid=12345)
        b = self._identity(pid=99999)
        assert not a.matches(b)

    def test_non_matching_fingerprint_detects_pid_reuse(self) -> None:
        a = self._identity(process_start_fingerprint="2024-01-01T00:00:00")
        b = self._identity(process_start_fingerprint="2024-06-01T12:00:00")
        assert not a.matches(b)

    def test_non_matching_guard_home(self) -> None:
        a = self._identity(guard_home="/tmp/guard1")
        b = self._identity(guard_home="/tmp/guard2")
        assert not a.matches(b)

    def test_non_matching_command(self) -> None:
        """``matches()`` must reject identities with different command lines —
        a PID reused by a different process will have a different cmdline."""
        a = self._identity(command="python3 -m hol-guard tray run --guard-home /a")
        b = self._identity(command="python3 -m hol-guard tray run --guard-home /b")
        assert not a.matches(b)

    def test_non_matching_executable(self) -> None:
        a = self._identity(executable="/usr/bin/python3")
        b = self._identity(executable="/usr/local/bin/python3.11")
        assert not a.matches(b)

    def test_non_matching_package_version(self) -> None:
        a = self._identity(package_version="2.0.0")
        b = self._identity(package_version="2.1.0")
        assert not a.matches(b)

    def test_non_matching_backend(self) -> None:
        a = self._identity(backend=TrayBackend.APPKIT)
        b = self._identity(backend=TrayBackend.APPINDICATOR)
        assert not a.matches(b)

    def test_non_matching_registration_generation(self) -> None:
        a = self._identity(registration_generation=1)
        b = self._identity(registration_generation=2)
        assert not a.matches(b)

    def test_payload_has_no_secrets(self) -> None:
        identity = self._identity()
        payload = identity.to_payload()
        payload_str = json.dumps(payload)
        assert "token" not in payload_str.lower()
        assert "secret" not in payload_str.lower()
        assert "password" not in payload_str.lower()
        assert "fragment" not in payload_str.lower()


class TestTrayRegistration:
    def test_registration_payload(self) -> None:
        reg = TrayRegistration(
            platform=TrayPlatform.MACOS,
            label=TRAY_REGISTRATION_LABEL,
            target_path="/Users/test/Library/LaunchAgents/org.hol.guard.tray.plist",
            program_arguments=("/usr/local/bin/hol-guard", "tray", "run"),
            run_at_login=True,
            owned=True,
            generation=1,
        )
        payload = reg.to_payload()
        assert payload["platform"] == "macos"
        assert payload["label"] == "org.hol.guard.tray"
        assert payload["program_arguments"] == ["/usr/local/bin/hol-guard", "tray", "run"]
        assert payload["run_at_login"] is True
        assert payload["owned"] is True

    def test_foreign_registration_not_owned(self) -> None:
        reg = TrayRegistration(
            platform=TrayPlatform.MACOS,
            label=TRAY_REGISTRATION_LABEL,
            target_path="/Users/test/Library/LaunchAgents/org.hol.guard.tray.plist",
            program_arguments=("/some/other/app",),
            run_at_login=True,
            owned=False,
            generation=0,
        )
        assert reg.owned is False


class TestTrayLocator:
    def _payload(self, **overrides: object) -> dict[str, object]:
        defaults: dict[str, object] = {
            "schema_version": LOCATOR_SCHEMA_VERSION,
            "package_version": "2.0.0",
            "pid": 12345,
            "process_start_fingerprint": "2024-01-01T00:00:00+00:00",
            "executable": "/usr/bin/python3",
            "command": "python3 -m hol-guard tray run",
            "guard_home": "/tmp/guard",
            "backend": "appkit",
            "registration_generation": 1,
            "last_ready": "2024-01-01T12:00:00+00:00",
            "crash_count": 0,
            "last_crash": None,
        }
        defaults.update(overrides)
        return defaults

    def test_round_trip(self) -> None:
        payload = self._payload()
        locator = TrayLocator.from_payload(payload)
        assert locator.schema_version == LOCATOR_SCHEMA_VERSION
        assert locator.pid == 12345
        assert locator.backend == TrayBackend.APPKIT
        result = locator.to_payload()
        assert result["pid"] == 12345
        assert result["backend"] == "appkit"

    def test_rejects_future_schema(self) -> None:
        payload = self._payload(schema_version=999)
        with pytest.raises(ValueError, match="unsupported locator schema"):
            TrayLocator.from_payload(payload)

    def test_missing_schema_raises(self) -> None:
        payload = self._payload()
        del payload["schema_version"]
        with pytest.raises(ValueError, match="missing schema_version"):
            TrayLocator.from_payload(payload)

    def test_invalid_backend_defaults_to_none(self) -> None:
        payload = self._payload(backend="nonexistent")
        locator = TrayLocator.from_payload(payload)
        assert locator.backend == TrayBackend.NONE

    def test_to_process_identity(self) -> None:
        locator = TrayLocator.from_payload(self._payload())
        identity = locator.to_process_identity()
        assert identity.pid == 12345
        assert identity.backend == TrayBackend.APPKIT

    def test_payload_has_no_secrets(self) -> None:
        locator = TrayLocator.from_payload(self._payload())
        payload_str = json.dumps(locator.to_payload())
        assert "token" not in payload_str.lower()
        assert "secret" not in payload_str.lower()
        assert "password" not in payload_str.lower()
        assert "fragment" not in payload_str.lower()

    def test_crash_tracking_fields(self) -> None:
        payload = self._payload(crash_count=2, last_crash="2024-01-01T10:00:00+00:00")
        locator = TrayLocator.from_payload(payload)
        assert locator.crash_count == 2
        assert locator.last_crash is not None


class TestTrayStatus:
    def test_status_payload(self) -> None:
        cap = TrayCapability(
            platform=TrayPlatform.MACOS,
            backend=TrayBackend.APPKIT,
            supported=True,
            reason=TrayReasonCode.OK,
        )
        status = TrayStatus(
            state=TrayState.RUNNING,
            capability=cap,
            registration=None,
            process=None,
            reason=TrayReasonCode.OK,
            recovery_command="hol-guard tray start",
            last_ready=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
        )
        payload = status.to_payload()
        assert payload["state"] == "running"
        assert payload["reason"] == "ok"
        assert payload["recovery_command"] == "hol-guard tray start"
        assert payload["last_ready"] == "2024-01-01T12:00:00+00:00"

    def test_status_with_none_fields(self) -> None:
        cap = TrayCapability(
            platform=None,
            backend=TrayBackend.NONE,
            supported=False,
            reason=TrayReasonCode.UNSUPPORTED_PLATFORM,
        )
        status = TrayStatus(
            state=TrayState.UNSUPPORTED,
            capability=cap,
            registration=None,
            process=None,
            reason=TrayReasonCode.UNSUPPORTED_PLATFORM,
            recovery_command="",
            last_ready=None,
        )
        payload = status.to_payload()
        assert payload["registration"] is None
        assert payload["process"] is None
        assert payload["last_ready"] is None


class TestTrayLifecycleResult:
    def test_success_result(self) -> None:
        result = TrayLifecycleResult(
            ok=True,
            state=TrayState.RUNNING,
            reason=TrayReasonCode.OK,
            message="Tray icon started",
        )
        payload = result.to_payload()
        assert payload["ok"] is True
        assert payload["state"] == "running"
        assert payload["reason"] == "ok"
        assert payload["message"] == "Tray icon started"

    def test_failure_result_with_recovery(self) -> None:
        result = TrayLifecycleResult(
            ok=False,
            state=TrayState.REPAIR_REQUIRED,
            reason=TrayReasonCode.LOCATOR_MALFORMED,
            message="Locator file is corrupted",
            recovery_command="hol-guard tray install --force",
        )
        payload = result.to_payload()
        assert payload["ok"] is False
        assert payload["recovery_command"] == "hol-guard tray install --force"


class TestHelpers:
    def test_coerce_int_from_int(self) -> None:
        assert _coerce_int(42) == 42

    def test_coerce_int_from_str(self) -> None:
        assert _coerce_int("42") == 42

    def test_coerce_int_from_invalid_str(self) -> None:
        assert _coerce_int("abc") == 0

    def test_coerce_int_from_none(self) -> None:
        assert _coerce_int(None) == 0

    def test_coerce_int_from_bool_returns_zero(self) -> None:
        assert _coerce_int(True) == 0

    def test_parse_datetime_valid(self) -> None:
        dt = _parse_datetime("2024-01-01T12:00:00+00:00")
        assert dt is not None
        assert dt.year == 2024

    def test_parse_datetime_invalid(self) -> None:
        assert _parse_datetime("not a date") is None

    def test_parse_datetime_none(self) -> None:
        assert _parse_datetime(None) is None

    def test_utcnow_is_timezone_aware(self) -> None:
        dt = utcnow()
        assert dt.tzinfo is not None


class TestConstants:
    def test_schema_version_is_positive(self) -> None:
        assert LOCATOR_SCHEMA_VERSION >= 1

    def test_registration_label_is_stable(self) -> None:
        assert TRAY_REGISTRATION_LABEL == "org.hol.guard.tray"

    def test_crash_retry_limit_is_reasonable(self) -> None:
        assert 1 <= MAX_CRASH_RETRIES <= 10


class TestTrayAssetPackaging:
    """Verify tray icon assets are accessible via importlib.resources."""

    def test_assets_directory_exists(self) -> None:
        from codex_plugin_scanner.guard.tray import assets as assets_module

        assert hasattr(assets_module, "__path__")

    def test_at_least_one_icon_available(self) -> None:
        try:
            from importlib.resources import files
        except ImportError:
            from importlib_resources import files  # type: ignore[no-redef]

        asset_root = files("codex_plugin_scanner.guard.tray.assets")
        icons = [p for p in asset_root.iterdir() if p.name.endswith(".png")]
        assert len(icons) > 0, "No tray icon PNG assets found"

    def test_icon_files_are_valid_pngs(self) -> None:
        try:
            from importlib.resources import files
        except ImportError:
            from importlib_resources import files  # type: ignore[no-redef]

        from PIL import Image

        asset_root = files("codex_plugin_scanner.guard.tray.assets")
        for icon_path in asset_root.iterdir():
            if icon_path.name.endswith(".png"):
                with icon_path.open("rb") as f:
                    img = Image.open(f)
                    img.verify()
