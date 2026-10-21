"""A vanished generation never substitutes for authenticated stop confirmation."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_native_extensions as extension_probe
from ci.native_runtime import probe_installed_pi_output as probe
from codex_plugin_scanner.guard import native_resident_client


@pytest.mark.parametrize("retry_confirmed", [True, False])
def test_cleanup_reconfirms_stop_after_generation_disappears(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, retry_confirmed: bool
) -> None:
    clock = [0.0]
    stops: list[dict[str, object]] = []
    state_checks = [0]
    guard_home = tmp_path / "guard-home"

    def state_files(_home: Path) -> tuple[Path, ...]:
        state_checks[0] += 1
        return (guard_home / "generation.json",) if state_checks[0] == 1 else ()

    def stop(**kwargs: object) -> bool:
        stops.append(kwargs)
        return len(stops) > 1 and retry_confirmed

    monkeypatch.setattr(probe, "_daemon_cleanup_timeout_seconds", lambda: 1.0)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(probe, "_native_state_files", state_files)
    monkeypatch.setattr(native_resident_client, "close_native_residents", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(native_resident_client, "stop_native_resident", stop)
    identity = SimpleNamespace(path=Path("/trusted/native-runtime"))

    if retry_confirmed:
        probe._cleanup_native(identity, guard_home)
    else:
        with pytest.raises(probe.ProbeError, match="authenticated native cleanup failed"):
            probe._cleanup_native(identity, guard_home)

    assert len(stops) >= 2
    assert all(call["retire_clients"] is True for call in stops)
    assert all(call["state_dir"] == guard_home / "native-runtime" for call in stops)
    assert all(call["deadline_monotonic"] == 1.0 for call in stops)
    assert all(0 < call["timeout_seconds"] <= 1.0 for call in stops)


@pytest.mark.parametrize("failure", [OSError, RuntimeError])
def test_extension_probe_retries_transient_cleanup_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: type[Exception]
) -> None:
    clock = [0.0]
    attempts: list[float] = []

    def close(_home: Path, *, deadline_monotonic: float) -> bool:
        attempts.append(deadline_monotonic)
        if len(attempts) < 3:
            raise failure("transient cleanup error")
        return True

    monkeypatch.setattr(extension_probe, "_DAEMON_CLEANUP_TIMEOUT", 1.0)
    monkeypatch.setattr(extension_probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(extension_probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(extension_probe, "close_native_residents", close)

    assert extension_probe.close_native_residents_with_retry(tmp_path)
    assert attempts == [1.0, 1.0, 1.0]
    assert clock[0] == 2 * extension_probe._NATIVE_CLEANUP_RETRY_INTERVAL


def test_extension_probe_returns_false_after_repeated_cleanup_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clock = [0.0]
    attempts = 0

    def close(_home: Path, *, deadline_monotonic: float) -> bool:
        nonlocal attempts
        attempts += 1
        assert deadline_monotonic == 1.0
        raise RuntimeError("transient cleanup error")

    monkeypatch.setattr(extension_probe, "_DAEMON_CLEANUP_TIMEOUT", 1.0)
    monkeypatch.setattr(extension_probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(extension_probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(extension_probe, "close_native_residents", close)

    assert not extension_probe.close_native_residents_with_retry(tmp_path)
    assert attempts == 4
    assert clock[0] == 1.0
