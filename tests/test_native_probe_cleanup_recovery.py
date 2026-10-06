"""A vanished generation never substitutes for authenticated stop confirmation."""

from pathlib import Path
from types import SimpleNamespace

import pytest

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

    monkeypatch.setattr(probe, "_DAEMON_CLEANUP_TIMEOUT", 1.0)
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
