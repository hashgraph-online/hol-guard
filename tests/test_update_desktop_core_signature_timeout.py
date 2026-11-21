from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_desktop_core
from codex_plugin_scanner.guard.cli.update_desktop_core import DesktopCoreUpdateError


def _candidate(tmp_path: Path) -> tuple[Path, str]:
    launcher = tmp_path / "hol-guard"
    launcher.write_bytes(b"launcher-bytes")
    return launcher, hashlib.sha256(b"launcher-bytes").hexdigest()


def test_a_sealed_launcher_is_verified_once_with_a_bundle_sized_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Verifying a sealed onedir launcher hashes every bundled resource, which took 4.4-5.5 s
    # on a busy Mac. The old 5 s ceiling, paid twice per candidate, failed the update.
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    calls: list[float] = []

    def verify(_path: Path, *, deep: bool = False, timeout: float = 5.0) -> str:
        calls.append(timeout)
        return "TEAMID"

    monkeypatch.setattr(update_desktop_core, "verified_macos_signing_team", verify)
    launcher, digest = _candidate(tmp_path)

    update_desktop_core._verify_candidate(launcher, expected_team="TEAMID", expected_sha256=digest)

    assert calls == [30.0]


def test_an_unverified_launcher_is_still_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    monkeypatch.setattr(update_desktop_core, "verified_macos_signing_team", lambda _path, **_kwargs: None)
    launcher, digest = _candidate(tmp_path)

    with pytest.raises(DesktopCoreUpdateError) as error:
        update_desktop_core._verify_candidate(launcher, expected_team="TEAMID", expected_sha256=digest)

    assert error.value.reason_code == "desktop_core_signature_invalid"


def test_a_launcher_of_another_team_is_still_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_desktop_core.sys, "platform", "darwin")
    monkeypatch.setattr(update_desktop_core, "verified_macos_signing_team", lambda _path, **_kwargs: "OTHERTEAM")
    launcher, digest = _candidate(tmp_path)

    with pytest.raises(DesktopCoreUpdateError) as error:
        update_desktop_core._verify_candidate(launcher, expected_team="TEAMID", expected_sha256=digest)

    assert error.value.reason_code == "desktop_core_signature_mismatch"
