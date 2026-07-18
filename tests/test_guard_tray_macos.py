"""Tests for macOS tray platform adapter (MacOSTrayAdapter).

Validates LaunchAgent registration, ownership detection, plist structure,
idempotency, and security properties without touching real system resources.
Uses tmp_path for file-based operations and mocks for subprocess calls.
"""

from __future__ import annotations

import plistlib
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from codex_plugin_scanner.guard.tray.contracts import (
    TRAY_REGISTRATION_LABEL,
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
)
from codex_plugin_scanner.guard.tray.platforms import macos as macos_module

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


def _capability(platform: TrayPlatform = TrayPlatform.MACOS) -> TrayCapability:
    """Build a TrayCapability for the given platform."""
    return TrayCapability(
        platform=platform,
        backend=TrayBackend.APPKIT,
        supported=True,
        reason=TrayReasonCode.OK,
    )


@pytest.fixture()
def adapter() -> macos_module.MacOSTrayAdapter:
    return macos_module.MacOSTrayAdapter()


@pytest.fixture()
def guard_home(tmp_path: Path) -> Path:
    return tmp_path / "guard_home"


@pytest.fixture()
def mock_plist_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Patch macos_module constants so the plist is written under tmp_path."""
    launchagents = tmp_path / "Library" / "LaunchAgents"
    launchagents.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(macos_module, "LAUNCHAGENTS_DIR", launchagents)
    monkeypatch.setattr(macos_module, "PLIST_FILENAME", f"{TRAY_REGISTRATION_LABEL}.plist")
    return launchagents


# ---------------------------------------------------------------------------
# Platform identification
# ---------------------------------------------------------------------------


class TestPlatformId:
    def test_platform_is_macos(self, adapter: macos_module.MacOSTrayAdapter) -> None:
        assert adapter.platform is TrayPlatform.MACOS

    def test_detect_capability_returns_macos(self, adapter: macos_module.MacOSTrayAdapter) -> None:
        # detect_capability() calls TrayPlatform.current() which checks
        # sys.platform. On Linux CI this returns LINUX. Mock it to MACOS.
        with patch.object(TrayPlatform, "current", return_value=TrayPlatform.MACOS):
            cap = adapter.detect_capability()
            assert cap.platform is TrayPlatform.MACOS


# ---------------------------------------------------------------------------
# Plist path correctness
# ---------------------------------------------------------------------------


class TestPlistPath:
    def test_plist_path_under_library_launch_agents(
        self, adapter: macos_module.MacOSTrayAdapter, mock_plist_dir: Path
    ) -> None:
        plist_path = adapter._plist_path()
        assert plist_path.parent == mock_plist_dir
        assert plist_path.name == f"{TRAY_REGISTRATION_LABEL}.plist"

    def test_plist_filename_matches_label(self) -> None:
        assert f"{TRAY_REGISTRATION_LABEL}.plist" == macos_module.PLIST_FILENAME

    def test_plist_path_uses_home_directory(self, adapter: macos_module.MacOSTrayAdapter, mock_plist_dir: Path) -> None:
        plist_path = adapter._plist_path()
        assert plist_path.is_relative_to(mock_plist_dir)


# ---------------------------------------------------------------------------
# Install — plist structure correctness
# ---------------------------------------------------------------------------


class TestInstallPlistStructure:
    def test_run_at_load_true_by_default(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        result = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        assert result["installed"] is True

        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["RunAtLoad"] is True

    def test_run_at_load_false_when_requested(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        result = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=False,
        )
        assert result["installed"] is True

        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["RunAtLoad"] is False

    def test_label_matches_tray_registration_label(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["Label"] == TRAY_REGISTRATION_LABEL

    def test_program_arguments_contains_codex_plugin_scanner(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        args = plist["ProgramArguments"]
        assert any("codex_plugin_scanner" in str(arg) for arg in args)

    def test_program_arguments_no_secrets_or_tokens(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        all_values: list[str] = [str(arg) for arg in plist["ProgramArguments"]]
        secret_patterns = [
            "token",
            "secret",
            "api_key",
            "apikey",
            "password",
            "Bearer",
            "sk-",
            "ghp_",
        ]
        joined = " ".join(all_values).lower()
        for pat in secret_patterns:
            assert pat not in joined, f"Secret pattern '{pat}' found in ProgramArguments: {all_values}"

    def test_plist_contains_keep_alive_false(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["KeepAlive"] is False

    def test_plist_contains_standard_log_paths(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert "StandardOutPath" in plist
        assert "StandardErrorPath" in plist
        assert (guard_home / "tray" / "stdout.log") == Path(plist["StandardOutPath"])
        assert (guard_home / "tray" / "stderr.log") == Path(plist["StandardErrorPath"])

    def test_plist_contains_python_unbuffered_env(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        env = plist.get("EnvironmentVariables", {})
        assert env.get("PYTHONUNBUFFERED") == "1"


# ---------------------------------------------------------------------------
# Install — full plist contents (no secrets anywhere)
# ---------------------------------------------------------------------------


class TestInstallPlistNoSecrets:
    """Assert that NO field in the entire plist contains secret-like content."""

    SECRET_PATTERNS: ClassVar[list[str]] = [
        "token",
        "secret",
        "api_key",
        "apikey",
        "password",
        "Bearer",
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
    ]

    @staticmethod
    def _flatten_values(obj: object, path: str = "") -> list[str]:
        """Recursively flatten all string values from a plist dict/list."""
        values: list[str] = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                values.extend(TestInstallPlistNoSecrets._flatten_values(v, f"{path}.{k}"))
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                values.extend(TestInstallPlistNoSecrets._flatten_values(v, f"{path}[{i}]"))
        else:
            values.append(str(obj))
        return values

    def test_no_secret_value_in_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        plist_path = adapter._plist_path()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)

        all_values = self._flatten_values(plist)
        for value in all_values:
            # Skip path-like values (StandardOutPath, etc.) — they contain
            # directory segments that naturally match secret patterns.
            if "/" in value:
                continue
            value_lower = value.lower()
            for pat in self.SECRET_PATTERNS:
                assert pat not in value_lower, f"Secret pattern '{pat}' found in plist value: {value!r}"


# ---------------------------------------------------------------------------
# Inspect — ownership detection
# ---------------------------------------------------------------------------


class TestInspectOwnership:
    def test_not_installed_when_no_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("installed") is False

    def test_owned_when_program_arguments_match(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("installed") is True
        assert result.get("owned") is True
        assert "path" in result

    def test_foreign_when_different_program_arguments(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        """A plist with same Label but different ProgramArguments = foreign."""
        plist_path = adapter._plist_path()
        foreign_plist = {
            "Label": TRAY_REGISTRATION_LABEL,
            "ProgramArguments": [
                "/usr/bin/python3",
                "/some/other/app.py",
            ],
            "RunAtLoad": True,
        }
        with plist_path.open("wb") as f:
            plistlib.dump(foreign_plist, f)

        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("installed") is True
        assert result.get("owned") is False

    def test_foreign_detects_hol_guard_keyword(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        """A plist referencing 'hol-guard' is considered owned."""
        plist_path = adapter._plist_path()
        hol_plist = {
            "Label": TRAY_REGISTRATION_LABEL,
            "ProgramArguments": [
                "/usr/bin/python3",
                "-m",
                "hol-guard.cli",
            ],
            "RunAtLoad": True,
        }
        with plist_path.open("wb") as f:
            plistlib.dump(hol_plist, f)

        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("owned") is True

    def test_malformed_plist_marked_not_owned(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        plist_path = adapter._plist_path()
        plist_path.write_bytes(b"not a valid plist {{{")

        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("installed") is True
        assert result.get("owned") is False
        assert result.get("malformed") is True

    def test_inspect_returns_run_at_login(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("run_at_login") is True

    def test_inspect_returns_keep_alive(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        result = adapter.inspect_registration(guard_home=guard_home)
        assert result.get("keep_alive") is False


# ---------------------------------------------------------------------------
# Install — foreign plist rejection (collision detection)
# ---------------------------------------------------------------------------


class TestInstallCollision:
    def test_rejects_foreign_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        """Installing over a foreign LaunchAgent should be rejected."""
        plist_path = adapter._plist_path()
        foreign_plist = {
            "Label": TRAY_REGISTRATION_LABEL,
            "ProgramArguments": ["/usr/local/bin/other-app"],
            "RunAtLoad": True,
        }
        with plist_path.open("wb") as f:
            plistlib.dump(foreign_plist, f)

        result = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        assert result.get("installed") is False
        assert result.get("reason") == "startup_registration_collision"
        assert plist_path.exists()  # Not overwritten

    def test_overwrites_own_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        """Re-installing over our own plist should succeed (idempotent)."""
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        first_result = adapter.inspect_registration(guard_home=guard_home)
        assert first_result.get("owned") is True

        second_result = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=False,
        )
        assert second_result.get("installed") is True

        updated = adapter.inspect_registration(guard_home=guard_home)
        assert updated.get("run_at_login") is False


# ---------------------------------------------------------------------------
# Install / Remove — idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_install_twice_is_idempotent(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        plist_path = adapter._plist_path()
        r1 = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        assert r1["installed"] is True

        r2 = adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        assert r2["installed"] is True
        # File should still exist (idempotent — no error)
        assert plist_path.exists()

    def test_remove_nonexistent_is_noop(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        result = adapter.remove_registration(guard_home=guard_home)
        assert result.get("removed") is False
        assert result.get("reason") == "not_installed"

    def test_remove_twice_is_idempotent(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        r1 = adapter.remove_registration(guard_home=guard_home)
        assert r1.get("removed") is True

        r2 = adapter.remove_registration(guard_home=guard_home)
        assert r2.get("removed") is False
        assert r2.get("reason") == "not_installed"

    def test_remove_foreign_refuses(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        """Removing a foreign LaunchAgent should be refused."""
        plist_path = adapter._plist_path()
        foreign_plist = {
            "Label": TRAY_REGISTRATION_LABEL,
            "ProgramArguments": ["/usr/local/bin/other-app"],
            "RunAtLoad": True,
        }
        with plist_path.open("wb") as f:
            plistlib.dump(foreign_plist, f)

        result = adapter.remove_registration(guard_home=guard_home)
        assert result.get("removed") is False
        assert result.get("reason") == "startup_registration_collision"
        assert plist_path.exists()  # Not removed


# ---------------------------------------------------------------------------
# Start / Stop / Process — subprocess mocking
# ---------------------------------------------------------------------------


class TestProcessLifecycle:
    def test_start_process_loads_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        mock_run = MagicMock(return_value=MagicMock(returncode=0))
        with patch("subprocess.run", mock_run):
            result = adapter.start_process(
                guard_home=guard_home,
                capability=_capability(),
            )
        assert result.get("started") is True
        assert mock_run.call_count >= 1

    def test_start_process_installs_if_missing(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        mock_run = MagicMock(return_value=MagicMock(returncode=0))
        with patch("subprocess.run", mock_run):
            result = adapter.start_process(
                guard_home=guard_home,
                capability=_capability(),
            )
        assert result.get("started") is True

    def test_stop_process_unloads_plist(
        self,
        adapter: macos_module.MacOSTrayAdapter,
        mock_plist_dir: Path,
        guard_home: Path,
    ) -> None:
        adapter.install_registration(
            guard_home=guard_home,
            capability=_capability(),
            run_at_login=True,
        )
        mock_run = MagicMock(return_value=MagicMock(returncode=0))
        with patch("subprocess.run", mock_run):
            result = adapter.stop_process(pid=1234)
        assert result.get("stopped") is True
        unload_call = mock_run.call_args_list[0]
        assert "unload" in str(unload_call)

    def test_is_process_running_pid_zero(self, adapter: macos_module.MacOSTrayAdapter) -> None:
        """PID <= 0 checks via launchctl list."""
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout=""))
        with patch("subprocess.run", mock_run):
            result = adapter.is_process_running(pid=0)
        assert result is True

    def test_is_process_running_pid_nonzero(self, adapter: macos_module.MacOSTrayAdapter) -> None:
        """PID > 0 delegates to is_process_alive."""
        with patch(
            "codex_plugin_scanner.guard.tray.state.is_process_alive",
            return_value=True,
        ):
            result = adapter.is_process_running(pid=1234)
        assert result is True

    def test_is_process_running_pid_negative(self, adapter: macos_module.MacOSTrayAdapter) -> None:
        """Negative PIDs also go through launchctl list."""
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout=""))
        with patch("subprocess.run", mock_run):
            result = adapter.is_process_running(pid=-1)
        assert result is True
