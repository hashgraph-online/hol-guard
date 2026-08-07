"""Reference-runtime unit tests plus an opt-in real runsc isolation corpus."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest
from codex_plugin_scanner.guard.runtime.gvisor_reference_runtime import GVisorReferenceRuntime
from codex_plugin_scanner.guard.runtime.isolation_provider import ProviderPlanError

_RUNSC = Path("/tmp/hol-guard-test/runsc")
_BUNDLES = Path("/tmp/hol-guard-test/bundles")
_STATE = Path("/tmp/hol-guard-test/state")


def _write_fake_runsc() -> str:
    _RUNSC.parent.mkdir(parents=True, exist_ok=True)
    _RUNSC.write_bytes(b"fake-runsc")
    _RUNSC.chmod(0o755)
    return hashlib.sha256(_RUNSC.read_bytes()).hexdigest()


def _runner(digest: str | None = None) -> GVisorReferenceRuntime:
    return GVisorReferenceRuntime(
        runsc_path=str(_RUNSC),
        runsc_digest=digest or _write_fake_runsc(),
        bundle_root=str(_BUNDLES),
        state_root=str(_STATE),
    )


def _bundle(name: str) -> Path:
    path = _BUNDLES / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "config.json").write_text("{}", encoding="utf-8")
    return path


class TestConfiguration:
    def test_rejects_relative_or_non_guard_owned_paths(self) -> None:
        digest = "1" * 64
        with pytest.raises(ValueError, match="absolute"):
            GVisorReferenceRuntime(
                runsc_path="runsc",
                runsc_digest=digest,
                bundle_root=str(_BUNDLES),
                state_root=str(_STATE),
            )
        with pytest.raises(ValueError, match="Guard-owned"):
            GVisorReferenceRuntime(
                runsc_path="/usr/bin/runsc",
                runsc_digest=digest,
                bundle_root=str(_BUNDLES),
                state_root=str(_STATE),
            )

    def test_rejects_invalid_digest_and_platform(self) -> None:
        with pytest.raises(ValueError, match="64 lowercase"):
            _runner("not-a-digest")
        digest = _write_fake_runsc()
        with pytest.raises(ValueError, match="systrap or kvm"):
            GVisorReferenceRuntime(
                runsc_path=str(_RUNSC),
                runsc_digest=digest,
                bundle_root=str(_BUNDLES),
                state_root=str(_STATE),
                platform="ptrace",
            )

    def test_binary_digest_mismatch_fails_closed(self) -> None:
        _write_fake_runsc()
        runner = _runner("1" * 64)
        with pytest.raises(ProviderPlanError, match="digest mismatch"):
            runner.verify_binary()

    def test_binary_permissions_fail_closed(self) -> None:
        digest = _write_fake_runsc()
        _RUNSC.chmod(0o700)
        with pytest.raises(ProviderPlanError, match="sandbox process"):
            _ = _runner(digest).verify_binary()
        _RUNSC.chmod(0o775)
        with pytest.raises(ProviderPlanError, match="writable outside"):
            _ = _runner(digest).verify_binary()

    def test_bundle_traversal_and_unknown_instances_fail(self) -> None:
        runner = _runner()
        with pytest.raises(ProviderPlanError, match="invalid"):
            runner.run("../outside")
        with pytest.raises(ProviderPlanError, match=r"config\.json"):
            runner.run("guard-missing")


class TestExecution:
    @patch("subprocess.run")
    def test_command_pins_network_platform_and_forces_cleanup(self, run: MagicMock) -> None:
        _bundle("guard-unit")

        def invoke(command: tuple[str, ...], **kwargs: object) -> MagicMock:
            if "run" in command:
                output = kwargs["stdout"]
                assert isinstance(output, io.BufferedIOBase)
                output.write(b"ok\n")
            return MagicMock(returncode=0)

        run.side_effect = invoke
        result = _runner().run("guard-unit")
        command = run.call_args_list[0].args[0]
        assert command[command.index("--network") + 1] == "none"
        assert command[command.index("--platform") + 1] == "systrap"
        assert command[-3:] == (
            "--bundle",
            str((_BUNDLES / "guard-unit").resolve()),
            "guard-unit",
        )
        cleanup = run.call_args_list[1].args[0]
        assert cleanup[-3:] == ("delete", "--force", "guard-unit")
        assert result.exit_code == 0
        assert result.cleanup_complete is True
        assert result.stdout_bytes == 3

    @patch("subprocess.run")
    def test_timeout_is_terminal_and_cleanup_runs(self, run: MagicMock) -> None:
        _bundle("guard-timeout")

        def invoke(command: tuple[str, ...], **kwargs: object) -> MagicMock:
            if "run" in command:
                output = kwargs["stdout"]
                assert isinstance(output, io.BufferedIOBase)
                output.write(b"partial")
                raise __import__("subprocess").TimeoutExpired(("runsc",), 1)
            return MagicMock(returncode=0)

        run.side_effect = invoke
        result = _runner().run("guard-timeout", timeout_seconds=1)
        assert result.timed_out is True
        assert result.exit_code == 124
        assert result.cleanup_complete is True
        assert run.call_count == 2

    @patch("subprocess.run")
    def test_output_capture_is_hard_bounded(self, run: MagicMock) -> None:
        _bundle("guard-output")

        def invoke(command: tuple[str, ...], **kwargs: object) -> MagicMock:
            if "run" in command:
                output = kwargs["stdout"]
                assert isinstance(output, io.BufferedIOBase)
                output.write(b"x" * 2_097_152)
            return MagicMock(returncode=0)

        run.side_effect = invoke
        result = _runner().run("guard-output")
        assert result.stdout_bytes == 1_048_576

    @patch("subprocess.run")
    def test_cancel_is_idempotent_and_validated(self, run: MagicMock) -> None:
        run.side_effect = (
            MagicMock(returncode=128),
            MagicMock(returncode=128),
        )
        runner = _runner()
        assert runner.cancel("guard-cancelled") is True
        with pytest.raises(ProviderPlanError, match="invalid"):
            runner.cancel("workspace-controlled/id")


@pytest.mark.skipif(
    os.environ.get("HOL_GUARD_RUNSC_INTEGRATION") != "1",
    reason="requires pinned Linux runsc + busybox-static",
)
class TestRealRunscIsolation:
    @staticmethod
    def _materialize(name: str, script: str) -> GVisorReferenceRuntime:
        runsc_source = Path(os.environ["HOL_GUARD_RUNSC_PATH"])
        busybox_source = Path(os.environ["HOL_GUARD_BUSYBOX_PATH"])
        root = Path("/tmp/hol-guard-test")
        root.mkdir(parents=True, exist_ok=True)
        runsc = root / "runsc"
        shutil.copy2(runsc_source, runsc)
        runsc.chmod(0o755)
        bundle = root / "bundles" / name
        rootfs = bundle / "rootfs"
        (rootfs / "bin").mkdir(parents=True, exist_ok=True)
        for directory in ("dev", "proc", "tmp", "var/run"):
            (rootfs / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(busybox_source, rootfs / "bin" / "busybox")
        config = {
            "ociVersion": "1.0.2",
            "process": {
                "terminal": False,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/busybox", "sh", "-c", script],
                "env": ["PATH=/bin"],
                "cwd": "/",
                "capabilities": {
                    "bounding": [],
                    "effective": [],
                    "inheritable": [],
                    "permitted": [],
                    "ambient": [],
                },
                "noNewPrivileges": True,
            },
            "root": {"path": "rootfs", "readonly": True},
            "hostname": "guard-sandbox",
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc"},
                {
                    "destination": "/dev",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
                },
                {
                    "destination": "/tmp",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": ["nosuid", "nodev", "noexec", "mode=1777", "size=4096k"],
                },
            ],
            "linux": {
                "resources": {
                    "memory": {"limit": 268435456},
                    "pids": {"limit": 128},
                    "cpu": {"quota": 50000, "period": 100000},
                },
                "namespaces": [
                    {"type": "pid"},
                    {"type": "network"},
                    {"type": "ipc"},
                    {"type": "uts"},
                    {"type": "mount"},
                    {"type": "cgroup"},
                ],
                "maskedPaths": ["/proc/kcore", "/proc/keys", "/proc/timer_list"],
                "readonlyPaths": [
                    "/proc/asound",
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys",
                    "/proc/sysrq-trigger",
                ],
            },
        }
        bundle.mkdir(parents=True, exist_ok=True)
        (bundle / "config.json").write_text(json.dumps(config), encoding="utf-8")
        digest = hashlib.sha256(runsc.read_bytes()).hexdigest()
        return GVisorReferenceRuntime(
            runsc_path=str(runsc),
            runsc_digest=digest,
            bundle_root=str(root / "bundles"),
            state_root=str(root / "state"),
        )

    def test_breakout_secret_socket_privilege_and_network_denied(self) -> None:
        script = " && ".join(
            (
                "! touch /host-breakout",
                'test "${HOST_SECRET-unset}" = unset',
                "test ! -S /var/run/docker.sock",
                "! mount -t tmpfs tmpfs /tmp",
                "! wget -q -T 2 -O- http://169.254.169.254/latest/meta-data/",
                'printf "assurance-ok\\n"',
            )
        )
        runner = self._materialize("guard-breakout", script)
        result = runner.run("guard-breakout", timeout_seconds=20)
        expected = framed_digest("guard.runsc-stdout.v1", {"bytes": b"assurance-ok\n".hex()})
        assert result.exit_code == 0
        assert result.stdout_digest == expected
        assert result.cleanup_complete is True
        assert not (_BUNDLES / "host-breakout").exists()

    def test_runtime_crash_and_timeout_are_cleaned(self) -> None:
        crash = self._materialize("guard-crash", "kill -SEGV $$")
        crash_result = crash.run("guard-crash", timeout_seconds=10)
        assert crash_result.exit_code != 0
        assert crash_result.cleanup_complete is True

        timeout = self._materialize("guard-sleep", "sleep 10")
        timeout_result = timeout.run("guard-sleep", timeout_seconds=1)
        assert timeout_result.timed_out is True
        assert timeout_result.cleanup_complete is True
