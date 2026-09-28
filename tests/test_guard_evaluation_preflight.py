from __future__ import annotations

import io
import os
import platform
import shlex
import stat
import sys
import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace
from urllib.request import Request, urlopen

import pytest

from codex_plugin_scanner.guard import evaluation_preflight as preflight_module
from codex_plugin_scanner.guard.adapters import hook_python_subprocess as probe_module
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationResult
from codex_plugin_scanner.guard.evaluation_preflight import (
    EvaluationSetup,
    cleanup_interrupted_evaluation_setup,
    preflight_evaluation,
    setup_evaluation,
)
from codex_plugin_scanner.guard.evaluation_witness import LocalSideEffectWitness


def test_windows_job_cleanup_serializes_only_the_owned_probe() -> None:
    entered = Event()
    release = Event()
    attempted = Event()
    terminated = Event()
    other_closed = Event()
    calls: list[str] = []

    class BlockingJob:
        def close(self) -> None:
            calls.append("closing")
            entered.set()
            assert release.wait(timeout=2)
            calls.append("closed")

        def terminate(self) -> None:
            calls.append("terminated")
            terminated.set()

    owned = probe_module._ProbeWindowsJob(BlockingJob())
    other = probe_module._ProbeWindowsJob(SimpleNamespace(close=other_closed.set))

    def terminate_owned() -> None:
        attempted.set()
        owned.terminate()

    threads = [Thread(target=owned.close), Thread(target=terminate_owned), Thread(target=other.close)]
    started: list[Thread] = []
    try:
        threads[0].start()
        started.append(threads[0])
        assert entered.wait(timeout=1)
        threads[1].start()
        started.append(threads[1])
        assert attempted.wait(timeout=1)
        threads[2].start()
        started.append(threads[2])
        assert other_closed.wait(timeout=1)
        assert not terminated.wait(timeout=0.05)
    finally:
        release.set()
        for thread in started:
            thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in started)
    assert calls == ["closing", "closed", "terminated"]


def _host_os() -> str:
    value = platform.system().lower()
    return "macos" if value == "darwin" else value


def _host_architecture() -> str:
    value = platform.machine().lower().replace("-", "_")
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(value, value)


def _fake_host(tmp_path: Path, *, version: str = "0.1.0") -> Path:
    executable = tmp_path / "synthetic-agent"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        f"  printf '%s\\n' 'synthetic-agent {version}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _profile(tmp_path: Path, executable: Path | None = None) -> dict[str, object]:
    root = tmp_path
    endpoint = "http://127.0.0.1:8765/receiver"
    artifact_digest = "sha256:" + sha256(b"synthetic artifact").hexdigest()
    host_identity: dict[str, object] = {
        "product": "synthetic-agent",
        "version": "0.1.0",
        "os": _host_os(),
        "architecture": _host_architecture(),
        "runtimeLocation": "local",
        "requiredPrivilege": "administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user",
    }
    if executable is not None:
        host_identity["executable"] = str(executable)
    return {
        "schemaVersion": "guard.evaluation-profile.v1",
        "profileId": "synthetic-local-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.4.2",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": host_identity,
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.4.2",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "d" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root)],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.shell", "expectedAction": "block"},
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _artifact(tmp_path: Path) -> Path:
    path = tmp_path / "core-fixture.bin"
    path.write_bytes(b"synthetic artifact")
    return path


def _artifact_paths(path: Path) -> dict[str, Path]:
    return {"core-fixture": path}


@pytest.mark.parametrize(
    "settings",
    [
        {"timeout_seconds": True},
        {"timeout_seconds": "bad"},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": 3601},
        {"output_limit_bytes": True},
        {"output_limit_bytes": "bad"},
        {"output_limit_bytes": 1.0},
        {"output_limit_bytes": 0},
        {"output_limit_bytes": -1},
        {"output_limit_bytes": 131073},
    ],
)
def test_invalid_probe_budget_never_spawns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, settings: dict[str, object]
) -> None:
    def unexpected_spawn(*_args: object, **_kwargs: object) -> object:
        pytest.fail("invalid budget attempted process execution")

    monkeypatch.setattr(probe_module, "subprocess", SimpleNamespace(Popen=unexpected_spawn))

    with pytest.raises(ValueError, match="invalid probe"):
        probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, **settings)  # type: ignore[arg-type]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process-group cleanup")
@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_posix_capture_failure_reaps_owned_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    original = probe_module.subprocess
    processes = []

    def spawn(*args: object, **kwargs: object) -> object:
        process = original.Popen(*args, **kwargs)
        processes.append(process)
        return process

    class BrokenSelector:
        def __enter__(self) -> object:
            raise error_type("synthetic private diagnostic")

        def __exit__(self, *_args: object) -> None:
            pass

    monkeypatch.setattr(probe_module, "selectors", SimpleNamespace(DefaultSelector=BrokenSelector))
    monkeypatch.setattr(
        probe_module,
        "subprocess",
        SimpleNamespace(
            Popen=spawn, PIPE=original.PIPE, DEVNULL=original.DEVNULL, TimeoutExpired=original.TimeoutExpired
        ),
    )

    result = probe_module.run_probe(
        [sys.executable, "-I", "-c", "import time; time.sleep(3)"], cwd=tmp_path, env={}, timeout_seconds=1
    )

    assert result.capture_incomplete
    assert result.returncode != 0
    assert len(processes) == 1
    assert processes[0].returncode is not None
    assert processes[0].stdout.closed and processes[0].stderr.closed


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_windows_stdin_failure_kills_process_when_job_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    calls: list[str] = []

    class BrokenStdin:
        def close(self) -> None:
            raise error_type("synthetic private diagnostic")

    def failed_job_operation() -> None:
        raise OSError("synthetic job failure")

    process = SimpleNamespace(
        stdin=BrokenStdin(), kill=lambda: calls.append("kill"), wait=lambda **_kwargs: calls.append("wait")
    )
    job = SimpleNamespace(close=failed_job_operation, terminate=failed_job_operation)
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))

    with pytest.raises(RuntimeError, match="guard_hook_python_probe_execution_failed"):
        probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={})
    assert calls == ["kill", "wait"]


@pytest.mark.parametrize("reap_expires", [False, True])
def test_windows_timeout_has_bounded_reap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reap_expires: bool) -> None:
    calls: list[str] = []
    deadlines: list[float] = []
    timeout_error = probe_module.subprocess.TimeoutExpired

    def wait(*, timeout: float) -> int:
        deadlines.append(timeout)
        if len(deadlines) == 1 or reap_expires:
            raise timeout_error("synthetic-agent", timeout)
        process.returncode = -9
        return -9

    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO(), returncode=None, wait=wait)
    job = SimpleNamespace(terminate=lambda: calls.append("terminate"), close=lambda: calls.append("close"))
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))

    result = probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, timeout_seconds=0.1)

    assert result.timed_out
    assert result.capture_incomplete is reap_expires
    assert len(deadlines) == 2 and all(0 < timeout <= 1 for timeout in deadlines)
    assert calls == ["terminate", "close"]


def test_windows_probe_interrupt_closes_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def wait(**_kwargs: object) -> int:
        raise KeyboardInterrupt

    process = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO(), returncode=0, wait=wait)
    job = SimpleNamespace(terminate=lambda: calls.append("terminate"), close=lambda: calls.append("close"))
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))

    with pytest.raises(KeyboardInterrupt):
        probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={})

    assert calls == ["close"]


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_windows_probe_requires_job_assignment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise error_type("synthetic private diagnostic")

    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", unavailable)

    with pytest.raises(RuntimeError, match=r"^guard_hook_python_probe_execution_failed$"):
        probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={})


@pytest.mark.parametrize(("close_fails", "terminate_fails"), [(False, False), (True, False), (True, True)])
def test_windows_probe_job_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, close_fails: bool, terminate_fails: bool
) -> None:
    calls: list[str] = []

    def close() -> None:
        calls.append("close")
        if close_fails:
            raise OSError("synthetic private diagnostic")

    def terminate() -> None:
        calls.append("terminate")
        if terminate_fails:
            raise OSError("synthetic private diagnostic")

    process = SimpleNamespace(
        stdin=io.BytesIO(),
        stdout=io.BytesIO(b"synthetic-agent 0.1.0\n"),
        stderr=io.BytesIO(),
        returncode=0,
        wait=lambda **_kwargs: 0,
    )
    process.kill = lambda: calls.append("kill")
    job = SimpleNamespace(terminate=terminate, close=close)
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))

    result = probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, timeout_seconds=1)

    assert process.stdin.closed
    assert result.stdout == b"synthetic-agent 0.1.0\n"
    assert result.capture_incomplete is close_fails
    expected = ["close", "terminate", "close", "kill"] if terminate_fails else ["close", "terminate"]
    assert calls == (expected if close_fails else ["close"])


@pytest.mark.parametrize("terminate_fails", [False, True])
def test_windows_probe_overflow_terminates_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminate_fails: bool
) -> None:
    calls: list[str] = []

    def terminate() -> None:
        calls.append("terminate")
        if terminate_fails:
            raise OSError("synthetic private diagnostic")

    process = SimpleNamespace(
        stdin=io.BytesIO(),
        stdout=io.BytesIO(b"x" * 10000),
        stderr=io.BytesIO(),
        returncode=0,
        wait=lambda **_kwargs: 0,
    )
    process.kill = lambda: calls.append("kill")
    job = SimpleNamespace(terminate=terminate, close=lambda: calls.append("close"))
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(probe_module, "spawn_windows_hook_process", lambda *_args, **_kwargs: (process, job))

    result = probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, output_limit_bytes=4096)

    assert result.output_overflow
    assert len(result.stdout) <= 4096
    assert "terminate" in calls
    assert "close" in calls
    assert result.capture_incomplete is terminate_fails
    if terminate_fails:
        assert calls.index("close") < calls.index("kill")


def test_threaded_probe_read_failure_is_not_complete_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenStream(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise OSError("synthetic private diagnostic")

    process = SimpleNamespace(
        stdin=io.BytesIO(),
        stdout=io.BytesIO(b"synthetic-agent 0.1.0\n"),
        stderr=BrokenStream(),
        returncode=0,
        wait=lambda **_kwargs: 0,
    )
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        probe_module,
        "spawn_windows_hook_process",
        lambda *_args, **_kwargs: (process, SimpleNamespace(terminate=lambda: None, close=lambda: None)),
    )
    monkeypatch.setattr(
        probe_module,
        "subprocess",
        SimpleNamespace(Popen=lambda *_args, **_kwargs: process, PIPE=-1, DEVNULL=-3),
    )

    result = probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, timeout_seconds=0.1)

    assert result.capture_incomplete
    assert result.stdout == b"synthetic-agent 0.1.0\n"
    assert result.stderr == b""


def test_threaded_probe_late_capture_remains_incomplete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]

    class DelayedReader:
        def __init__(self, *, target: Callable[..., None], args: tuple[object, ...], daemon: bool) -> None:
            self.target = target
            self.args = args
            self.alive = True

        def start(self) -> None:
            pass

        def join(self, timeout: float) -> None:
            if timeout > 0.5:
                self.target(*self.args)
                self.alive = False

        def is_alive(self) -> bool:
            return self.alive

    def wait(**_kwargs: object) -> int:
        clock[0] = 0.1
        return 0

    process = SimpleNamespace(
        stdin=io.BytesIO(), stdout=io.BytesIO(b"synthetic-agent 0.1.0\n"), stderr=io.BytesIO(), returncode=0, wait=wait
    )
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        probe_module,
        "spawn_windows_hook_process",
        lambda *_args, **_kwargs: (process, SimpleNamespace(terminate=lambda: None, close=lambda: None)),
    )
    monkeypatch.setattr(probe_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(
        probe_module, "threading", SimpleNamespace(Event=probe_module.threading.Event, Thread=DelayedReader)
    )
    monkeypatch.setattr(
        probe_module, "subprocess", SimpleNamespace(Popen=lambda *_args, **_kwargs: process, PIPE=-1, DEVNULL=-3)
    )

    result = probe_module.run_probe(["synthetic-agent"], cwd=tmp_path, env={}, timeout_seconds=0.1)

    assert result.capture_incomplete
    assert result.stdout == b"synthetic-agent 0.1.0\n"


@pytest.mark.skipif(os.name == "nt", reason="synthetic executable uses a POSIX shebang")
@pytest.mark.parametrize("writes", [((1, 131072),), ((2, 131072),), ((1, 3000), (2, 3000))])
def test_host_version_probe_rejects_output_beyond_profile_budget(
    tmp_path: Path, writes: tuple[tuple[int, int], ...]
) -> None:
    executable = tmp_path / "synthetic-agent"
    executable.write_text(
        f"#!{sys.executable}\nimport os\nos.write(1, b'synthetic-agent 0.1.0\\n')\n"
        + "".join(f"os.write({descriptor}, b'x' * {size})\n" for descriptor, size in writes),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    profile = _profile(tmp_path, executable)
    profile["resourceLimits"]["maxOutputBytes"] = 4096  # type: ignore[index]
    report = preflight_evaluation(
        profile, artifact_paths=_artifact_paths(_artifact(tmp_path)), allow_host_execution=True
    )

    assert report.status == "blocked_environment"
    assert report.reason == "host_version_output_limit"
    assert "xxxxxxxx" not in str(report.to_dict())


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX process-group cleanup")
def test_host_version_deadline_stops_child_holding_output_pipe(tmp_path: Path) -> None:
    effect = tmp_path / "delayed-child-effect"
    started = tmp_path / "child-started"
    executable = tmp_path / "synthetic-agent"
    executable.write_text(
        "#!/bin/sh\n"
        f"(/bin/sleep 3; printf '%s' 'child ran' > {shlex.quote(str(effect))}) &\n"
        f"printf '%s' 'started' > {shlex.quote(str(started))}\n"
        "printf '%s\\n' 'synthetic-agent 0.1.0'\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    report = preflight_evaluation(
        _profile(tmp_path, executable), artifact_paths=_artifact_paths(_artifact(tmp_path)), allow_host_execution=True
    )

    assert started.exists(), report.reason
    assert report.status == "blocked_environment"
    assert report.reason == "host_version_timeout"
    time.sleep(3.1)
    assert not effect.exists()


def test_preflight_validates_host_and_artifact_without_running_scenarios(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    report = preflight_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        allow_host_execution=True,
    )

    assert report.status == "passed"
    assert report.phase == "preflight"
    assert report.owned_root is None
    assert report.to_dict()["status"] == "passed"
    assert all(check["status"] == "passed" for check in report.checks)
    assert any(check["name"] == "network_scope_declaration" for check in report.checks)
    assert any(check["name"] == "privilege" for check in report.checks)


def test_preflight_rejects_unavailable_required_privilege(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    host = profile["hostIdentity"]
    assert isinstance(host, dict)
    host["requiredPrivilege"] = "standard_user" if host["requiredPrivilege"] == "administrator" else "administrator"
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))
    assert report.status == "blocked_environment"
    assert report.reason == "privilege_mismatch"


@pytest.mark.parametrize(("elevated", "expected"), [(False, "standard_user"), (True, "administrator")])
def test_windows_privilege_detection(monkeypatch: pytest.MonkeyPatch, elevated: bool, expected: str) -> None:
    import ctypes

    monkeypatch.setattr(preflight_module, "os", SimpleNamespace(name="nt"))
    shell = SimpleNamespace(IsUserAnAdmin=lambda: int(elevated))
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(shell32=shell), raising=False)
    assert preflight_module._observed_privilege() == expected


def test_unobservable_privilege_is_not_reported_as_a_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    monkeypatch.setattr(preflight_module, "_observed_privilege", lambda: "unknown")
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact))
    assert report.status == "not_run"
    assert report.reason == "privilege_unobservable"


def test_host_binary_is_not_executed_by_default(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    marker = tmp_path / "host-ran"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    artifact = _artifact(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact))
    assert report.status == "not_run"
    assert report.reason == "isolated_host_execution_not_enabled"
    assert not marker.exists()


def test_missing_host_is_blocked_without_reading_or_creating_setup(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, tmp_path / "does-not-exist")
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "host_executable_missing"
    assert report.to_dict()["status"] == "blocked_environment"
    assert report.owned_root is None


def test_undeclared_host_returns_not_run(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path)
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))

    assert report.status == "not_run"
    assert report.reason == "host_executable_not_declared"


def test_mismatched_os_is_blocked_before_host_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    expected_os = str(profile["hostIdentity"]["os"])  # type: ignore[index]
    mismatch = "windows" if expected_os != "windows" else "linux"
    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_preflight.platform.system", lambda: mismatch)

    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact))

    assert report.status == "blocked_environment"
    assert report.reason == "os_mismatch"
    assert any(check.get("name") == "os" and check.get("status") == "blocked_environment" for check in report.checks)


def test_mismatched_host_version_is_blocked(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    profile["hostIdentity"]["version"] = "9.9.9"  # type: ignore[index]

    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "host_version_mismatch"


@pytest.mark.parametrize("printed,expected", [("v0.1.0", "0.1.0"), ("0.1.0", "v0.1.0")])
def test_common_v_prefixed_host_versions_match(tmp_path: Path, printed: str, expected: str) -> None:
    executable = _fake_host(tmp_path, version=printed)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    profile["hostIdentity"]["version"] = expected  # type: ignore[index]
    report = preflight_evaluation(profile, artifact_paths=_artifact_paths(artifact), allow_host_execution=True)
    assert report.status == "passed"


def test_missing_artifact_is_blocked_after_host_checks(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), artifact_paths={}, allow_host_execution=True)

    assert report.status == "blocked_environment"
    assert report.reason == "artifact_missing"
    assert any(check.get("name") == "artifact:core-fixture" for check in report.checks)


def test_missing_artifact_mapping_is_not_run(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    report = preflight_evaluation(_profile(tmp_path, executable), allow_host_execution=True)

    assert report.status == "not_run"
    assert report.reason == "artifact_paths_not_supplied"


def test_wrong_artifact_bytes_block_setup(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    artifact.write_bytes(b"different artifact")
    report = preflight_evaluation(
        _profile(tmp_path, executable), artifact_paths=_artifact_paths(artifact), allow_host_execution=True
    )
    assert report.status == "blocked_environment"
    assert report.reason == "artifact_digest_mismatch"


def test_setup_is_private_and_cleanup_preserves_unrelated_files(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"keep this file")
    profile = _profile(tmp_path, executable)

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )

    assert isinstance(setup, EvaluationSetup)
    assert setup.report.status == "passed"
    assert setup.root_path is not None
    assert setup.root_path.is_relative_to(tmp_path)
    assert setup.guard_home is not None and setup.guard_home.is_dir()
    assert setup.workspace is not None and setup.workspace.is_dir()
    assert stat.S_IMODE(setup.root_path.stat().st_mode) == 0o700
    assert stat.S_IMODE(setup.guard_home.stat().st_mode) == 0o700
    assert stat.S_IMODE(setup.workspace.stat().st_mode) == 0o700
    owned_root = setup.root_path
    assert owned_root.name.startswith("hol-guard-eval-")
    assert unrelated.read_bytes() == b"keep this file"

    assert setup.cleanup() is True
    assert not owned_root.exists()
    assert unrelated.read_bytes() == b"keep this file"


def test_cleanup_rejects_a_tampered_ownership_marker(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    setup = setup_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    marker.write_text("foreign", encoding="utf-8")

    with pytest.raises(ValueError, match="ownership marker"):
        setup.cleanup()
    assert setup.root_path.exists()
    setup.root_path.joinpath(".hol-guard-evaluation-owned").write_text(  # type: ignore[union-attr]
        setup.marker_token or "", encoding="utf-8"
    )
    assert setup.cleanup() is True


def test_interrupted_cleanup_requires_retained_token_and_preserves_unrelated_files(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    unrelated = tmp_path / "user-config.json"
    unrelated.write_bytes(b'{"keep":"unchanged"}\n')
    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None and setup.marker_token is not None
    owned_root, token = setup.root_path, setup.marker_token
    del setup  # Model process loss: only the separately retained handle survives.

    wrong_token = ("0" if token[0] != "0" else "1") + token[1:]
    with pytest.raises(ValueError, match="ownership marker"):
        cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=wrong_token)
    assert owned_root.is_dir()
    assert unrelated.read_bytes() == b'{"keep":"unchanged"}\n'

    assert cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=token) is True
    assert not owned_root.exists()
    assert unrelated.read_bytes() == b'{"keep":"unchanged"}\n'
    assert cleanup_interrupted_evaluation_setup(profile, owned_root=owned_root, marker_token=token) is False


def test_interrupted_cleanup_rejects_another_profile_parent(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    profile = _profile(tmp_path, executable)
    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.root_path is not None and setup.marker_token is not None
    other_parent = tmp_path / "other-private-parent"
    other_parent.mkdir(mode=0o700)
    other_profile = _profile(tmp_path, executable)
    scope = other_profile["targetScope"]
    assert isinstance(scope, dict)
    scope["rootPath"] = str(other_parent)
    scope["allowedPaths"] = [str(other_parent)]

    with pytest.raises(ValueError, match="outside the profile target scope"):
        cleanup_interrupted_evaluation_setup(other_profile, owned_root=setup.root_path, marker_token=setup.marker_token)
    assert setup.root_path.exists()
    assert setup.cleanup() is True


def test_interrupted_cleanup_rejects_a_symlink_to_unrelated_state(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation may require elevated Windows privileges")
    unrelated = tmp_path / "unrelated-state"
    unrelated.mkdir()
    marker = unrelated / "user-config.json"
    marker.write_bytes(b"preserve")
    link = tmp_path / "hol-guard-eval-link"
    link.symlink_to(unrelated, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symlink"):
        cleanup_interrupted_evaluation_setup(_profile(tmp_path), owned_root=link, marker_token="0" * 32)
    assert marker.read_bytes() == b"preserve"


def test_setup_rejects_non_temporary_parent_without_touching_it(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("preserve", encoding="utf-8")
    profile = _profile(tmp_path, executable)
    unsafe_parent = Path(os.environ.get("HOME", "/"))

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=unsafe_parent,
        allow_host_execution=True,
    )

    assert setup.report.status == "blocked_environment"
    assert setup.report.reason == "setup_parent_outside_profile_scope"
    assert unrelated.read_text(encoding="utf-8") == "preserve"


def test_setup_rejects_publicly_writable_temporary_parent(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode check")
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    parent = tmp_path / "public-parent"
    parent.mkdir()
    parent.chmod(0o777)
    profile = _profile(tmp_path, executable)
    scope = profile["targetScope"]
    assert isinstance(scope, dict)
    scope["rootPath"] = str(parent)
    scope["allowedPaths"] = [str(parent / "workspace")]

    setup = setup_evaluation(
        profile,
        artifact_paths=_artifact_paths(artifact),
        parent_dir=parent,
        allow_host_execution=True,
    )
    assert setup.report.status == "blocked_environment"
    assert setup.report.reason == "setup_parent_outside_profile_scope"
    assert list(parent.iterdir()) == []


def test_witness_uses_owned_setup_workspace_and_rejects_tampered_owner(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact = _artifact(tmp_path)
    setup = setup_evaluation(
        _profile(tmp_path, executable),
        artifact_paths=_artifact_paths(artifact),
        parent_dir=tmp_path,
        allow_host_execution=True,
    )
    assert setup.workspace is not None and setup.root_path is not None and setup.marker_token is not None
    with LocalSideEffectWitness(setup=setup) as witness:
        assert witness.root.parent == setup.workspace
        assert witness.check_file_ready()
    marker = setup.root_path / ".hol-guard-evaluation-owned"
    marker.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="owned evaluation setup"), LocalSideEffectWitness(setup=setup):
        pass
    marker.write_text(setup.marker_token, encoding="utf-8")
    assert setup.cleanup() is True


def test_predeclared_network_pair_can_bind_a_profile_and_setup(tmp_path: Path) -> None:
    executable = _fake_host(tmp_path)
    artifact_path = _artifact(tmp_path)
    with LocalSideEffectWitness() as witness:
        pair = witness.new_network_pair()
        profile = _profile(tmp_path, executable)
        profile["expectedCapabilities"] = [{"capabilityId": "synthetic.network", "expectedAction": "block"}]
        profile["network"]["allowedEndpoints"] = [pair.denied_url, pair.allowed_url]  # type: ignore[index]
        profile["targetScope"]["allowedEndpoints"] = [pair.denied_url, pair.allowed_url]  # type: ignore[index]
        setup = setup_evaluation(
            profile,
            artifact_paths=_artifact_paths(artifact_path),
            parent_dir=tmp_path,
            allow_host_execution=True,
        )
        assert setup.report.status == "passed"
        try:
            assert witness.check_network_ready()
            with urlopen(Request(pair.allowed_url, data=b"", method="POST"), timeout=2) as response:
                assert response.status == 204
            observation = witness.observe_network_pair(pair)
            assert observation.receiver_conditions_met
            artifact = profile["installedArtifacts"][0]  # type: ignore[index]
            result = {
                "schemaVersion": "guard.evaluation-result.v1",
                "resultId": "network-result",
                "profileId": profile["profileId"],
                "buildIdentity": profile["buildIdentity"],
                "artifactIdentity": artifact,
                "evidenceIdentity": {
                    "evidenceId": "network-evidence",
                    "proofRunId": "network-run",
                    "evidenceType": "live_installed_host_test",
                    "artifactDigest": artifact["digest"],
                },
                "status": "passed",
                "startedAt": "2026-09-23T12:00:00Z",
                "finishedAt": "2026-09-23T12:00:01Z",
                "cases": [
                    {
                        "caseId": "synthetic.network",
                        "status": "passed",
                        "expectedAction": "block",
                        "observedAction": "block",
                        "proofType": "live_installed_host_test",
                        "witness": {
                            "kind": "loopback_receiver",
                            "endpoint": pair.denied_url,
                            "allowedEndpoint": pair.allowed_url,
                            "receiverReady": observation.receiver_ready,
                            "deniedReached": observation.denied_reached,
                            "allowedReached": observation.allowed_reached,
                        },
                    }
                ],
            }
            assert EvaluationResult.from_dict(result, profile=profile).to_dict() == result
        finally:
            assert setup.cleanup() is True
