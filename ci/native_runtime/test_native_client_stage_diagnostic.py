from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import BinaryIO, cast

import pytest

from ci.native_runtime import native_client_stage_diagnostic as diagnostic
from codex_plugin_scanner.guard import native_resident_stream


def test_bounded_parser_drops_unknown_oversized_unterminated_and_duplicate_lines() -> None:
    stages = diagnostic._Stages()
    lines = tuple(diagnostic._PREFIX + stage.encode() + b"\n" for stage in diagnostic._STAGES)
    assert len(lines) == len(set(lines)) == 20
    assert sum(len(line) for line in lines) == 892
    assert diagnostic._MAX_LINE_BYTES == 64
    assert max(len(line) - 1 for line in lines) <= diagnostic._MAX_LINE_BYTES
    assert diagnostic._MAX_STREAMS == 4
    for _ in range(4096):
        stages.feed(b"synthetic-private-canary" * 10)
        assert len(stages.partial) <= diagnostic._MAX_LINE_BYTES
    stages.feed(b"\n" + diagnostic._PREFIX + b"unknown-private-canary\n")
    for line in lines:
        for byte in line:
            stages.feed(bytes([byte]))
        stages.feed(line)
    assert stages.snapshot() == list(diagnostic._STAGES)
    assert b"canary" not in stages.partial


def test_real_pipe_is_drained_and_closed_without_retaining_private_stderr() -> None:
    stages = diagnostic._Stages()
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('canary'*20000+'\\n'+ "
            "'guard_native_client_stage_v1=frame_read\\n'); print('original-response')",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stderr is not None and process.stdout is not None
    thread = threading.Thread(target=stages.read, args=(process.stderr,))
    thread.start()
    assert process.stdout.read() == b"original-response\n"
    assert process.wait(timeout=5) == 0
    thread.join(timeout=5)
    process.stdout.close()
    assert not thread.is_alive() and process.stderr.closed
    assert stages.snapshot() == ["frame_read"]
    assert not stages.partial


def test_proxy_forwards_unrelated_calls_and_bounds_opt_in_launches() -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    original = ModuleType("subprocess")
    process = object()

    def launch(*args: object, **kwargs: object) -> object:
        calls.append((args, kwargs))
        return process

    vars(original)["Popen"] = launch
    observation = diagnostic.ClientStageObservation()
    proxy = diagnostic._SubprocessProxy(original, observation)
    # Every argument and return identity survives an unrelated launch.
    assert proxy.Popen("unrelated", shell=True, cwd="private-path") is process
    assert calls[-1] == (("unrelated",), {"shell": True, "cwd": "private-path"})
    # No reader is attempted in this seam; the real-pipe test covers draining.
    vars(original)["Popen"] = lambda *args, **kwargs: launch(*args, **kwargs)
    from types import SimpleNamespace

    process = SimpleNamespace(stderr=None)
    argv = ("runtime", "resident-client-stream", "--stdin", "private-home")
    env = {"ORIGINAL": "private-canary"}
    for index in range(5):
        assert proxy.Popen(argv, env=env, stderr=subprocess.DEVNULL, arbitrary="unchanged") is process
        actual = calls[-1][1]
        assert actual["arbitrary"] == "unchanged"
        assert actual["stderr"] == (subprocess.PIPE if index < 4 else subprocess.DEVNULL)
        assert (diagnostic._ENVIRONMENT_KEY in cast(dict[str, str], actual["env"])) is (index < 4)
    assert env == {"ORIGINAL": "private-canary"}
    assert len(observation._streams) == 4


def test_context_restores_original_module_and_preserves_failure_identity(capsys: pytest.CaptureFixture[str]) -> None:
    original = native_resident_stream.subprocess
    error = RuntimeError("private-error-canary")
    with pytest.raises(RuntimeError) as caught, diagnostic.observe_client_stages() as observation:
        assert native_resident_stream.subprocess is not original
        stages = observation.reserve()
        assert stages is not None
        stages.feed(diagnostic._PREFIX + b"authenticate\n")
        observation.report_failure()
        raise error
    assert caught.value is error and native_resident_stream.subprocess is original
    report = json.loads(capsys.readouterr().err)
    assert report == {
        "schema": "guard.native-client-stage-observation.v1",
        "observation": "post_failure",
        "timing_claim": False,
        "stage_semantics": "first_observations_per_stream",
        "empty_stream_semantics": "unavailable_evidence",
        "streams": [["authenticate"]],
    }


def test_success_is_silent_and_report_failure_cannot_raise(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with diagnostic.observe_client_stages():
        pass
    assert capsys.readouterr().err == ""

    def fail(*args: object, **kwargs: object) -> str:
        raise ValueError("private-canary")

    monkeypatch.setattr(diagnostic.json, "dumps", fail)
    diagnostic.ClientStageObservation().report_failure()


def test_actual_client_cleanup_ends_owned_drain_and_preserves_stdout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from queue import Queue

    real_popen = subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []
    observed = threading.Event()
    drained = threading.Event()
    original_read = diagnostic._Stages.read

    def read(stages: diagnostic._Stages, pipe: BinaryIO) -> None:
        try:
            original_read(stages, pipe)
        finally:
            drained.set()

    original_feed = diagnostic._Stages.feed

    def feed(stages: diagnostic._Stages, chunk: bytes) -> None:
        original_feed(stages, chunk)
        if stages.snapshot():
            observed.set()

    def launch(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        command = (
            "import os,sys,struct; "
            "assert os.environ['HOL_GUARD_NATIVE_CLIENT_STAGE_DIAGNOSTIC']=='1'; "
            "sys.stderr.write('private-canary'*10000+'\\n'+'guard_native_client_stage_v1=frame_read\\n'); "
            "sys.stderr.flush(); sys.stdout.buffer.write(struct.pack('!I',2)+b'{}'); "
            "sys.stdout.buffer.flush(); sys.stdin.buffer.read()"
        )
        process = cast(Callable[..., subprocess.Popen[bytes]], real_popen)([sys.executable, "-c", command], **kwargs)
        processes.append(process)
        return process

    module = ModuleType("subprocess")
    vars(module).update(vars(subprocess))
    vars(module)["Popen"] = launch
    monkeypatch.setattr(native_resident_stream, "subprocess", module)
    monkeypatch.setattr(diagnostic._Stages, "read", read)
    monkeypatch.setattr(diagnostic._Stages, "feed", feed)
    with diagnostic.observe_client_stages() as observation:
        client = native_resident_stream._PersistentNativeClient(
            executable=Path(sys.executable),
            state_dir=tmp_path,
            environment={},
        )
        try:
            assert client._start()
            assert observed.wait(5)
            assert cast(Queue[bytes], client._responses).get(timeout=5) == b"{}"
            assert observation._streams[0].snapshot() == ["frame_read"]
        finally:
            client.close()
        assert drained.wait(5)
    assert len(processes) == 1 and processes[0].poll() is not None
    assert processes[0].stderr is not None and processes[0].stderr.closed


def test_original_launch_failure_identity_is_unchanged() -> None:
    original = ModuleType("subprocess")
    error = OSError("synthetic-private-launch-canary")

    def fail(*args: object, **kwargs: object) -> object:
        raise error

    vars(original)["Popen"] = fail
    proxy = diagnostic._SubprocessProxy(original, diagnostic.ClientStageObservation())
    with pytest.raises(OSError) as caught:
        proxy.Popen(("runtime", "resident-client-stream", "--stdin", "home"), env={}, stderr=subprocess.DEVNULL)
    assert caught.value is error
