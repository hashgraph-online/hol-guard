"""Opt-in client stderr stages, observed after failure rather than at the deadline.

The installed package and framed stdout protocol are unchanged. Only this probe
context opts its actual client-stream children into bounded, fixed Rust labels.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from types import ModuleType
from typing import BinaryIO, cast

from codex_plugin_scanner.guard import native_resident_stream

_ENVIRONMENT_KEY = "HOL_GUARD_NATIVE_CLIENT_STAGE_DIAGNOSTIC"
_PREFIX = b"guard_native_client_stage_v1="
_STAGES = (
    "stream_entry",
    "lease_acquired",
    "frame_read",
    "request_entry",
    "discovery",
    "startup_lock",
    "spawn",
    "connect",
    "authenticate",
    "request_written",
    "response_received",
    "frame_written",
    "lease_directory_ready",
    "lease_process_identified",
    "lease_runtime_hashed",
    "lease_nonce_ready",
    "lease_directory_lock_acquired",
    "lease_file_ready",
    "lease_durable",
    "lease_refused",
)
_LINES = {_PREFIX + stage.encode("ascii"): stage for stage in _STAGES}
_MAX_STREAMS = 4
_MAX_LINE_BYTES = 64


class _Stages:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stages: list[str] = []
        self.partial = bytearray()
        self.discarding = False

    def feed(self, chunk: bytes) -> None:
        # The actual reader supplies at most 256 bytes. Long/unterminated and
        # unknown lines exist only in the bounded partial buffer, never reports.
        for byte in chunk:
            if byte == 10:
                stage = None if self.discarding else _LINES.get(bytes(self.partial))
                self.partial.clear()
                self.discarding = False
                if stage is not None:
                    with self.lock:
                        if stage not in self.stages:
                            self.stages.append(stage)
            elif not self.discarding:
                if len(self.partial) == _MAX_LINE_BYTES:
                    self.partial.clear()
                    self.discarding = True
                else:
                    self.partial.append(byte)

    def read(self, pipe: BinaryIO) -> None:
        try:
            while chunk := os.read(pipe.fileno(), 256):
                self.feed(chunk)
        except (OSError, ValueError):
            pass
        finally:
            with suppress(Exception):
                pipe.close()
            self.partial.clear()

    def snapshot(self) -> list[str]:
        with self.lock:
            return list(self.stages)


class ClientStageObservation:
    def __init__(self) -> None:
        self._streams: list[_Stages] = []
        self._lock = threading.Lock()

    def reserve(self) -> _Stages | None:
        with self._lock:
            if len(self._streams) >= _MAX_STREAMS:
                return None
            stages = _Stages()
            self._streams.append(stages)
            return stages

    def report_failure(self) -> None:
        with suppress(BaseException):
            with self._lock:
                streams = [stages.snapshot() for stages in self._streams]
            print(
                json.dumps(
                    {
                        "schema": "guard.native-client-stage-observation.v1",
                        "observation": "post_failure",
                        "timing_claim": False,
                        "stage_semantics": "first_observations_per_stream",
                        "empty_stream_semantics": "unavailable_evidence",
                        "streams": streams,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )


class _SubprocessProxy(ModuleType):
    def __init__(self, original: ModuleType, observation: ClientStageObservation) -> None:
        super().__init__(original.__name__)
        self._original = original
        self._observation = observation

    def __getattr__(self, name: str) -> object:
        return getattr(self._original, name)

    def _popen(self, *args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        stages = None
        argv = args[0] if len(args) == 1 else None
        env = kwargs.get("env")
        if (
            isinstance(argv, (tuple, list))
            and len(argv) == 4
            and tuple(argv[1:3]) == ("resident-client-stream", "--stdin")
            and kwargs.get("stderr") == subprocess.DEVNULL
            and isinstance(env, dict)
        ):
            stages = self._observation.reserve()
        if stages is not None:
            kwargs = dict(
                kwargs, env=dict(cast(dict[str, str], env), **{_ENVIRONMENT_KEY: "1"}), stderr=subprocess.PIPE
            )
        launch = cast(Callable[..., subprocess.Popen[bytes]], self._original.Popen)
        process = launch(*args, **kwargs)
        if stages is not None and process.stderr is not None:
            # Never wait for observation or alter the client process lifetime.
            # This bounded drain ends on EOF from the normal publisher cleanup.
            try:
                threading.Thread(target=stages.read, args=(process.stderr,), daemon=True).start()
            except Exception:
                with suppress(Exception):
                    process.stderr.close()
        return cast(subprocess.Popen[bytes], process)

    Popen = _popen


@contextmanager
def observe_client_stages() -> Iterator[ClientStageObservation]:
    observation = ClientStageObservation()
    original = native_resident_stream.subprocess
    native_resident_stream.subprocess = _SubprocessProxy(original, observation)
    try:
        yield observation
    finally:
        native_resident_stream.subprocess = original
