"""Failure cleanup and census bounds for the owned native lifecycle fixture."""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ci.native_runtime import native_phase_lifecycle_support as support
from scripts.native_slo_rust_phase_receiver import supported

pytestmark = pytest.mark.skipif(not supported(), reason="Linux native diagnostic lifecycle controls")


@pytest.mark.parametrize("stage", ["root", "state", "key", "spawn"])
def test_constructor_failure_closes_pinned_executable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stage: str
) -> None:
    runtime = Path(sys.executable).resolve(strict=True)
    root = tmp_path / "owned-stream"
    opened: list[tuple[support.Executable, int]] = []
    executable = support.Executable
    mkdir = Path.mkdir
    open_descriptor = os.open

    def retain(path: Path) -> support.Executable:
        value = executable(path)
        opened.append((value, value.descriptor))
        return value

    def make_directory(path: Path, *args: Any, **kwargs: Any) -> None:
        if (stage == "root" and path == root) or (stage == "state" and path == root / "native-runtime"):
            raise PermissionError("controlled constructor refusal")
        mkdir(path, *args, **kwargs)

    def open_file(path: Any, *args: Any, **kwargs: Any) -> int:
        if stage == "key" and path == root / "native-runtime" / "policy-verifier.key":
            raise PermissionError("controlled constructor refusal")
        return open_descriptor(path, *args, **kwargs)

    def refuse_spawn(*_args: Any, **_kwargs: Any) -> Any:
        if stage == "spawn":
            raise PermissionError("controlled constructor refusal")
        raise AssertionError("the refused constructor reached native process creation")

    monkeypatch.setattr(support, "Executable", retain)
    monkeypatch.setattr(Path, "mkdir", make_directory)
    monkeypatch.setattr(os, "open", open_file)
    monkeypatch.setattr(support.subprocess, "Popen", refuse_spawn)
    with pytest.raises(PermissionError, match="controlled constructor refusal"):
        support.OwnedNativeStream(runtime, root, {})
    assert len(opened) == 1
    value, descriptor = opened[0]
    assert value.descriptor == -1
    with pytest.raises(OSError) as error:
        os.fstat(descriptor)
    assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("entry_count", [3, 1000])
def test_process_census_stops_before_allocating_past_its_cap(monkeypatch: pytest.MonkeyPatch, entry_count: int) -> None:
    class Census:
        read = 0
        closed = False

        def __enter__(self) -> Census:
            return self

        def __exit__(self, *_args: object) -> None:
            self.closed = True

        def __iter__(self) -> Any:
            for index in range(entry_count):
                self.read += 1
                yield SimpleNamespace(path=f"/proc/{index + 1}")

    census = Census()
    monkeypatch.setattr(support, "MAX_PROC_ENTRIES", 3)
    monkeypatch.setattr(os, "scandir", lambda path: census)
    if entry_count > 3:
        with pytest.raises(AssertionError, match="process census entry cap reached"):
            support._bounded_proc_entries()
        assert census.read == 4
    else:
        assert support._bounded_proc_entries() == [Path("/proc/1"), Path("/proc/2"), Path("/proc/3")]
        assert census.read == 3
    assert census.closed
