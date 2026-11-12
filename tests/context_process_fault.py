"""Fault only verified optional descendants of this disposable test process.

Read process metadata and kernel executable identities, never argv, environment,
readiness credentials or resident state. Keep PID/start identities in memory.
Rust must perform normal containment; the final fallback keeps a failed test
from leaking its own paused child and cannot turn that test into a pass.
"""

from __future__ import annotations

import hashlib
import os
import select
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from scripts.cigar_benchmark_processes import kernel_image


@dataclass(frozen=True)
class Row:
    parent: int
    group: int
    start: tuple[str, ...]
    name: str
    state: str

    def same(self, other: Row | None) -> bool:
        return other is not None and (self.parent, self.group, self.start, self.name) == (
            other.parent,
            other.group,
            other.start,
            other.name,
        )


def _snapshot() -> dict[int, Row]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,stat=,lstart=,comm="],
        capture_output=True,
        text=True,
        timeout=2,
        check=True,
    )
    if len(result.stdout) > 8 * 1024 * 1024:
        raise AssertionError("process metadata exceeds its fixture bound")
    rows = {}
    for line in result.stdout.splitlines():
        fields = line.split(None, 9)
        if len(fields) != 10:
            raise AssertionError("process metadata shape changed")
        rows[int(fields[0])] = Row(int(fields[1]), int(fields[2]), tuple(fields[4:9]), fields[9], fields[3])
    return rows


def _lineage(rows: dict[int, Row], pid: int) -> dict[int, Row]:
    result = {}
    while pid != os.getpid():
        row = rows.get(pid)
        if row is None or pid in result or row.state.startswith("Z"):
            return {}
        result[pid] = row
        pid = row.parent
    return result


def _digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 128 * 1024 * 1024:
        raise AssertionError("owned process image is outside the fixture bounds")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _python_image(python: Path, expected_digest: str) -> Path:
    if _digest(python.resolve(strict=True)) != expected_digest:
        raise AssertionError("selected interpreter differs from its approved artifact")
    # Framework launchers exec a different kernel image. Observe our own ready
    # child after exec instead of assuming the bin/python path is that image.
    program = (
        "import sys,time; assert sys.implementation.name=='cpython'; "
        "assert sys.version_info[:2]==(3,14) and sys.version_info.releaselevel=='final'; "
        "print('ready',flush=True); time.sleep(15)"
    )
    process = subprocess.Popen(
        [str(python), "-I", "-S", "-B", "-u", "-c", program],
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if not select.select([process.stdout], [], [], 5)[0] or process.stdout.readline(16) != b"ready\n":
            raise AssertionError("owned interpreter image probe did not become ready")
        image = kernel_image(process.pid)
        if image is None:
            raise AssertionError("owned interpreter kernel image unavailable")
        return image
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=3)


class OwnedOptionalProcesses:
    def __init__(self, rows, bridge, workers, images, lineage):
        self.rows, self.bridge, self.workers = rows, bridge, workers
        self.images, self.lineage = images, lineage
        self.native = rows[bridge].parent
        self.metrics = {
            "captured_sdk_workers": len(workers),
            "ancestry_verified": True,
            "kernel_images_and_artifacts_verified": True,
            "separate_process_group": True,
            "signals_sent": 0,
            "fallback_signals": 0,
            "contained": False,
        }

    @classmethod
    def capture(cls, binary: Path, selection: dict, approval: dict):
        expected_python = _python_image(Path(selection["python"]), approval["python_sha256"])
        expected_native = _digest(binary)
        rows = _snapshot()
        groups = {}
        for pid, row in rows.items():
            if Path(row.name).name == "cigar-context-worker" and _lineage(rows, pid):
                groups.setdefault(row.parent, []).append(pid)
        candidates = []
        for bridge, workers in groups.items():
            parent = rows.get(bridge)
            if parent is None or parent.parent not in rows or parent.group != bridge or len(workers) != 2:
                continue
            pids = [bridge, parent.parent, *workers]
            images = {pid: kernel_image(pid) for pid in pids}
            if images[bridge] != expected_python or any(image is None for image in images.values()):
                continue
            if _digest(images[parent.parent]) != expected_native:
                continue
            if any(rows[pid].group != bridge or _digest(images[pid]) != approval["worker_sha256"] for pid in workers):
                continue
            lineage = {}
            for pid in pids:
                lineage.update(_lineage(rows, pid))
            if all(pid in lineage for pid in pids):
                candidates.append(cls(rows, bridge, workers, images, lineage))
        if len(candidates) != 1:
            raise AssertionError("expected one qualified optional process group descended from this fixture")
        return candidates[0]

    def interrupt(self, kind: str) -> None:
        if kind not in {"bridge-crash", "sdk-crash", "bridge-stall"}:
            raise AssertionError("unknown fixture fault")
        current = _snapshot()
        if any(not row.same(current.get(pid)) for pid, row in self.lineage.items()):
            raise AssertionError("owned process lineage changed before fault injection")
        if any(kernel_image(pid) != image for pid, image in self.images.items()):
            raise AssertionError("owned process image changed before fault injection")
        targets = self.workers if kind == "sdk-crash" else [self.bridge]
        chosen_signal = signal.SIGSTOP if kind == "bridge-stall" else signal.SIGKILL
        self.metrics["fault"] = kind
        for pid in targets:
            row = _snapshot().get(pid)
            if row is None or row.state.startswith("Z"):
                continue
            if not self.rows[pid].same(row) or kernel_image(pid) != self.images[pid]:
                raise AssertionError("owned target changed before its signal")
            try:
                os.kill(pid, chosen_signal)
                self.metrics["signals_sent"] += 1
            except ProcessLookupError:
                pass
        if not self.metrics["signals_sent"]:
            raise AssertionError("no actual optional process was interrupted")

    def _remaining(self):
        rows = _snapshot()
        return [
            pid
            for pid in [self.bridge, *self.workers]
            if pid in rows and rows[pid].start == self.rows[pid].start and not rows[pid].state.startswith("Z")
        ]

    def verify_containment(self) -> None:
        deadline = time.monotonic() + 8
        while self._remaining() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.metrics["contained"] = not self._remaining()
        row = _snapshot().get(self.native)
        self.metrics["native_parent_survived"] = (
            self.rows[self.native].same(row)
            and not row.state.startswith("Z")
            and kernel_image(self.native) == self.images[self.native]
        )
        assert self.metrics["contained"], "Rust did not contain the interrupted optional group"
        assert self.metrics["native_parent_survived"], "optional failure must preserve its native authority process"

    def cleanup_owned(self) -> None:
        for pid in self._remaining():
            row = _snapshot().get(pid)
            # Known ownership survives reparenting, but never PID reuse/exec.
            if row is None or row.start != self.rows[pid].start or kernel_image(pid) != self.images[pid]:
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                self.metrics["fallback_signals"] += 1
            except ProcessLookupError:
                pass
