"""Process metadata only: aggregate the isolated benchmark and every child.

Retain observed PID/start identities across reparenting. Never request argv,
environment, open-file paths or credential-bearing resident state files.
"""

from __future__ import annotations

import ctypes
import os
import statistics
import subprocess
import sys
import threading
from collections import Counter
from pathlib import Path

from scripts.native_slo_process_tree import _system_ps_path


def kernel_image(pid: int) -> Path | None:
    """Ask the kernel for the executable identity where supported."""
    if sys.platform.startswith("linux"):
        try:
            return Path(os.readlink(f"/proc/{pid}/exe")).resolve()
        except OSError:
            return None
    if sys.platform != "darwin":
        return None
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pidpath
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    length = function(pid, buffer, len(buffer))
    if not 0 < length < len(buffer):
        return None
    return Path(os.fsdecode(buffer.value)).resolve()


class ProcessSampler:
    def __init__(self, selected_python: Path) -> None:
        self.root = os.getpid()
        self.host_python = Path(sys.executable).resolve(strict=True)
        self.host_image = kernel_image(self.root)
        self.selected_python = selected_python.resolve(strict=True)
        self.known: dict[int, tuple[str, ...]] = {}
        self._live_descendants: dict[tuple[int, tuple[str, ...]], str] = {}
        self.samples: list[dict] = []
        self.errors = 0
        self.observed_names: Counter[str] = Counter()
        self._lock = threading.Lock()
        self._sample_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cigar-rss-sampler", daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_args):
        self._stop.set()
        self._thread.join(timeout=2)
        if self._thread.is_alive():
            raise RuntimeError("benchmark process sampler did not stop")

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except (OSError, ValueError, subprocess.SubprocessError, RuntimeError):
                self.errors += 1
            self._stop.wait(0.05)

    def sample(self) -> dict:
        with self._sample_lock:
            return self._sample()

    def sample_with_identities(self) -> tuple[dict, dict[tuple[int, tuple[str, ...]], str]]:
        """Internal fixture baselines; callers must persist only aggregates."""
        with self._sample_lock:
            aggregate = self._sample()
            with self._lock:
                return aggregate, dict(self._live_descendants)

    def _sample(self) -> dict:
        ps = _system_ps_path()
        if ps is None:
            raise RuntimeError("trusted system process sampler unavailable")
        process = subprocess.Popen(
            [str(ps), "-axo", "pid=,ppid=,rss=,stat=,lstart=,comm="],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            output, _ = process.communicate(timeout=1)
        except BaseException:
            process.kill()
            process.communicate(timeout=1)
            raise
        if process.returncode or len(output) > 8 * 1024 * 1024:
            raise RuntimeError("bounded process metadata unavailable")
        rows = {}
        for line in output.splitlines():
            parts = line.split(None, 9)
            if len(parts) != 10:
                raise ValueError("process metadata shape changed")
            pid, parent, rss = map(int, parts[:3])
            rows[pid] = (parent, rss * 1024, tuple(parts[4:9]), parts[9], parts[3])
        if self.root not in rows:
            raise RuntimeError("benchmark owner missing from process snapshot")
        with self._lock:
            included = {self.root} | {
                pid for pid, identity in self.known.items() if pid in rows and rows[pid][2] == identity
            }
            while True:
                expanded = included | {pid for pid, row in rows.items() if row[0] in included}
                if expanded == included:
                    break
                included = expanded
            included.discard(process.pid)  # This short-lived measurement process is not the product.
            # macOS CPython's framework launcher can report "Python" as comm
            # rather than its selected bin/python3.14 path. Establish the
            # actual bridge by its ownership of an observed SDK worker; runtime
            # version/artifact eligibility is independently checked by Guard.
            bridges = {
                rows[pid][0]
                for pid in included
                if "cigar-context-worker" in Path(rows[pid][3]).name.lower() and not rows[pid][4].startswith("Z")
            }
            counts, sizes, live = Counter(), Counter(), {}
            for pid in included:
                _, rss, identity, executable, state = rows[pid]
                name = Path(executable).name.lower()
                self.observed_names[name] += 1
                self.known[pid] = identity
                kind = (
                    "benchmark_daemon_host"
                    if pid == self.root
                    else "terminated_child"
                    if state.startswith("Z")
                    else "sdk_worker"
                    if "cigar-context-worker" in name
                    else "native_runtime"
                    if "hol-guard-runtime" in name
                    else "python_bridge"
                    if "python" in name and pid in bridges
                    else "guard_python_worker"
                    if "python" in name
                    and (
                        Path(executable).resolve() == self.host_python
                        or (self.host_image is not None and kernel_image(pid) == self.host_image)
                    )
                    else "exiting_host_python_child"
                    if name.strip("()") == self.host_python.name.lower()
                    else "selected_python"
                    if "python" in name and Path(executable).resolve() == self.selected_python
                    else "other_python_child"
                    if "python" in name
                    else "other_descendant"
                )
                counts[kind] += 1
                sizes[kind] += rss
                if pid != self.root and not state.startswith("Z"):
                    live[(pid, identity)] = kind
            result = {"rss_bytes": sum(sizes.values()), "counts": dict(counts), "rss_by_kind": dict(sizes)}
            if len(self.samples) >= 8192:
                raise RuntimeError("process metadata sample budget exhausted")
            self.samples.append(result)
            self._live_descendants = live
            return result

    def checkpoint(self) -> int:
        with self._lock:
            return len(self.samples)

    def summary(self, start: int = 0) -> dict:
        with self._lock:
            samples = self.samples[start:]
            if not samples:
                raise RuntimeError("no complete process samples")
            peak = max(samples, key=lambda item: item["rss_bytes"])
            kinds = {kind for item in samples for kind in item["counts"]}
            return {
                "samples": len(samples),
                "sampling_errors": self.errors,
                "median_rss_bytes": int(statistics.median(item["rss_bytes"] for item in samples)),
                "peak_rss_bytes": peak["rss_bytes"],
                "at_peak_counts": peak["counts"],
                "at_peak_rss_by_kind": peak["rss_by_kind"],
                "maximum_counts": {kind: max(item["counts"].get(kind, 0) for item in samples) for kind in kinds},
                "includes_observed_reparented_children": True,
                "shared_pages_may_be_counted_in_multiple_processes": True,
            }
