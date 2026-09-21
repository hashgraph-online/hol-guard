"""Trusted diagnostic wrappers injected into the existing isolated archive child.

This module is a benchmark helper, never imported by production. It does not
parse archives itself or disable the child's environment/capability/resource
limits. Phase timers add overhead; authoritative latency samples use the
unmodified parent and child separately.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from typing import Any


def run_profile(inspector: Any, arguments: list[str], child_started: float, child_imported: float) -> int:
    imported_ms = (child_imported - child_started) * 1000
    worker = sys.modules[inspector._inspect_archive.__module__]
    phases: dict[str, dict[str, float | int]] = {}

    def timed(name: str, function: Callable[..., Any]) -> Callable[..., Any]:
        def measure(*args: Any, **kwargs: Any) -> Any:
            wall = time.perf_counter()
            cpu = time.process_time()
            try:
                return function(*args, **kwargs)
            finally:
                sample = phases.setdefault(name, {"wall_ms": 0.0, "cpu_ms": 0.0, "calls": 0})
                sample["wall_ms"] += (time.perf_counter() - wall) * 1000
                sample["cpu_ms"] += (time.process_time() - cpu) * 1000
                sample["calls"] += 1

        return measure

    # The worker's _hash_file calls policy._hash_stream. Only the worker aliases
    # are wrapped, so the initial path hash and both descriptor hashes do not
    # double count one another.
    worker._hash_file = timed("digest_reads", worker._hash_file)
    worker._hash_stream = timed("digest_reads", worker._hash_stream)
    worker._preflight_expanded_tar_stream = timed("expanded_stream_preflight", worker._preflight_expanded_tar_stream)
    worker.tarfile.TarFile.next = timed("tar_member_decode", worker.tarfile.TarFile.next)
    worker._install_script_risk = timed("manifest_policy", worker._install_script_risk)
    worker._python_build_script_risk = timed("manifest_policy", worker._python_build_script_risk)
    inspector._child_limits = timed("resource_limits", inspector._child_limits)
    inspector._inspect_archive = timed("inspection_total", inspector._inspect_archive)
    exit_code = inspector._child_main(arguments)
    sys.stderr.write(json.dumps({"child_import_ms": imported_ms, "phases": phases}, separators=(",", ":")))
    return exit_code
