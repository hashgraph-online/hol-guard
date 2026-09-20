#!/usr/bin/env python3
"""Installed native mixed-load diagnostics with explicit SQLite/queue observers.

The installed package and its bundled default runtime must remain unchanged.
The separately built observer measures logical SQLite VFS callbacks and actual
writer queue residence. Neither metric is a kernel or physical-device measure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from scripts.bench_guard_native_installed_slo_runtime import _runtime_summary  # noqa: E402
from scripts.native_slo_contract import proof_environment_violations  # noqa: E402
from scripts.native_slo_daemon_fixture import DaemonFixture  # noqa: E402
from scripts.native_slo_failure import failure_evidence  # noqa: E402
from scripts.native_slo_mixed import run_mixed_scenario  # noqa: E402
from scripts.native_slo_persistence_observation import (  # noqa: E402
    PersistenceObservationSpec,
    persistence_observation_checks,
)
from scripts.native_slo_sqlite_vfs_identity import image_identity  # noqa: E402


def _source_identity() -> dict[str, str]:
    scripts = _ROOT / "scripts"
    paths = sorted(
        {
            *scripts.glob("native*.py"),
            *scripts.glob("bench_guard_native*.py"),
            *(scripts / "ci/rsp131_sqlite_vfs").glob("*.[ch]"),
        }
    )
    if len(paths) > 512:
        raise ValueError("native diagnostic source set exceeds its fixed bound")
    identities = {}
    for path in paths:
        with path.open("rb") as stream:
            data = stream.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError("native diagnostic source exceeds its per-file bound")
        identities[str(path.relative_to(_ROOT))] = hashlib.sha256(data).hexdigest()
    return identities


def run_observed_persistence(
    *, spec: PersistenceObservationSpec, raw_file: Path, duration_seconds: float, rate: float, concurrency: int
) -> dict[str, Any]:
    """Run the unchanged mixed workload against the installed default runtime."""
    before: dict[str, Any] = {}
    after: dict[str, Any] = {}
    mixed: dict[str, Any] = {}
    failures: list[dict[str, object]] = []
    runtime: Path | None = None
    try:
        if proof_environment_violations():
            raise RuntimeError("persistence diagnostic requires the ordinary proof environment")
        status = native_runtime_status()
        if status.identity is None:
            raise RuntimeError("installed default native runtime unavailable")
        runtime = status.identity.path
        before = {
            "runtime": _runtime_summary(runtime),
            "extension": image_identity(spec.extension),
            "observer_source_sha256": _source_identity(),
        }
        if before["extension"]["sha256"] != spec.extension_sha256:
            raise ValueError("persistence observer extension digest mismatch")
        with DaemonFixture(runtime, policy="normal") as session:
            mixed = run_mixed_scenario(
                session,
                raw_file=raw_file,
                duration_seconds=duration_seconds,
                rate=rate,
                concurrency=concurrency,
                receipt_observation=spec,
            )
    except Exception as error:
        failures.append(failure_evidence(error))
    finally:
        if before and runtime is not None:
            try:
                after = {
                    "runtime": _runtime_summary(runtime),
                    "extension": image_identity(spec.extension),
                    "observer_source_sha256": _source_identity(),
                }
            except Exception as error:
                failures.append(failure_evidence(error))
    checks = persistence_observation_checks(mixed)
    checks["installed_and_observer_identities_unchanged"] = bool(before) and before == after
    checks["ordinary_environment_retained"] = not proof_environment_violations()
    return {
        "schema": "hol-guard.installed-persistence-observation.v1",
        "scope": "installed_native_mixed_hooks_policy_updates_inventory_and_resident_restart",
        "passed": mixed.get("passed") is True and all(checks.values()) and not failures,
        "checks": checks,
        "mixed": mixed,
        "identity_before": before,
        "identity_after": after,
        "failures": failures,
        "headline_timing_eligible": False,
        "full_rsp131_qualification": False,
        "unavailable": ["kernel_fsync_counts", "physical_device_bytes", "separate_uninstrumented_paired_performance"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extension", required=True, type=Path)
    parser.add_argument("--extension-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--rate", type=float, default=20.0)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--queue-max-pending", type=int, default=65_536)
    args = parser.parse_args()
    spec = PersistenceObservationSpec(args.extension, args.extension_sha256, args.queue_max_pending)
    result = run_observed_persistence(
        spec=spec,
        raw_file=args.ledger,
        duration_seconds=args.seconds,
        rate=args.rate,
        concurrency=args.concurrency,
    )
    encoded = (json.dumps(result, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ValueError("persistence diagnostic aggregate exceeds its 1 MiB bound")
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with os.fdopen(os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(encoded)
    print(
        json.dumps({"passed": result["passed"], "headline_timing_eligible": False, "full_rsp131_qualification": False})
    )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
