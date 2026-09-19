#!/usr/bin/env python3
"""Measure offline scanner process costs and controlled cloud-client wait attribution.

No external service is contacted. Controlled transport delays are not cloud latency.
Cisco engines are not installed by this script or replaced with a fake clean engine.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import urllib.error
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from profile_inventory_refresh import fixture, timed

REAL_SLEEP = time.sleep
URL = "https://fixture.invalid/api/v1/guard/events"


def child_cpu():
    if os.name != "posix":
        return None
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def process_profile(samples):
    from codex_plugin_scanner.integrations.scanner_subprocess import run_bounded_scanner_process, scrubbed_scanner_env

    rows = []
    for case, output_size, delay, timeout in (
        ("isolated_json_1k", 1024, 0, 5.0),
        ("isolated_json_256k", 262144, 0, 5.0),
        ("isolated_controlled_wait", 1024, 0.05, 5.0),
        ("isolated_deadline", 1024, 5.0, 0.25),
    ):
        code = f"import json,time;time.sleep({delay!r});print(json.dumps({{'fixture': 'x'*{output_size}}}))"
        observations = []
        for sample in range(samples):
            before_children = child_cpu()
            wall, cpu = time.perf_counter(), time.process_time()
            result = run_bounded_scanner_process(
                [sys.executable, "-P", "-c", code], env=scrubbed_scanner_env(), timeout_seconds=timeout
            )
            after_children = child_cpu()
            observations.append(
                {
                    "sample": sample,
                    "wall_s": time.perf_counter() - wall,
                    "parent_cpu_s": time.process_time() - cpu,
                    "reaped_children_cpu_s": None if before_children is None else after_children - before_children,
                    "timed_out": result.timed_out,
                    "returncode": result.returncode,
                    "stdout_bytes": len(result.stdout.encode()),
                    "stderr_bytes": len(result.stderr.encode()),
                }
            )
            if case == "isolated_deadline":
                assert result.timed_out
            else:
                assert result.returncode == 0 and not result.timed_out
                assert json.loads(result.stdout) == {"fixture": "x" * output_size}
        rows.append({"case": case, "engine": "controlled Python fixture, not Cisco", "samples": observations})
    return rows


def cisco_profile(samples):
    from codex_plugin_scanner.guard.adapters.gemini import GeminiHarnessAdapter
    from codex_plugin_scanner.guard.inventory_cisco import run_cisco_inventory_scans

    installed = {}
    for name in ("cisco-ai-mcp-scanner", "cisco-ai-skill-scanner"):
        try:
            installed[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            installed[name] = None
    if any(installed.values()):
        return {"installed": installed, "scope": "installed optional engines not executed in offline fixture"}
    with tempfile.TemporaryDirectory(prefix="hol-inventory-cisco-") as directory:
        context = fixture(Path(directory), 1)
        (context.workspace_dir / ".mcp.json").write_text('{"mcpServers":{}}\n', encoding="utf-8")
        detection = GeminiHarnessAdapter().detect(context)

        def run():
            return run_cisco_inventory_scans(
                harness="gemini",
                context=context,
                detection=detection,
                mcp_mode="auto",
                skill_mode="auto",
                timeout_seconds=5.0,
            )

        runs, observations = timed(run, samples)
        assert [item.source for item in runs] == ["cisco-mcp-scanner", "cisco-skill-scanner"]
        assert all(item.status != "enabled" and not item.findings for item in runs)
        assert all(item.metadata["evidenceProvenance"] == "client_unverified" for item in runs)
        assert all(item.metadata["scannerVerificationRequired"] == "guard_cloud" for item in runs)
        return {
            "installed": installed,
            "scope": "actual unavailable-engine wrappers, no successful scan claim",
            "samples": observations,
            "results": [
                {
                    "source": item.source,
                    "status": item.status,
                    "duration_ms": item.duration_ms,
                    "findings": len(item.findings),
                    "evidenceProvenance": item.metadata["evidenceProvenance"],
                    "scannerResolutionSource": item.metadata["scannerResolutionSource"],
                    "scannerVerificationRequired": item.metadata["scannerVerificationRequired"],
                }
                for item in runs
            ],
        }


def http_error(code):
    headers = Message()
    if code in {429, 503}:
        headers["Retry-After"] = "2"
    return urllib.error.HTTPError(URL, code, "controlled fixture", headers, io.BytesIO(b"{}"))


def cloud_client_profile(samples):
    from codex_plugin_scanner.guard.runtime import runner

    rows = []
    cases = (
        ("accepted", ["accepted"], None),
        ("timeout_retry", ["timeout", "accepted"], None),
        ("rate_limit_retry", [429, 429, "accepted"], None),
        ("gateway_retry", [503, 503, "accepted"], None),
        ("unauthorized", [401], "HTTPError"),
        ("missing_endpoint", [404], "HTTPError"),
        ("malformed_response", ["malformed"], "JSONDecodeError"),
    )
    for case, sequence, expected_error in cases:
        observations = []
        for sample in range(samples):
            attempts, requested_sleeps = [], []
            outcomes = iter(sequence)
            imposed_wait = 0.0

            def transport(request, *, timeout, attempts=attempts, outcomes=outcomes):
                nonlocal imposed_wait
                assert request.full_url == URL
                attempts.append(
                    {
                        "timeout_s": timeout,
                        "request_bytes": len(request.data),
                        "same_body": request.data == b'{"events":[]}',
                    }
                )
                REAL_SLEEP(0.01)
                imposed_wait += 0.01
                outcome = next(outcomes)
                if isinstance(outcome, int):
                    raise http_error(outcome)
                if outcome == "timeout":
                    raise TimeoutError("controlled timeout without waiting 90 seconds")
                return io.BytesIO(b"invalid" if outcome == "malformed" else b'{"accepted":1}')

            def controlled_retry_wait(seconds, requested_sleeps=requested_sleeps):
                nonlocal imposed_wait
                requested_sleeps.append(seconds)
                REAL_SLEEP(0.01)
                imposed_wait += 0.01

            request = runner._guard_sync_request(
                {"access_token": "fixture-token"},
                request_url=URL,
                method="POST",
                data=b'{"events":[]}',
                extra_headers=None,
            )
            error_class = None
            wall, cpu = time.perf_counter(), time.process_time()
            with (
                patch.object(runner, "managed_urlopen", transport),
                patch.object(runner.time, "sleep", controlled_retry_wait),
            ):
                try:
                    assert runner._urlopen_json_with_timeout_retry(
                        request=request, timeout_seconds=90, retry_timeout_seconds=120
                    ) == {"accepted": 1}
                except (urllib.error.HTTPError, json.JSONDecodeError) as error:
                    error_class = type(error).__name__
            assert error_class == expected_error
            assert len(attempts) == len(sequence) and all(item["same_body"] for item in attempts)
            if case == "timeout_retry":
                assert [item["timeout_s"] for item in attempts] == [90, 120]
            if case in {"rate_limit_retry", "gateway_retry"}:
                assert requested_sleeps == [2, 2]
            observations.append(
                {
                    "sample": sample,
                    "wall_s": time.perf_counter() - wall,
                    "parent_cpu_s": time.process_time() - cpu,
                    "error_class": error_class,
                    "attempts": attempts,
                    "requested_retry_wait_s": requested_sleeps,
                    "imposed_fixture_wait_s": imposed_wait,
                }
            )
        rows.append({"case": case, "samples": observations})
    return rows


def _profile_source_sha256(root: Path) -> dict[str, str]:
    package_root = root / "src/codex_plugin_scanner"
    runtime_root = package_root / "guard/runtime"
    runner_sources = sorted(
        (
            runtime_root / "runner.py",
            *(path for path in runtime_root.glob("runner*.py") if path.name != "runner.py" and path.is_file()),
        )
    )
    sources = (
        "guard/inventory_cisco.py",
        "integrations/scanner_subprocess.py",
        "integrations/cisco_mcp_scanner.py",
        "integrations/cisco_skill_scanner.py",
        *(path.relative_to(package_root).as_posix() for path in runner_sources),
    )
    return {name: hashlib.sha256((package_root / name).read_bytes()).hexdigest() for name in sources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--section", choices=("all", "process", "cisco", "cloud"), default="all")
    args = parser.parse_args()
    if not 1 <= args.samples <= 10:
        parser.error("samples must be 1..10")
    root = Path(__file__).resolve().parents[1]
    report = {
        "schema": "guard.inventory-wait-profile.v1",
        "python": sys.version,
        "platform": platform.platform(),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_sha256": _profile_source_sha256(root),
        "scope": "offline component fixture; controlled transport wait is not actual cloud latency",
        "process": process_profile(args.samples) if args.section in {"all", "process"} else [],
        "cisco": cisco_profile(args.samples) if args.section in {"all", "cisco"} else {},
        "cloud_client": cloud_client_profile(args.samples) if args.section in {"all", "cloud"} else [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "section": args.section}))


if __name__ == "__main__":
    main()
