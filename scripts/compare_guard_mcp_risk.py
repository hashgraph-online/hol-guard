#!/usr/bin/env python3
"""Compare two local source trees through identical actual MCP stdio workers.

The caller supplies frozen baseline/candidate source roots. The parent client
uses the installed/current framing helper; each fresh worker imports exclusively
from its selected source root. No local source path is emitted in the report.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import sys
import tempfile
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from profile_guard_mcp_session import BenchmarkCaseError, performance_lock, run_case, write_checkpoint

_SOURCES = ("proxy/runtime_mcp.py", "proxy/framing.py", "proxy/tool_catalog.py", "mcp_tool_calls.py")


def source_identity(source: Path) -> dict[str, str]:
    return {
        name: hashlib.sha256((source / "codex_plugin_scanner/guard" / name).read_bytes()).hexdigest()
        for name in _SOURCES
    }


def verify_facts(baseline: Path, *, progress=None, attempt=None) -> dict:
    """Use frozen pre-change source, not a second spelling of new predicates."""
    from codex_plugin_scanner.guard import mcp_tool_calls as candidate
    from codex_plugin_scanner.guard.config import GuardConfig

    name = "codex_plugin_scanner.guard._mcp_risk_baseline_oracle"
    spec = importlib.util.spec_from_file_location(name, baseline / "codex_plugin_scanner/guard/mcp_tool_calls.py")
    if spec is None or spec.loader is None:
        raise ValueError("mcp_comparison_cannot_load_baseline_oracle")
    reference = importlib.util.module_from_spec(spec)
    sys.modules[name] = reference
    spec.loader.exec_module(reference)
    probes = ["", "ordinary text", "x" * 1024, "x" * 16384, "x" * 131072]
    tokens = (
        "subprocess.run()",
        "child_process.spawn()",
        "childprocess",
        "popen",
        "os.system",
        "runtime.exec",
        "spawn_sync()",
        "execfile()",
        "system()",
        "https://example.invalid",
        "http://example.invalid",
        "curl",
        "wget",
        "fetch",
        "axios",
        "requests",
        "socket.connect",
        "net.connect",
        "dns.resolve",
        "create_connection()",
        "getaddrinfo()",
        "gethostbyname()",
        "sendto()",
        "recvfrom()",
        "urllib.request.urlopen",
        "urllib.urlopen",
        "http.client.",
        "https.",
        "udp",
        "tcp",
        "socks",
        "proxy",
        "tunnel",
        "port_forward",
        "port-forward",
        ".env",
        ".ssh",
        "idrsa",
        "id_rsa",
        "id-rsa",
        "credentials",
        "token",
        "secret",
        "passwd",
        ".npmrc",
        ".pypirc",
        "sudo",
        "chmod",
        "chown",
        "launchctl",
        "systemctl",
        "httpClient.get",
        "runtimeExec",
        "[2001:db8:0:0:0:0:0:1]",
        "[::1]",
        "192.0.2.4:1234",
        "::ffff:192.0.2.1",
        "999.999.999.999",
        "::",
        "1:2:3:4:5:6:7",
        "éÉ Σσ ıİ",
    )
    for token in tokens:
        probes.extend((token, "prefix" + token + "suffix", "_" + token + "_"))
    checked = 0
    prepared_cases = 0
    trace = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="guard-mcp-risk-parity-") as temporary:
        root = Path(temporary)
        for action in ("allow", "warn", "review", "block"):
            config = GuardConfig(guard_home=root, workspace=root, default_action=action)
            for tool, key, description in (
                ("echo_0", "text", "Echo text."),
                ("summarize", "command", "Summarize text."),
                ("browser_navigate", "url", "Navigate to a URL."),
                ("readFile", "sourcePath", "Read files and run commands."),
            ):
                artifact = candidate.build_tool_call_artifact(
                    harness="codex",
                    server_name="synthetic",
                    tool_name=tool,
                    source_scope="project",
                    config_path=".mcp.json",
                    transport="stdio",
                    tool_schema={"type": "object", "properties": {key: {"type": "string"}}},
                    tool_description=description,
                )
                for probe in probes:
                    if attempt is not None:
                        attempt(checked + 1)
                    arguments = {key: probe, "sample": 17}
                    results = []
                    for module in (reference, candidate):
                        facts_arguments = {}
                        facts = None
                        if module is candidate and hasattr(module, "prepare_tool_call_risk_facts"):
                            facts = module.prepare_tool_call_risk_facts(artifact, arguments)
                            if facts is None:
                                raise RuntimeError("mcp_comparison_candidate_did_not_prepare_plain_json_facts")
                            facts_arguments["risk_facts"] = facts
                            prepared_cases += 1
                        results.append(
                            {
                                "categories": facts.categories
                                if facts
                                else module.tool_call_risk_categories(artifact, arguments),
                                "approval_hash": module.build_tool_call_hash(
                                    artifact, arguments, workspace=root, config=config, **facts_arguments
                                ),
                                "policy": asdict(
                                    module._evaluate_current_tool_call(
                                        config=config, artifact=artifact, arguments=arguments, **facts_arguments
                                    )
                                ),
                            }
                        )
                    if results[0] != results[1]:
                        raise RuntimeError("mcp_comparison_frozen_source_fact_mismatch")
                    # Record a fixed-size outcome digest, never policy/receipt/path bodies.
                    trace.update(json.dumps(results[0], sort_keys=True, default=str).encode())
                    checked += 1
                    if progress is not None:
                        progress(checked)
    return {
        "cases": checked,
        "mismatches": 0,
        "candidate_prepared_facts_cases": prepared_cases,
        "compared": ["risk_categories", "approval_hash", "full_policy_decision"],
        "matched_outcome_trace_sha256": trace.hexdigest(),
        "oracle": "frozen_baseline_module_shared_unchanged_authorities",
    }


def run_comparison(
    *,
    baseline: Path,
    candidate: Path,
    output: Path,
    lock_file: Path,
    samples: int,
    comparison_name: str = "risk-prefilter",
    memory_boundary: bool = False,
    container_boundary: bool = False,
) -> dict:
    roots = {"baseline": baseline.resolve(), "candidate": candidate.resolve()}
    identities = {label: source_identity(root) for label, root in roots.items()}
    cases = []
    if memory_boundary or container_boundary:
        kinds = ("dense-integers", "nested-records", "nested-text") if container_boundary else ("ascii", "unicode")
        for block, payload_kind in enumerate(kinds):
            for source in ("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"):
                cases.append(
                    {
                        "block": block,
                        "source": source,
                        "payload_bytes": 4 * 1024 * 1024 - 512,
                        "samples": min(samples, 3),
                        "profile": True,
                        "compact_result": True,
                        "payload_kind": payload_kind,
                    }
                )
    else:
        for block in range(5):
            for payload in (1024, 16384, 131072):
                for source in ("baseline", "candidate") if block % 2 == 0 else ("candidate", "baseline"):
                    cases.append({"block": block, "source": source, "payload_bytes": payload, "samples": samples})
        for payload in (1024, 16384, 131072):
            for source in ("baseline", "candidate"):
                cases.append({"source": source, "payload_bytes": payload, "samples": min(samples, 20), "profile": True})
    report = {
        "schema": f"hol-guard-mcp-{comparison_name}-comparison.v1",
        "qualification": False,
        "campaign": "near_frame_ceiling_container_diagnostic"
        if container_boundary
        else "near_frame_ceiling_memory_diagnostic"
        if memory_boundary
        else "five_alternating_process_blocks",
        "platform": platform.system(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "runtime_sources_sha256": identities,
        "measurement_lock": "per_case_POSIX_flock",
        "limitations": [
            "source_route_not_installed_cli",
            "single_host_diagnostic",
            "c1_only",
            "synthetic_echo_payloads",
            "profile_timings_are_not_qualification",
            "memory_samples_are_not_absolute_peak",
            "warm_sample_count_below_release_tail_gate",
        ],
        "cases": [],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError("mcp_comparison_refuses_to_overwrite_attempts")
    write_checkpoint(output, report)
    try:
        with performance_lock(lock_file):
            report["facts_parity"] = verify_facts(roots["baseline"])
    except (Exception, KeyboardInterrupt) as error:
        report["failed_facts_parity"] = {"reason": type(error).__name__}
        write_checkpoint(output, report)
        raise
    write_checkpoint(output, report)
    prior_pythonpath = os.environ.get("PYTHONPATH")
    try:
        for index, scheduled in enumerate(cases):
            options = dict(scheduled)
            source = options.pop("source")
            block = options.pop("block", None)
            os.environ["PYTHONPATH"] = str(roots[source])
            started_utc = None
            try:
                if source_identity(roots[source]) != identities[source]:
                    raise ValueError("mcp_comparison_source_changed")
                with performance_lock(lock_file):
                    started_utc = datetime.now(timezone.utc).isoformat()
                    result = run_case(**options)
                    finished_utc = datetime.now(timezone.utc).isoformat()
                if any(
                    identities[source].get(name) != digest for name, digest in result["loaded_runtime_sha256"].items()
                ):
                    raise ValueError("mcp_comparison_worker_loaded_wrong_source")
                if source_identity(roots[source]) != identities[source]:
                    raise ValueError("mcp_comparison_source_changed_during_case")
            except (Exception, KeyboardInterrupt) as error:
                report["failed_case"] = {
                    "case": index + 1,
                    "scheduled": scheduled,
                    "started_utc": started_utc,
                    "failed_utc": datetime.now(timezone.utc).isoformat(),
                    **(error.evidence if isinstance(error, BenchmarkCaseError) else {"reason": type(error).__name__}),
                }
                write_checkpoint(output, report)
                raise
            result.update({"source": source, "block": block, "started_utc": started_utc, "finished_utc": finished_utc})
            report["cases"].append(result)
            report["completed_cases"] = len(report["cases"])
            write_checkpoint(output, report)
            print(
                json.dumps(
                    {
                        "case": index + 1,
                        "total": len(cases),
                        **scheduled,
                        "p95_ms": result["client_roundtrip_ms"]["p95"],
                        "tree_cpu_ms": result["tree_cpu_ms_per_call"],
                    }
                ),
                file=sys.stderr,
                flush=True,
            )
            # Give queued sibling workloads a turn after checkpointing a cell.
            time.sleep(0.1)
    finally:
        if prior_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = prior_pythonpath
    report["comparisons"] = []
    for index in range(0, len(report["cases"]), 2):
        pair = report["cases"][index : index + 2]
        old = next(case for case in pair if case["source"] == "baseline")
        new = next(case for case in pair if case["source"] == "candidate")
        parity = old["correctness"] == new["correctness"]
        comparison = {
            "block": old["block"],
            "payload_bytes": old["fixture"]["payload_bytes"],
            "payload_kind": old["fixture"]["payload_kind"],
            "profile": old["fixture"]["profile"],
            "exact_correctness_parity": parity,
            "roundtrip_p95_change_percent": 100
            * (new["client_roundtrip_ms"]["p95"] / old["client_roundtrip_ms"]["p95"] - 1),
            "tree_cpu_change_percent": 100 * (new["tree_cpu_ms_per_call"] / old["tree_cpu_ms_per_call"] - 1),
        }
        report["comparisons"].append(comparison)
        if not parity:
            report["failed_parity"] = {"pair": index // 2, "errors": 1}
            write_checkpoint(output, report)
            raise RuntimeError("mcp_comparison_correctness_mismatch")
    write_checkpoint(output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-src", type=Path, required=True)
    parser.add_argument("--candidate-src", type=Path, required=True)
    parser.add_argument("--lock-file", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument(
        "--comparison-name", choices=("risk-prefilter", "request-facts", "structural-facts"), default="risk-prefilter"
    )
    boundary = parser.add_mutually_exclusive_group()
    boundary.add_argument("--memory-boundary", action="store_true")
    boundary.add_argument("--container-boundary", action="store_true")
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10000:
        parser.error("samples must be 1..10000")
    report = run_comparison(
        baseline=args.baseline_src,
        candidate=args.candidate_src,
        output=args.json,
        lock_file=args.lock_file,
        samples=args.samples,
        comparison_name=args.comparison_name,
        memory_boundary=args.memory_boundary,
        container_boundary=args.container_boundary,
    )
    print(json.dumps({"completed_cases": report["completed_cases"], "qualification": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
