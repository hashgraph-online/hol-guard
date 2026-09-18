#!/usr/bin/env python3
"""Witness which real local package routes can call an unversioned bundle lookup.

This is a functional source-route witness, not a performance benchmark. It uses
the normal signed bundle loader, artifact builder, evaluator and evidence store.
The only fixture override supplies a synthetic workspace ID. A transparent call
recorder observes bundle lookups, and unexpected networking fails the witness.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import platform
import socket
import subprocess
import sys
import tempfile
from dataclasses import asdict
from pathlib import Path


def source_identity(root: Path) -> dict[str, object]:
    return {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "source_diff_sha256": hashlib.sha256(
            subprocess.check_output(["git", "diff", "HEAD", "--", "src"], cwd=root)
        ).hexdigest(),
        "source_status": subprocess.check_output(
            ["git", "status", "--porcelain", "--", "src"], cwd=root, text=True
        ).splitlines(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    initial_identity = source_identity(root)
    if initial_identity["source_status"]:
        parser.error("the source tree must be clean")
    sys.path[:0] = [str(root / "src"), str(root)]
    import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator
    from codex_plugin_scanner.guard.runtime.supply_chain_bundle import load_supply_chain_bundle_response
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_guard_supply_chain_evaluator import (
        WORKSPACE_ID,
        _artifact_for_targets,
        _bundle_response,
        _package,
    )

    network_attempts = []

    def reject_network(*_args, **_kwargs):
        network_attempts.append(True)
        raise AssertionError("The local route witness attempted networking")

    socket.create_connection = reject_network
    socket.socket.connect = reject_network
    socket.socket.connect_ex = reject_network
    bundle_response = _bundle_response(
        packages=[
            _package(ecosystem="npm", name="minimist", version="1.2.8", default_action="block"),
            _package(ecosystem="npm", name="anchor", version="1.0.0", default_action="block"),
        ]
    )
    original_lookup = evaluator.evaluate_cached_supply_chain_bundle
    api_decision = original_lookup(
        load_supply_chain_bundle_response(bundle_response),
        package_name="minimist",
        package_version=None,
        ecosystem="npm",
        now=1779148800.0,
    )
    assert api_decision.action == "block"
    observed_calls = []
    observed_decisions = []

    def observe_lookup(*call_args, **kwargs):
        observed_calls.append({key: kwargs.get(key) for key in ("package_name", "package_version", "ecosystem")})
        decision = original_lookup(*call_args, **kwargs)
        observed_decisions.append(asdict(decision))
        return decision

    evaluator.evaluate_cached_supply_chain_bundle = observe_lookup
    cases = []
    with tempfile.TemporaryDirectory(prefix="guard-package-route-witness-") as temporary:
        directory = Path(temporary)
        for case_name in ("bare_registry_direct", "lockfile_resolved_direct", "exact_transitive"):
            workspace = directory / case_name / "workspace"
            workspace.mkdir(parents=True)
            entries = {}
            if case_name == "lockfile_resolved_direct":
                entries["node_modules/minimist"] = {"version": "1.2.8"}
            elif case_name == "exact_transitive":
                entries["node_modules/holder/node_modules/minimist"] = {"version": "1.2.8"}
            (workspace / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": entries}))
            store = GuardStore(directory / case_name / "guard")
            store.get_cloud_workspace_id = lambda: WORKSPACE_ID
            store.cache_supply_chain_bundle(WORKSPACE_ID, bundle_response, "2026-05-19T00:00:00Z")
            target = {
                "bare_registry_direct": "minimist",
                "lockfile_resolved_direct": "minimist@^1.2.0",
                "exact_transitive": "anchor@1.0.0",
            }[case_name]
            artifact = _artifact_for_targets(
                target,
                lockfile_paths=("package-lock.json",),
            )
            observed_calls.clear()
            observed_decisions.clear()
            result = evaluator.evaluate_package_request_artifact(
                artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
            )
            with store._connect() as connection:
                evidence = [
                    dict(row) for row in connection.execute("select * from guard_evidence order by evidence_id")
                ]
            calls = list(observed_calls)
            assert all(isinstance(call["package_version"], str) for call in calls)
            if case_name == "bare_registry_direct":
                # A bare npm token is normalized to the literal registry tag.
                # It is not the cached API's name-only None-version query.
                assert calls == [{"package_name": "minimist", "package_version": "latest", "ecosystem": "npm"}]
                assert observed_decisions[0]["reason"] == "no_cached_match"
                assert len(result.packages) == len(evidence) == 1
            else:
                expected_names = ["minimist"] if case_name == "lockfile_resolved_direct" else ["anchor", "minimist"]
                assert [call["package_name"] for call in calls] == expected_names
                assert result.decision == "block"
                assert len(result.packages) == len(evidence) == len(expected_names)
                assert all(package.get("resolvedVersion") is not None for package in result.packages)
            cases.append(
                {
                    "case": case_name,
                    "command": artifact.metadata["redacted_command"],
                    "cached_bundle_calls": calls,
                    "cached_bundle_decisions": list(observed_decisions),
                    "result": result.to_dict(),
                    "persisted_evidence": evidence,
                }
            )
    if network_attempts:
        raise AssertionError("Unexpected networking was attempted")
    final_identity = source_identity(root)
    assert final_identity == initial_identity
    evaluator_source = root / "src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py"
    source_bytes = evaluator_source.read_bytes()
    direct_call_lines = [
        node.lineno
        for node in ast.walk(ast.parse(source_bytes))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "evaluate_cached_supply_chain_bundle"
    ]
    report = {
        "schema": "guard-package-unversioned-route-witness-v1",
        "source": initial_identity,
        "final_source": final_identity,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "evaluator_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "evaluator_direct_lookup_call_lines": sorted(direct_call_lines),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "timing_scope": "not collected; functional source-route reachability witness only",
        "api_only_unversioned_decision": asdict(api_decision),
        "api_only_persistence_exercised": False,
        "full_evaluator_cases": cases,
        "assertions_passed": True,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "cases": len(cases), "assertions_passed": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
