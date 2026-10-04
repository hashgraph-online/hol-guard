"""Verify a complete Gauntlet evidence directory without trusting its verdicts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .catalog import load_catalog, load_catalog_data, retain_trusted_cases
from .evidence import assess_case
from .fixtures import digest_file
from .latency import summarize_hook_latency
from .source_identity import source_identity, validate_identity


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    """Read a bounded JSON object, rejecting missing files, symlinks and nonobject payloads."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("missing, symlinked or oversized evidence")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("evidence must be a JSON object")
    return data


def verify_report(
    directory: Path,
    *,
    expected_sha: str,
    require_qualified: bool = True,
    source_root: Path | None = None,
    source_manifest: Path | None = None,
) -> dict[str, Any]:
    """Recompute coverage, hashes and outcomes for the exact candidate source."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None:
        raise ValueError("expected candidate SHA must be a full commit")
    directory = directory.resolve()
    report = _read_json(directory / "summary.json", 1_000_000)
    if report.get("schema") != "hol.guard-gauntlet.evidence.v1" or report.get("candidate_sha") != expected_sha:
        raise ValueError("wrong evidence schema or stale candidate SHA")
    here = Path(__file__).resolve().parent
    repo = source_root.resolve() if source_root is not None else here.parents[1]
    if source_root is not None and source_manifest is not None:
        raise ValueError("select only one independently trusted source reference")
    manifest = _read_json(source_manifest, 1_000_000) if source_manifest is not None else None
    if manifest is not None and manifest.get("schema") != "hol.guard-gauntlet.github-source.v1":
        raise ValueError("unsupported trusted GitHub source manifest")
    if manifest is not None:
        catalog_text = manifest.get("catalog_json")
        if not isinstance(catalog_text, str):
            raise ValueError("trusted source manifest lacks the candidate catalog")
        catalog_hash = hashlib.sha256(catalog_text.encode("utf-8")).hexdigest()
        if catalog_hash != manifest.get("runner_files", {}).get("scenarios.json"):
            raise ValueError("candidate catalog does not match its immutable source digest")
        expected = load_catalog_data(json.loads(catalog_text))
    else:
        catalog_path = repo / "ci/gauntlet/scenarios.json"
        catalog_hash = digest_file(catalog_path)
        expected = load_catalog(catalog_path)
    retain_trusted_cases(expected, load_catalog())
    if report.get("catalog_sha256") != catalog_hash:
        raise ValueError("scenario catalog changed after evidence was produced")
    ids = [scenario.id for scenario in expected]
    if report.get("expected_scenarios") != ids or [row.get("id") for row in report.get("cases", [])] != ids:
        raise ValueError("missing, duplicate, reordered or unknown scenario evidence")
    if report.get("full_profile") is not True or report.get("pass") is not True:
        raise ValueError("partial or failed runs do not qualify")
    if require_qualified and (
        report.get("merge_qualified") is not True
        or report.get("source_dirty") is not False
        or report.get("source_unchanged") is not True
    ):
        raise ValueError("evidence does not qualify the exact clean installed candidate")
    if require_qualified:
        validate_identity(report, expected_sha=expected_sha)
        if manifest is None:
            actual_binding = source_identity(repo, expected_sha)
        else:
            actual_binding = {
                key: manifest.get(key)
                for key in ("candidate_sha", "tested_source_sha", "source_parents", "tested_base_sha", "source_dirty")
            }
        if any(report.get(key) != value for key, value in actual_binding.items()):
            raise ValueError("reported ancestry does not match the independently resolved Git commit")
    sdk_digest = (
        manifest.get("sdk_lock_sha256")
        if manifest is not None
        else digest_file(repo / "ci/pi-exact-continuation/package-lock.json")
    )
    if report.get("sdk_lock_sha256") != sdk_digest:
        raise ValueError("Oh My Pi dependency lock changed after evidence was produced")
    if manifest is not None and manifest.get("runner_files") != report.get("runner_files"):
        raise ValueError("reported runner differs from immutable candidate Git blobs")
    if manifest is None:
        candidate_runner = repo / "ci/gauntlet"
        actual_runner = {p.name: digest_file(p) for p in sorted(candidate_runner.iterdir()) if p.is_file()}
        if report.get("runner_files") != actual_runner:
            raise ValueError("Gauntlet runner changed after evidence was produced")
    results = []
    observations = []
    missing_latency_cases = []
    for scenario, row in zip(expected, report["cases"], strict=True):
        path = directory / "cases" / f"{scenario.id}.json"
        case = _read_json(path, 8_000_000)
        if case.get("id") != scenario.id or case.get("expectation") != scenario.expectation:
            raise ValueError("scenario identity mismatch")
        if digest_file(path) != row.get("evidence_sha256"):
            raise ValueError("scenario evidence bytes changed")
        observations.extend(case["guard_observations"])
        if "hook_latency" not in case:
            missing_latency_cases.append(scenario.id)
        if "hook_latency" in case and case["hook_latency"] != summarize_hook_latency(case["guard_observations"]):
            raise ValueError("claimed hook latency does not match observed evidence")
        result = assess_case(scenario, case)
        if result != case.get("assessment") or any(row.get(k) != v for k, v in result.items()):
            raise ValueError("claimed result does not match observed evidence")
        if result["outcome"] != "pass":
            raise ValueError("a required scenario did not pass")
        results.append(result)
    latency = summarize_hook_latency(observations)
    if "hook_latency" in report and report["hook_latency"] != latency:
        raise ValueError("claimed aggregate hook latency does not match observed evidence")
    return {
        "verified": True,
        "candidate_sha": expected_sha,
        "scenarios": len(results),
        "actual_tool_calls": sum(result["tool_calls"] for result in results),
        "merge_qualified": report["merge_qualified"],
        "hook_latency": latency,
        "hook_latency_reported": "hook_latency" in report and not missing_latency_cases,
        "cases_missing_latency_report": missing_latency_cases,
    }
