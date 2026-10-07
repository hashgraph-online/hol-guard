"""Verify a complete Gauntlet evidence directory without trusting its verdicts."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from .catalog import load_catalog, load_catalog_data, retain_trusted_cases
from .evidence import assess_case, reconcile
from .fixtures import digest_file
from .input_evidence import input_digest
from .latency import summarize_hook_latency
from .source_identity import source_identity, validate_identity
from .transport import reconcile_rounds

_CONTAINED_SCHEMA = "hol.guard-gauntlet.contained-bun-vitest.evidence.v1"
_CONTAINED_PROFILE = "contained-bun-vitest-extended"
_CONTAINED_CASE_IDS = (
    "bunx-vitest",
    "bun-x-vitest",
    "bun-no-install",
    "bun-cwd",
    "bun-cwd-equals",
    "bun-cross-project",
    "bun-cross-project-equals",
)
_CONTAINED_CHECKS = frozenset(
    {
        "contained-test-files-unchanged",
        "contained-dependencies-unchanged",
        "contained-project-files-unchanged",
        "contained-project-local-dependencies",
    }
)


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    """Read a bounded JSON object, rejecting missing files, symlinks and nonobject payloads."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("missing, symlinked or oversized evidence")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("evidence must be a JSON object")
    return data


def _contained_public_path(value: object) -> bool:
    return isinstance(value, str) and (
        value.startswith("/")
        or value.startswith(("{{fixture}}/", "{{workspace}}/", "{{home}}/", "{{contained_project}}/"))
    )


def _contained_wrapper_argv(command: object, expected_workspace: str) -> tuple[list[str] | None, str | None]:
    if not isinstance(command, str):
        return None, "contained wrapper command is missing"
    try:
        argv = shlex.split(command)
    except ValueError:
        return None, "contained wrapper command is not valid shell argv"
    canonical = " ".join("'" + value.replace("'", "'\\''") + "'" for value in argv)
    if command != canonical:
        return None, "contained wrapper command is not canonical"
    if len(argv) != 12 or not _contained_public_path(argv[0]):
        return None, "contained wrapper is not an approved path"
    if argv[1] != "execute-contained-test" or argv[2] != "--guard-home" or not _contained_public_path(argv[3]):
        return None, "contained wrapper guard-home binding is malformed"
    if argv[4:6] != ["--workspace", expected_workspace]:
        return None, "contained wrapper workspace binding differs from the reviewed caller"
    if argv[6] != "--request-file":
        return None, "contained wrapper request-file flag is missing"
    request = Path(argv[7])
    if (
        not request.is_absolute()
        or request.name != "request.json"
        or not request.parent.name.startswith("hol-guard-contained-test-")
    ):
        return None, "contained wrapper request path is not adapter-owned"
    if argv[8] != "--request-sha256" or re.fullmatch(r"[0-9a-f]{64}", argv[9]) is None:
        return None, "contained wrapper request digest is malformed"
    if argv[10] != "--home" or not _contained_public_path(argv[11]):
        return None, "contained wrapper home binding is malformed"
    return argv, None


def _verify_contained_case(case: dict[str, Any], row: dict[str, Any], expected_id: str) -> None:
    if case.get("id") != expected_id or case.get("profile") != _CONTAINED_PROFILE:
        raise ValueError("contained case identity mismatch")
    if digest_file(case["_path"]) != row.get("evidence_sha256"):
        raise ValueError("contained case evidence bytes changed")
    if case.get("filesystem") != case.get("_filesystem"):
        raise ValueError("contained case physical proof differs from the profile report")
    filesystem = case.get("filesystem")
    if (
        not isinstance(filesystem, dict)
        or set(filesystem) != _CONTAINED_CHECKS
        or not all(value is True for value in filesystem.values())
    ):
        raise ValueError("contained case lacks complete physical fixture proof")
    assessment = case.get("assessment")
    expected_assessment = {key: row.get(key) for key in row if key != "evidence_sha256"}
    if assessment != expected_assessment or assessment.get("outcome") != "pass":
        raise ValueError("contained case result does not match its independently recomputed assessment")
    proof = case.get("request_proof")
    if not isinstance(proof, dict) or set(proof) != {
        "schema",
        "tool_call_id",
        "workspace",
        "payload_sha256",
        "request_sha256",
    }:
        raise ValueError("contained case lacks a bounded request proof")
    if (
        proof.get("schema") != "guard-contained-test-request-proof.v1"
        or not isinstance(proof.get("tool_call_id"), str)
        or not isinstance(proof.get("workspace"), str)
        or re.fullmatch(r"[0-9a-f]{64}", proof.get("payload_sha256", "")) is None
        or re.fullmatch(r"[0-9a-f]{64}", proof.get("request_sha256", "")) is None
        or proof["workspace"] != case.get("caller_workspace")
    ):
        raise ValueError("contained request proof fields are malformed")
    events = case.get("events")
    if not isinstance(events, list):
        raise ValueError("contained case omitted host events")
    calls, errors = reconcile(events)
    if errors or len(calls) != len(_CONTAINED_CASE_IDS):
        raise ValueError("contained host event inventory is incomplete")
    call = next((item for item in calls if item.get("id") == proof["tool_call_id"]), None)
    if call is None or call.get("name") != "bash" or call.get("is_error") is not False:
        raise ValueError("contained request proof does not identify a completed bash call")
    wrapper = call.get("args", {}).get("command")
    wrapper_argv, wrapper_error = _contained_wrapper_argv(wrapper, case.get("caller_workspace", ""))
    if wrapper_error or wrapper_argv is None:
        raise ValueError(wrapper_error or "contained wrapper is unavailable")
    if wrapper_argv[9] != proof["request_sha256"]:
        raise ValueError("contained request proof digest differs from the executed wrapper")
    expected_input = {"command": case.get("command")}
    expected_payload = {
        "hook_event_name": "PreToolUse",
        "tool_call_id": proof["tool_call_id"],
        "tool_name": "bash",
        "tool_input": expected_input,
    }
    if input_digest(expected_payload) != proof["payload_sha256"]:
        raise ValueError("contained request proof is not bound to the original command")
    observations = case.get("guard_observations")
    if not isinstance(observations, list):
        raise ValueError("contained case omitted Guard observations")
    bound = [row for row in observations if row.get("tool_call_id") == proof["tool_call_id"]]
    pre = [item for item in bound if item.get("event") == "PreToolUse"]
    post = [item for item in bound if item.get("event") == "PostToolUse"]
    if len(pre) != 1 or len(post) != 1 or pre[0].get("input") != expected_input:
        raise ValueError("contained native observations are not bound to the original command")
    native = pre[0].get("native_observation")
    receipt = native.get("native_receipt") if isinstance(native, dict) else None
    if (
        pre[0].get("decision") != "deny"
        or pre[0].get("reason_code") != "native_vitest_readonly_containment_required"
        or pre[0].get("policy_action") != "sandbox-required"
        or not isinstance(native, dict)
        or native.get("required_execution_profile") != "vitest-readonly-v1"
        or not isinstance(receipt, dict)
        or receipt.get("authority") != "rust"
        or receipt.get("harness") != "omp"
        or receipt.get("event_name") != "PreToolUse"
        or receipt.get("decision") != "deny"
        or receipt.get("reason_code") != pre[0].get("reason_code")
        or receipt.get("request_id") != pre[0].get("probe_request_id")
        or not isinstance(receipt.get("decision_id"), str)
        or not receipt["decision_id"]
    ):
        raise ValueError("contained native observation lacks the authoritative Rust denial")
    if post[0].get("decision") != "allow" or post[0].get("input", {}).get("command") != wrapper:
        raise ValueError("contained post observation is not bound to the executed wrapper")
    result = call.get("result")
    details = result.get("details", {}) if isinstance(result, dict) else {}
    presentation = details.get("holGuardContainedTest") if isinstance(details, dict) else None
    if (
        not isinstance(presentation, dict)
        or presentation.get("schema") != "guard-contained-test-presentation.v1"
        or presentation.get("toolCallId") != proof["tool_call_id"]
        or presentation.get("input") != expected_input
        or presentation.get("command") != wrapper
        or ("exitCode" in details and details.get("exitCode") != 0)
    ):
        raise ValueError("contained result presentation is not bound to the executed wrapper")
    target = case.get("target_workspace")
    if target is not None:
        try:
            original = shlex.split(case["command"])
        except ValueError as error:
            raise ValueError("cross-project contained command is not valid shell argv") from error
        requested = None
        if len(original) > 2 and original[:2] == ["bun", "--cwd"]:
            requested = original[2]
        elif len(original) > 1 and original[0] == "bun" and original[1].startswith("--cwd="):
            requested = original[1][6:]
        if requested != target or target == case.get("caller_workspace"):
            raise ValueError("cross-project contained case lacks distinct caller and target workspaces")


def verify_contained_report(
    directory: Path,
    *,
    report: dict[str, Any],
    expected_sha: str,
    require_qualified: bool,
    source_root: Path | None,
    source_manifest: Path | None,
) -> dict[str, Any]:
    """Verify additive contained evidence without treating it as qualification."""
    if re.fullmatch(r"[0-9a-f]{40}", expected_sha) is None:
        raise ValueError("expected candidate SHA must be a full commit")
    if report.get("candidate_sha") != expected_sha:
        raise ValueError("wrong contained evidence candidate SHA")
    if require_qualified:
        raise ValueError("contained Bun/Vitest evidence is additive; use --exploratory to verify it")
    if (
        report.get("schema") != _CONTAINED_SCHEMA
        or report.get("profile") != _CONTAINED_PROFILE
        or report.get("qualification") != "extended-profile-only"
        or report.get("core20_qualified") is not False
        or report.get("full_profile") is not True
        or report.get("pass") is not True
        or report.get("merge_qualified") is not False
        or report.get("source_dirty") is not False
        or report.get("source_unchanged") is not True
        or report.get("returncode") != 0
        or report.get("timed_out") is not False
        or report.get("cleanup_ok") is not True
        or report.get("approval_delta") != 0
        or report.get("profile_protocol_errors") != []
    ):
        raise ValueError("contained report is partial, failed or incorrectly labeled")
    rows = report.get("cases")
    if (
        not isinstance(rows, list)
        or [row.get("id") for row in rows] != list(_CONTAINED_CASE_IDS)
        or report.get("expected_cases") != list(_CONTAINED_CASE_IDS)
        or report.get("actual_tool_calls") != len(_CONTAINED_CASE_IDS)
    ):
        raise ValueError("contained report has missing, duplicate or reordered cases")
    filesystem = report.get("filesystem")
    if (
        not isinstance(filesystem, dict)
        or set(filesystem) != _CONTAINED_CHECKS
        or not all(value is True for value in filesystem.values())
    ):
        raise ValueError("contained report lacks complete physical fixture proof")
    if report.get("egress_requests") != []:
        raise ValueError("contained report includes an egress request")
    inference = report.get("inference")
    if (
        not isinstance(inference, dict)
        or inference.get("canary_export_violations") != 0
        or not isinstance(inference.get("live_rounds"), list)
        or not inference["live_rounds"]
        or not all(isinstance(round_data, dict) for round_data in inference["live_rounds"])
        or not reconcile_rounds(inference["live_rounds"])[0]
    ):
        raise ValueError("contained report lacks completed live inference evidence")
    if source_root is not None and source_manifest is not None:
        raise ValueError("select only one independently trusted source reference")
    here = Path(__file__).resolve().parent
    repo = source_root.resolve() if source_root is not None else here.parents[1]
    manifest = _read_json(source_manifest, 1_000_000) if source_manifest is not None else None
    if manifest is not None and manifest.get("schema") != "hol.guard-gauntlet.github-source.v1":
        raise ValueError("unsupported trusted GitHub source manifest")
    if manifest is not None:
        if manifest.get("candidate_sha") != expected_sha or manifest.get("runner_files") != report.get("runner_files"):
            raise ValueError("contained report differs from the immutable source manifest")
        sdk_digest = manifest.get("sdk_lock_sha256")
        catalog_hash = manifest.get("runner_files", {}).get("scenarios.json")
    else:
        candidate_runner = repo / "ci/gauntlet"
        actual_runner = {path.name: digest_file(path) for path in sorted(candidate_runner.iterdir()) if path.is_file()}
        if report.get("runner_files") != actual_runner:
            raise ValueError("Gauntlet runner changed after contained evidence was produced")
        sdk_digest = digest_file(repo / "ci/pi-exact-continuation/package-lock.json")
        catalog_hash = digest_file(repo / "ci/gauntlet/scenarios.json")
    if report.get("sdk_lock_sha256") != sdk_digest or report.get("core_catalog_sha256") != catalog_hash:
        raise ValueError("contained report source digests changed")
    for row, expected_id in zip(rows, _CONTAINED_CASE_IDS, strict=True):
        if not isinstance(row, dict):
            raise ValueError("contained case row is malformed")
        path = directory / "cases" / f"{expected_id}.json"
        case = _read_json(path, 8_000_000)
        case["_path"] = path
        case["_filesystem"] = filesystem
        _verify_contained_case(case, row, expected_id)
    return {
        "verified": True,
        "candidate_sha": expected_sha,
        "profile": _CONTAINED_PROFILE,
        "scenarios": len(rows),
        "actual_tool_calls": report["actual_tool_calls"],
        "merge_qualified": False,
        "qualification": "extended-profile-only",
    }


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
    if report.get("schema") == _CONTAINED_SCHEMA:
        return verify_contained_report(
            directory,
            report=report,
            expected_sha=expected_sha,
            require_qualified=require_qualified,
            source_root=source_root,
            source_manifest=source_manifest,
        )
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
