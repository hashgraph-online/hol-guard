#!/usr/bin/env python3
"""Validate and render the network-remediation proof and closure record."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

_REPOSITORY_SOURCE = Path(__file__).resolve().parents[1] / "src"
if str(_REPOSITORY_SOURCE) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_SOURCE))

from codex_plugin_scanner.guard.runtime.network_capability_reachability import (  # noqa: E402
    load_reachability_manifest,
    repository_manifest_path,
    validate_reachability_manifest,
)

SCHEMA_VERSION: Final = 1
TASK_IDS: Final = tuple(f"REM-{number:03d}" for number in range(121, 140))
ALLOWED_OUTCOMES: Final = frozenset({"passed", "partial", "blocked", "not-ready"})
PROHIBITED_PRIVACY_FIELDS: Final = frozenset(
    {
        "raw_hostname",
        "raw_url",
        "raw_command",
        "raw_prompt",
        "raw_output",
        "raw_payload",
        "raw_secret",
        "local_path",
        "personal_identifier",
    }
)
EXPECTED_TASK_EVIDENCE: Final[Mapping[str, tuple[str, ...]]] = {
    "REM-121": (
        "tests/test_guard_network_policy_evaluator.py",
        "tests/test_guard_network_destination_correlator.py",
        "tests/test_guard_linux_tcp_enforcement.py",
        "tests/test_guard_linux_udp_dns_enforcement.py",
    ),
    "REM-122": (
        "tests/test_guard_harness_smoke.py",
        "tests/test_guard_risk.py",
        "tests/test_guard_containment_executor.py",
    ),
    "REM-123": (
        "tests/test_guard_harness_contracts.py",
        "tests/test_guard_phase04_harness_ux.py",
        "tests/test_guard_phase07_harness_coverage_matrix.py",
    ),
    "REM-124": (
        "tests/test_guard_compound_developer_inspection.py",
        "tests/test_guard_compound_readonly_auto_allow.py",
        "tests/test_guard_trusted_local_tools.py",
    ),
    "REM-125": (
        "tests/test_guard_approval_store_dedup.py",
        "tests/test_guard_approval_reuse.py",
        "tests/test_guard_network_grant_engine.py",
    ),
    "REM-126": (
        "tests/test_guard_network_supervisor.py",
        "tests/test_guard_daemon_recovery_resilience.py",
        "tests/test_guard_provider_recovery.py",
    ),
    "REM-127": (
        ".github/workflows/guard-network-remediation-proof.yml",
        "tests/test_guard_network_capability_reachability.py",
    ),
    "REM-128": (
        "tests/test_guard_linux_tcp_enforcement.py",
        "tests/test_guard_linux_udp_dns_enforcement.py",
        "tests/test_guard_linux_network_observer.py",
    ),
    "REM-129": (
        ".github/workflows/guard-gvisor-reference.yml",
        "tests/test_guard_gvisor_reference_runtime.py",
        "tests/test_guard_container_network_plan.py",
        "tests/test_guard_kubernetes_runtime.py",
    ),
    "REM-130": (
        "scripts/guard_network_remediation_proof.py",
        "tests/test_guard_network_remediation_proof.py",
    ),
    "REM-131": (
        "tests/test_guard_linux_performance_acceptance.py",
        "tests/test_guard_daemon_perf.py",
    ),
    "REM-132": (
        "tests/test_guard_linux_artifact_lifecycle.py",
        "tests/test_privileged_workflow_policy.py",
        "tests/test_guard_gvisor_reference_runtime.py",
    ),
    "REM-133": (
        "ci/guard-network-capability-reachability.v1.json",
        "tests/test_guard_network_capability_reachability.py",
    ),
    "REM-134": (
        "tests/test_guard_network_remediation_proof.py",
        "scripts/guard_network_remediation_proof.py",
    ),
    "REM-135": (".github/workflows/guard-network-remediation-proof.yml",),
    "REM-136": (
        "docs/guard/network-remediation-readiness.md",
        "ci/guard-network-remediation-proof.v1.json",
    ),
    "REM-137": (
        "scripts/guard_network_remediation_proof.py",
        "tests/test_guard_network_remediation_proof.py",
    ),
    "REM-138": ("docs/guard/network-remediation-readiness.md",),
    "REM-139": (
        "ci/guard-network-remediation-proof.v1.json",
        "docs/guard/network-remediation-readiness.md",
    ),
}
_PRIVATE_ARTIFACT_NAMES: Final = frozenset(
    {
        "prd(4).md",
        "todo(4).md",
        "takeaway-prompt(2).md",
    }
)
_PRIVATE_ARTIFACT_PATH_FRAGMENTS: Final = (".codex/plans/",)
_EXCLUDED_SCAN_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "build",
        "dist",
        "node_modules",
    }
)
_CAPABILITY_LINK_FIELDS: Final = (
    "production_entrypoint",
    "installed_artifact",
    "live_probe",
    "active_generation_source",
    "observer",
    "behavioral_test",
)


class ProofValidationError(ValueError):
    """Raised when the proof record is incomplete or can overstate readiness."""


def _load_object(path: Path) -> Mapping[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ProofValidationError(f"{path}: expected a JSON object")
    return cast(Mapping[str, object], payload)


def _string_list(value: object, *, field: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ProofValidationError(f"{field} must contain non-empty strings")
    if not value and not allow_empty:
        raise ProofValidationError(f"{field} must contain at least one entry")
    return cast(list[str], value)


def _repository_file(repository_root: Path, value: object, *, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ProofValidationError(f"{field} must be a non-empty repository path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProofValidationError(f"{field} must stay within the repository")

    try:
        resolved_root = repository_root.resolve(strict=True)
        lexical_path = resolved_root / relative
        if lexical_path.is_symlink():
            raise ProofValidationError(f"{field} must be a non-symlink regular file: {value}")
        resolved_path = lexical_path.resolve(strict=True)
    except OSError as exc:
        raise ProofValidationError(f"{field} does not exist: {value}") from exc

    if not resolved_path.is_relative_to(resolved_root):
        raise ProofValidationError(f"{field} must stay within the repository")
    if not resolved_path.is_file() or resolved_path.stat().st_size == 0:
        raise ProofValidationError(f"{field} must be a non-empty regular file: {value}")
    return resolved_path


def _private_artifact_hits(repository_root: Path) -> list[str]:
    hits: list[str] = []
    for directory, directories, files in os.walk(repository_root):
        directories[:] = sorted(item for item in directories if item not in _EXCLUDED_SCAN_DIRECTORIES)
        parent = Path(directory)
        for filename in sorted(files):
            relative = (parent / filename).relative_to(repository_root).as_posix()
            lowered = relative.lower()
            if filename.lower() in _PRIVATE_ARTIFACT_NAMES or any(
                fragment in lowered for fragment in _PRIVATE_ARTIFACT_PATH_FRAGMENTS
            ):
                hits.append(relative)
    return hits


def _capability_summary(repository_root: Path) -> tuple[list[str], list[str]]:
    manifest_path = repository_manifest_path(repository_root)
    payload = load_reachability_manifest(manifest_path)
    validation_errors = validate_reachability_manifest(payload, repository_root=repository_root)
    if validation_errors:
        raise ProofValidationError("capability reachability manifest is invalid: " + "; ".join(validation_errors))

    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        raise ProofValidationError("capability reachability manifest must contain a capability list")

    advertised: list[str] = []
    production_ready: list[str] = []
    for index, raw_capability in enumerate(raw_capabilities):
        if not isinstance(raw_capability, Mapping):
            raise ProofValidationError(f"capabilities[{index}] must be an object")
        capability = cast(Mapping[str, object], raw_capability)
        identifier = capability.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ProofValidationError(f"capabilities[{index}].id must be a non-empty string")

        _repository_file(
            repository_root,
            capability.get("contract"),
            field=f"{identifier}.contract",
        )
        if capability.get("advertised") is True:
            for field in _CAPABILITY_LINK_FIELDS:
                _repository_file(
                    repository_root,
                    capability.get(field),
                    field=f"{identifier}.{field}",
                )
            advertised.append(identifier)
        if capability.get("production_ready") is True:
            production_ready.append(identifier)
    return sorted(advertised), sorted(production_ready)


def _validate_manifest_header(payload: Mapping[str, object], errors: list[str]) -> None:
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version must equal 1")
    if payload.get("repository") != "hashgraph-online/hol-guard":
        errors.append("repository must identify hashgraph-online/hol-guard")
    if payload.get("target_branch") != "release/3.0":
        errors.append("target_branch must equal release/3.0")
    raw_task_range = payload.get("task_range")
    expected_range = {"first": TASK_IDS[0], "last": TASK_IDS[-1], "count": len(TASK_IDS)}
    if not isinstance(raw_task_range, Mapping):
        errors.append("task_range must be an object")
    elif dict(raw_task_range) != expected_range:
        errors.append("task_range must exactly cover REM-121 through REM-139")


def _validate_privacy(payload: Mapping[str, object], errors: list[str]) -> None:
    raw_privacy = payload.get("privacy")
    if not isinstance(raw_privacy, Mapping):
        errors.append("privacy must be an object")
        return
    privacy = cast(Mapping[str, object], raw_privacy)
    if privacy.get("raw_domain_storage") is not False:
        errors.append("raw_domain_storage must remain disabled")
    try:
        prohibited_fields = set(_string_list(privacy.get("prohibited_fields"), field="privacy.prohibited_fields"))
    except ProofValidationError as exc:
        errors.append(str(exc))
    else:
        if prohibited_fields != PROHIBITED_PRIVACY_FIELDS:
            errors.append("privacy.prohibited_fields must preserve the complete bounded-evidence denylist")


def _validated_tasks(payload: Mapping[str, object], errors: list[str]) -> list[Mapping[str, object]] | None:
    raw_tasks = payload.get("tasks")
    if not isinstance(raw_tasks, list):
        errors.append("tasks must be a list")
        return None
    tasks: list[Mapping[str, object]] = []
    for index, raw_task in enumerate(raw_tasks):
        if not isinstance(raw_task, Mapping):
            errors.append(f"tasks[{index}] must be an object")
            continue
        tasks.append(cast(Mapping[str, object], raw_task))
    if [task.get("id") for task in tasks] != list(TASK_IDS):
        errors.append("tasks must appear exactly once in REM-121 through REM-139 order")
    return tasks


def _validate_task(
    task: Mapping[str, object],
    *,
    index: int,
    repository_root: Path,
    errors: list[str],
) -> None:
    identifier = task.get("id")
    label = identifier if isinstance(identifier, str) else f"tasks[{index}]"
    outcome = task.get("outcome")
    complete = task.get("complete")
    if outcome not in ALLOWED_OUTCOMES:
        errors.append(f"{label}: outcome is invalid")
    if type(complete) is not bool:
        errors.append(f"{label}: complete must be a boolean")
    if not isinstance(task.get("title"), str) or not task["title"]:
        errors.append(f"{label}: title must be a non-empty string")
    try:
        evidence = _string_list(task.get("evidence"), field=f"{label}.evidence")
        blockers = _string_list(task.get("blockers"), field=f"{label}.blockers", allow_empty=True)
    except ProofValidationError as exc:
        errors.append(str(exc))
        return
    if EXPECTED_TASK_EVIDENCE.get(label) is None or tuple(evidence) != EXPECTED_TASK_EVIDENCE[label]:
        errors.append(f"{label}.evidence must match the task-specific evidence contract")
    for evidence_index, evidence_path in enumerate(evidence):
        try:
            _repository_file(repository_root, evidence_path, field=f"{label}.evidence[{evidence_index}]")
        except ProofValidationError as exc:
            errors.append(str(exc))
    if complete is True and (outcome != "passed" or blockers):
        errors.append(f"{label}: completed tasks must pass without blockers")
    if complete is False and not blockers:
        errors.append(f"{label}: incomplete tasks must retain exact blockers")


def _validate_closure(raw_closure: object, tasks: list[Mapping[str, object]], errors: list[str]) -> object:
    if not isinstance(raw_closure, Mapping):
        errors.append("closure must be an object")
        return None
    closure = cast(Mapping[str, object], raw_closure)
    ready = closure.get("ready")
    if type(ready) is not bool:
        errors.append("closure.ready must be a boolean")
    if closure.get("release_authorized") is not False:
        errors.append("proof work cannot authorize a release")
    if not isinstance(closure.get("reason"), str) or not closure["reason"]:
        errors.append("closure.reason must be a non-empty string")
    all_complete = bool(tasks) and all(task.get("complete") is True for task in tasks)
    if ready is True and not all_complete:
        errors.append("closure cannot be ready while any task remains incomplete")
    if ready is False and all_complete:
        errors.append("closure must explain at least one incomplete task")
    if closure.get("verdict") != ("ready" if ready is True else "not-ready"):
        errors.append("closure.verdict must match closure.ready")
    return ready


def validate_proof_manifest(payload: Mapping[str, object], *, repository_root: Path) -> tuple[str, ...]:
    """Return deterministic validation errors for a proof manifest."""

    errors: list[str] = []
    _validate_manifest_header(payload, errors)
    _validate_privacy(payload, errors)
    tasks = _validated_tasks(payload, errors)
    if tasks is None:
        return tuple(errors)
    for index, task in enumerate(tasks):
        _validate_task(task, index=index, repository_root=repository_root, errors=errors)

    closure_ready = _validate_closure(payload.get("closure"), tasks, errors)

    advertised: list[str] = []
    production_ready: list[str] = []
    try:
        advertised, production_ready = _capability_summary(repository_root)
    except (OSError, ValueError, ProofValidationError) as exc:
        errors.append(str(exc))
    if advertised != production_ready:
        errors.append("advertised and production-ready capability identities must match")
    if closure_ready is True and not advertised:
        errors.append("closure cannot be ready without an advertised production capability")

    private_hits = _private_artifact_hits(repository_root)
    if private_hits:
        errors.append(f"private planning artifact paths are present: {', '.join(private_hits)}")

    return tuple(errors)


def build_proof_report(payload: Mapping[str, object], *, repository_root: Path) -> Mapping[str, object]:
    """Build the bounded machine-readable closure report."""

    errors = validate_proof_manifest(payload, repository_root=repository_root)
    if errors:
        raise ProofValidationError("\n".join(errors))

    tasks = cast(list[Mapping[str, object]], payload["tasks"])
    closure = cast(Mapping[str, object], payload["closure"])
    advertised, production_ready = _capability_summary(repository_root)
    incomplete = [cast(str, task["id"]) for task in tasks if task["complete"] is False]
    blocked = [cast(str, task["id"]) for task in tasks if task["outcome"] in {"blocked", "not-ready"}]
    partial = [cast(str, task["id"]) for task in tasks if task["outcome"] == "partial"]
    return {
        "schema_version": SCHEMA_VERSION,
        "program": payload["program"],
        "repository": payload["repository"],
        "target_branch": payload["target_branch"],
        "task_range": payload["task_range"],
        "ready": closure["ready"],
        "verdict": closure["verdict"],
        "reason": closure["reason"],
        "recommended_action": (
            "Preserve the proof contract and continue routine verification."
            if closure["ready"] is True
            else "Resolve the listed incomplete tasks and missing production evidence, then rerun with --require-ready."
        ),
        "release_authorized": False,
        "task_counts": {
            "total": len(tasks),
            "complete": len(tasks) - len(incomplete),
            "incomplete": len(incomplete),
            "partial": len(partial),
            "blocked_or_not_ready": len(blocked),
        },
        "incomplete_tasks": incomplete,
        "partial_tasks": partial,
        "blocked_tasks": blocked,
        "advertised_capabilities": advertised,
        "production_ready_capabilities": production_ready,
        "raw_domain_storage": False,
        "private_artifact_hits": [],
    }


def _write_report(report: Mapping[str, object], *, output: Path | None) -> None:
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("ci/guard-network-remediation-proof.v1.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    repository_root = args.repository_root.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = repository_root / manifest_path
    payload = _load_object(manifest_path)
    report = build_proof_report(payload, repository_root=repository_root)
    _write_report(report, output=args.output)
    if args.require_ready and report["ready"] is not True:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
