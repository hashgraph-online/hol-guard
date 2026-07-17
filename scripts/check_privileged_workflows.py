#!/usr/bin/env python3
"""Enforce immutable toolchain inputs in privileged GitHub Actions jobs."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

_FULL_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_EXACT_UV_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_WORKFLOW_SUFFIXES = frozenset({".yml", ".yaml"})


@dataclass(frozen=True)
class WorkflowPolicyViolation:
    """One actionable privileged-workflow policy violation."""

    workflow: Path
    job: str
    code: str
    message: str

    def render(self, *, root: Path) -> str:
        try:
            workflow = self.workflow.relative_to(root)
        except ValueError:
            workflow = self.workflow
        return f"{workflow}:{self.job}: [{self.code}] {self.message}"


def _mapping(value: object) -> dict[object, object]:
    return value if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _has_write_capability(permissions: object) -> bool:
    if isinstance(permissions, str):
        return permissions.strip().lower() == "write-all"
    return any(str(value).strip().lower() == "write" for value in _mapping(permissions).values())


def _effective_permissions(workflow: dict[object, object], job: dict[object, object]) -> object:
    if "permissions" in job:
        return job["permissions"]
    return workflow.get("permissions")


def _is_external_action(reference: str) -> bool:
    return not reference.startswith(("./", "docker://"))


def _is_commit_pinned(reference: str) -> bool:
    _, separator, revision = reference.rpartition("@")
    return separator == "@" and _FULL_COMMIT_SHA.fullmatch(revision) is not None


def _validate_action_reference(
    *,
    workflow_path: Path,
    job_name: str,
    step_name: str,
    reference: object,
) -> WorkflowPolicyViolation | None:
    if not isinstance(reference, str) or not reference.strip():
        return WorkflowPolicyViolation(
            workflow_path,
            job_name,
            "action-reference-invalid",
            f"{step_name} has an empty or non-string action reference.",
        )
    normalized = reference.strip()
    if not _is_external_action(normalized) or _is_commit_pinned(normalized):
        return None
    return WorkflowPolicyViolation(
        workflow_path,
        job_name,
        "action-not-commit-pinned",
        f"{step_name} uses {normalized!r}; privileged jobs require a full 40-character commit SHA.",
    )


def _validate_privileged_job(
    *,
    workflow_path: Path,
    job_name: str,
    job: dict[object, object],
) -> list[WorkflowPolicyViolation]:
    violations: list[WorkflowPolicyViolation] = []
    reusable_workflow = job.get("uses")
    if reusable_workflow is not None:
        violation = _validate_action_reference(
            workflow_path=workflow_path,
            job_name=job_name,
            step_name="reusable workflow",
            reference=reusable_workflow,
        )
        if violation is not None:
            violations.append(violation)

    for index, raw_step in enumerate(_sequence(job.get("steps")), start=1):
        step = _mapping(raw_step)
        if not step or "uses" not in step:
            continue
        step_name = str(step.get("name") or f"step {index}")
        reference = step.get("uses")
        violation = _validate_action_reference(
            workflow_path=workflow_path,
            job_name=job_name,
            step_name=step_name,
            reference=reference,
        )
        if violation is not None:
            violations.append(violation)

        if not isinstance(reference, str) or not reference.startswith("astral-sh/setup-uv@"):
            continue
        uv_version = _mapping(step.get("with")).get("version")
        if not isinstance(uv_version, str) or _EXACT_UV_VERSION.fullmatch(uv_version.strip()) is None:
            violations.append(
                WorkflowPolicyViolation(
                    workflow_path,
                    job_name,
                    "uv-version-not-pinned",
                    f"{step_name} must set with.version to an exact X.Y.Z version.",
                )
            )
    return violations


def validate_privileged_workflows(root: Path) -> tuple[WorkflowPolicyViolation, ...]:
    """Return policy violations for explicitly write-capable workflow jobs."""

    workflows_dir = root / ".github" / "workflows"
    violations: list[WorkflowPolicyViolation] = []
    for workflow_path in sorted(workflows_dir.glob("*")):
        if workflow_path.suffix not in _WORKFLOW_SUFFIXES or not workflow_path.is_file():
            continue
        try:
            raw_workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            violations.append(
                WorkflowPolicyViolation(
                    workflow_path,
                    "<workflow>",
                    "workflow-unreadable",
                    f"could not parse workflow: {exc}",
                )
            )
            continue
        workflow = _mapping(raw_workflow)
        for raw_job_name, raw_job in _mapping(workflow.get("jobs")).items():
            job = _mapping(raw_job)
            if not job or not _has_write_capability(_effective_permissions(workflow, job)):
                continue
            violations.extend(
                _validate_privileged_job(
                    workflow_path=workflow_path,
                    job_name=str(raw_job_name),
                    job=job,
                )
            )
    return tuple(violations)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root (defaults to cwd).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    violations = validate_privileged_workflows(root)
    if violations:
        for violation in violations:
            print(violation.render(root=root), file=sys.stderr)
        print(f"Privileged workflow policy failed with {len(violations)} violation(s).", file=sys.stderr)
        return 1
    print("Privileged workflow policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
