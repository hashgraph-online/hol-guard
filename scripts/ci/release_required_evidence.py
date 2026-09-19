#!/usr/bin/env python3
"""Inventory required test collection and configured installation checks."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, cast

import pytest
import yaml

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.verify_release_negative_outcomes import REQUIRED_TESTS

REQUIRED_RELEASE_FILES = ("tests/test_release_negative_outcomes.py",)
REQUIRED_RELEASE_NODE_IDS = tuple(REQUIRED_TESTS.values())
INSTALLED_CANARY_JOB = "pr-installed-canary"
INSTALLED_WHEEL_SNIPPET = 'uv tool run --from "$wheel" hol-guard --version'
ALPHA_WHEEL_SNIPPET = 'uv tool run --from "$guard_wheel" hol-guard --version'
NAMED_CI_DESELECT = (
    "tests/test_guard_hook_process_runner.py::"
    "test_scheduler_and_runner_complete_48_routine_reviews_without_capacity_denial"
)


class _CollectionSession(Protocol):
    items: list[pytest.Item]


@dataclass(frozen=True)
class ReleaseCollectionReport:
    schema: str
    source_sha: str
    evidence_kind: str
    collected_release_cases: int
    default_collected_cases: int
    deselected_required: tuple[str, ...]
    missing_required: tuple[str, ...]
    named_ci_deselects: tuple[str, ...]
    configured_canary_oses: tuple[str, ...]
    configured_wheel_jobs: tuple[str, ...]
    installed_runtime_verified: bool


class _NodeCollector:
    def __init__(self) -> None:
        self.items: list[pytest.Item] = []

    def pytest_collection_finish(self, session: _CollectionSession) -> None:
        self.items = list(session.items)


def _collect(root: Path, extra_args: Sequence[str], *, targets: Sequence[str]) -> list[str]:
    collector = _NodeCollector()
    result = pytest.main(
        [*(str(root / target) for target in targets), "--collect-only", "-p", "no:terminal", *extra_args],
        plugins=[collector],
    )
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {result}")
    return [item.nodeid for item in collector.items]


def _contains_node(nodeids: Sequence[str], required: str) -> bool:
    return any(nodeid.split("[", 1)[0] == required for nodeid in nodeids)


def _workflow_jobs(root: Path, filename: str = "publish.yml") -> dict[str, object]:
    workflow = yaml.safe_load((root / ".github/workflows" / filename).read_text(encoding="utf-8"))
    if not isinstance(workflow, dict):
        raise RuntimeError("publish workflow is not a mapping")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise RuntimeError("publish workflow has no jobs")
    return jobs


def _installed_canary_oses(jobs: dict[str, object]) -> tuple[str, ...]:
    job = jobs.get(INSTALLED_CANARY_JOB)
    if not isinstance(job, dict):
        raise RuntimeError("pr-installed-canary job is missing")
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        raise RuntimeError("pr-installed-canary strategy is missing")
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        raise RuntimeError("pr-installed-canary matrix is missing")
    os_list = matrix.get("os")
    if not isinstance(os_list, list) or not all(isinstance(item, str) for item in os_list):
        raise RuntimeError("pr-installed-canary OS matrix is missing")
    required = {"ubuntu-latest", "macos-latest", "windows-latest"}
    if set(os_list) != required:
        raise RuntimeError(f"pr-installed-canary OS matrix is incomplete: {os_list}")
    steps = job.get("steps")
    runs = [step.get("run", "") for step in steps if isinstance(step, dict)] if isinstance(steps, list) else []
    for command in ("verify-release --registry testpypi", "-m scripts.run_installed_canary"):
        if not any(isinstance(run, str) and command in run for run in runs):
            raise RuntimeError("pr-installed-canary checks are not configured")
    return tuple(os_list)


def _without_shell_comments(run: str) -> str:
    """Remove unquoted comments while retaining the original command text."""
    result: list[str] = []
    quote = ""
    escaped = False
    comment = False
    word_start = True
    for character in run:
        if comment:
            if character == "\n":
                result.append(character)
                comment = False
                word_start = True
            continue
        if escaped:
            result.append(character)
            escaped = False
            if character != "\n":
                word_start = False
            continue
        if quote:
            result.append(character)
            if character == quote:
                quote = ""
            elif character == "\\" and quote == '"':
                escaped = True
            continue
        if character == "#" and word_start:
            comment = True
            continue
        result.append(character)
        if character in {"'", '"'}:
            quote = character
            word_start = False
        elif character == "\\":
            escaped = True
        else:
            word_start = character in " \t\n;|&()<>"
    return "".join(result)


def _installed_wheel_jobs(jobs: dict[str, object]) -> tuple[str, ...]:
    configured: list[str] = []
    for name, snippet in (
        ("publish-alpha-testpypi", INSTALLED_WHEEL_SNIPPET),
        ("publish-alpha-pypi", ALPHA_WHEEL_SNIPPET),
        ("publish-main-pypi", ALPHA_WHEEL_SNIPPET),
    ):
        job = jobs.get(name)
        if not isinstance(job, dict):
            raise RuntimeError(f"{name} job is missing")
        steps = job.get("steps")
        if not isinstance(steps, list) or not any(
            isinstance(step, dict)
            and isinstance(step.get("run"), str)
            and snippet in _without_shell_comments(step["run"])
            and step.get("if") is not False
            and step.get("if") not in {"false", "${{ false }}"}
            for step in steps
        ):
            raise RuntimeError(f"{name} has no configured wheel install check")
        configured.append(name)
    return tuple(configured)


def _named_ci_deselects(root: Path) -> tuple[str, ...]:
    ci_text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if NAMED_CI_DESELECT not in ci_text:
        raise RuntimeError("CI shard deselect is no longer named; update the release inventory")
    return (NAMED_CI_DESELECT,)


def build_report(root: Path) -> ReleaseCollectionReport:
    default_ids = _collect(root, (), targets=REQUIRED_RELEASE_FILES)
    release_ids = _collect(root, ("-o", "addopts=", "-m", "release"), targets=REQUIRED_RELEASE_FILES)
    missing = tuple(node for node in REQUIRED_RELEASE_NODE_IDS if not _contains_node(release_ids, node))
    if missing:
        raise RuntimeError(f"required release tests were not collected: {missing}")
    deselected = tuple(
        node
        for node in REQUIRED_RELEASE_NODE_IDS
        if _contains_node(release_ids, node) and not _contains_node(default_ids, node)
    )
    if deselected:
        raise RuntimeError(f"required release tests were silently deselected: {deselected}")
    jobs = _workflow_jobs(root)
    return ReleaseCollectionReport(
        schema="hol-guard-release-collection.v1",
        source_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        evidence_kind="collection-and-configuration",
        collected_release_cases=len(release_ids),
        default_collected_cases=len(default_ids),
        deselected_required=deselected,
        missing_required=missing,
        named_ci_deselects=_named_ci_deselects(root),
        configured_canary_oses=_installed_canary_oses(_workflow_jobs(root, "installed-pr-canary.yml")),
        configured_wheel_jobs=_installed_wheel_jobs(jobs),
        installed_runtime_verified=False,
    )


def validate_collection_report(payload: Mapping[str, object], *, source_sha: str) -> None:
    if (
        payload.get("schema") != "hol-guard-release-collection.v1"
        or payload.get("source_sha") != source_sha
        or payload.get("evidence_kind") != "collection-and-configuration"
        or payload.get("missing_required") != []
        or payload.get("deselected_required") != []
        or payload.get("installed_runtime_verified") is not False
    ):
        raise ValueError("required release collection is incomplete")
    for key in ("collected_release_cases", "default_collected_cases"):
        value = payload.get(key)
        if type(value) is not int or value < len(REQUIRED_RELEASE_NODE_IDS):
            raise ValueError("required release collection count is incomplete")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    report = build_report(root)
    payload = json.dumps(asdict(report), indent=2, sort_keys=True) + "\n"
    output = cast(Path | None, args.output)
    if output is None:
        print(payload, end="")
    else:
        output.write_text(payload, encoding="utf-8")
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
