#!/usr/bin/env python3
"""Validate first-class fail-closed release evidence (refusals, unsupported)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

SCHEMA = "hol-guard-release-negative-outcomes.v1"
REQUIRED_TESTS = {
    "draft": "tests/test_release_negative_outcomes.py::test_draft_rollout_is_not_live_authority",
    "wrong-workspace": "tests/test_release_negative_outcomes.py::test_wrong_workspace_bundle_is_refused",
    "stale": "tests/test_release_negative_outcomes.py::test_stale_bundle_is_rejected_as_downgrade",
    "unavailable-runtime": "tests/test_release_negative_outcomes.py::test_unavailable_runtime_is_not_release_evidence",
    "immutable-block": "tests/test_release_negative_outcomes.py::test_immutable_block_is_not_remotely_approvable",
}
REQUIRED_CASES = tuple(REQUIRED_TESTS)
ALLOWED_RESULTS = frozenset({"fail-closed", "refused", "unsupported"})
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_MAX_BYTES = 256 * 1024


class NegativeOutcomeError(ValueError):
    """Raised when negative-outcome evidence is incomplete or happy-path-only."""


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise NegativeOutcomeError(f"{label} is not a bounded evidence token")
    return value


def result_digest(source_sha: str, results: object) -> str:
    encoded = json.dumps({"source_sha": source_sha, "pytest_results": results}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _execution(payload: Mapping[str, object]) -> tuple[str, list[dict[str, object]]]:
    source_sha = payload.get("source_sha")
    if not isinstance(source_sha, str) or _SHA40.fullmatch(source_sha) is None:
        raise NegativeOutcomeError("negative evidence source digest is invalid")
    results = payload.get("pytest_results")
    if not isinstance(results, list) or len(results) != len(REQUIRED_TESTS):
        raise NegativeOutcomeError("executed pytest results are incomplete")
    normalized: list[dict[str, object]] = []
    for node, row in zip(REQUIRED_TESTS.values(), results, strict=True):
        digest = hashlib.sha256(node.encode()).hexdigest()
        if not isinstance(row, dict) or row != {
            "nodeid_sha256": digest,
            "setup": "passed",
            "call": "passed",
            "teardown": "passed",
        }:
            raise NegativeOutcomeError("required negative assertion did not execute successfully")
        normalized.append(dict(row))
    if payload.get("pytest_results_sha256") != result_digest(source_sha, normalized):
        raise NegativeOutcomeError("pytest result digest does not bind execution")
    return source_sha, normalized


def validate_negative_outcomes(payload: Mapping[str, object]) -> dict[str, object]:
    if payload.get("schema") != SCHEMA:
        raise NegativeOutcomeError("unsupported negative-outcome schema")
    source_sha, execution = _execution(payload)
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise NegativeOutcomeError("negative-outcome cases are missing")
    by_name: dict[str, dict[str, object]] = {}
    for item in cases:
        if not isinstance(item, dict):
            raise NegativeOutcomeError("negative-outcome case must be an object")
        name = _token(item.get("name"), label="case")
        if name not in REQUIRED_CASES:
            raise NegativeOutcomeError(f"unsupported negative-outcome case: {name}")
        if name in by_name:
            raise NegativeOutcomeError(f"duplicate negative-outcome case: {name}")
        result = _token(item.get("result"), label="result")
        if result not in ALLOWED_RESULTS:
            raise NegativeOutcomeError(f"happy-path result is not evidence for {name}")
        if item.get("passed") is not False:
            raise NegativeOutcomeError(f"{name} must explicitly record passed=false as negative evidence")
        evidence = _token(item.get("evidence"), label="evidence")
        digest = item.get("pytest_nodeid_sha256")
        if digest != hashlib.sha256(REQUIRED_TESTS[name].encode()).hexdigest():
            raise NegativeOutcomeError(f"pytest digest is invalid for {name}")
        record: dict[str, object] = {"name": name, "result": result, "passed": False, "evidence": evidence}
        if isinstance(digest, str):
            record["pytest_nodeid_sha256"] = digest
        by_name[name] = record
    if set(by_name) != set(REQUIRED_CASES):
        missing = sorted(set(REQUIRED_CASES) - set(by_name))
        raise NegativeOutcomeError(f"negative-outcome set is incomplete: {missing}")
    return {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "pytest_results": execution,
        "pytest_results_sha256": result_digest(source_sha, execution),
        "cases": [by_name[name] for name in REQUIRED_CASES],
    }


def _load(path: Path) -> Mapping[str, object]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BYTES:
        raise NegativeOutcomeError("negative-outcome file is not a bounded regular file")
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NegativeOutcomeError("negative-outcome file is not valid JSON") from error
    if not isinstance(value, dict):
        raise NegativeOutcomeError("negative-outcome root must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        normalized = validate_negative_outcomes(_load(args.evidence))
    except NegativeOutcomeError as error:
        print(f"Negative-outcome validation failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
