#!/usr/bin/env python3
"""Validate privacy-safe installed Guard upgrade and rollback evidence.

The matrix is an aggregate contract.  It deliberately accepts counts and
statuses only; source payloads, commands, paths, and secrets are rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

PLATFORMS = frozenset({"manylinux-x64", "macos-x64", "macos-arm64", "windows-x64"})
REQUIRED_SCENARIOS = frozenset({"clean-install", "upgrade", "reinstall", "rollback", "fault-injection"})
ALL_HARNESSES = (
    "codex",
    "claude-code",
    "copilot",
    "cursor",
    "gemini",
    "hermes",
    "openclaw",
    "antigravity",
    "opencode",
    "kimi",
    "grok",
    "pi",
    "zcode",
)
_HARNESS_SET = frozenset(ALL_HARNESSES)
NON_WINDOWS_PLATFORMS = frozenset(PLATFORMS - {"windows-x64"})
OUTCOMES = frozenset({"pass", "fail-safe", "degraded"})
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_TEXT = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,95}\Z")
_SAFE_WAIVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,159}\Z")
_FORBIDDEN_VALUE = re.compile(
    r"(?:/Users/|/home/|/private/|\\Users\\|[A-Za-z]:\\|-----BEGIN|"
    r"\b(?:api[_-]?key|password|private[_-]?key|secret|token)\b)",
    re.IGNORECASE,
)
_FORBIDDEN_KEYS = frozenset(
    {
        "command",
        "commands",
        "cwd",
        "home",
        "home_dir",
        "path",
        "payload",
        "raw_output",
        "secret",
        "source",
        "stderr",
        "stdout",
        "token",
    }
)
_MAX_MATRIX_BYTES = 4 * 1024 * 1024


class InstalledMatrixError(ValueError):
    """Raised when installed release evidence is incomplete or unsafe."""


def _safe_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SAFE_TEXT.fullmatch(value) is None:
        raise InstalledMatrixError(f"{label} is not a bounded aggregate label")
    return value


def _reject_sensitive_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise InstalledMatrixError("matrix contains a non-aggregate field")
            _reject_sensitive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_keys(nested)
    elif isinstance(value, str) and _FORBIDDEN_VALUE.search(value):
        raise InstalledMatrixError("matrix contains sensitive aggregate text")


def _scenario_record(
    value: object,
    *,
    platform: str,
    expected_version: str,
) -> tuple[str, dict[str, object]]:
    if not isinstance(value, dict):
        raise InstalledMatrixError("scenario entry must be an object")
    name = _safe_text(value.get("name"), label="scenario")
    if name not in REQUIRED_SCENARIOS:
        raise InstalledMatrixError(f"scenario set is invalid for {platform}")
    if value.get("package_version") != expected_version:
        raise InstalledMatrixError(f"scenario version mismatch for {platform}/{name}")
    fields = ("env_unset", "native_selected", "python_fallback", "path_search", "download_attempted")
    if any(type(value.get(field)) is not bool for field in fields):
        raise InstalledMatrixError(f"scenario field is not boolean for {platform}/{name}")
    if value["env_unset"] is not True:
        raise InstalledMatrixError(f"production environment is not unset for {platform}/{name}")
    if value["python_fallback"] or value["path_search"] or value["download_attempted"]:
        raise InstalledMatrixError(f"unsafe runtime behavior for {platform}/{name}")
    outcome = _safe_text(value.get("outcome"), label="outcome")
    if outcome not in OUTCOMES:
        raise InstalledMatrixError(f"unsupported outcome for {platform}/{name}")
    native_selected = value["native_selected"]
    if name != "fault-injection" and native_selected is not True:
        raise InstalledMatrixError(f"native runtime was not selected for {platform}/{name}")
    if name == "fault-injection" and native_selected is False and outcome == "pass":
        raise InstalledMatrixError(f"fault outcome is inconsistent for {platform}/{name}")
    count = value.get("evidence_count")
    harness_count = value.get("harness_count")
    if type(count) is not int or not 1 <= count <= 1_000_000:
        raise InstalledMatrixError(f"evidence count is invalid for {platform}/{name}")
    if type(harness_count) is not int or not 1 <= harness_count <= 128:
        raise InstalledMatrixError(f"harness count is invalid for {platform}/{name}")
    harnesses = value.get("harnesses")
    if (
        not isinstance(harnesses, list)
        or len(harnesses) != len(ALL_HARNESSES)
        or any(not isinstance(item, str) for item in harnesses)
        or len(set(harnesses)) != len(ALL_HARNESSES)
        or set(harnesses) != _HARNESS_SET
        or harness_count != len(ALL_HARNESSES)
    ):
        raise InstalledMatrixError(f"all-harness coverage is incomplete for {platform}/{name}")
    return name, {
        "name": name,
        "package_version": expected_version,
        "env_unset": True,
        "native_selected": native_selected,
        "python_fallback": False,
        "path_search": False,
        "download_attempted": False,
        "outcome": outcome,
        "evidence_count": count,
        "harness_count": harness_count,
        "harnesses": list(ALL_HARNESSES),
    }


def _platform_record(value: object, *, expected_version: str) -> tuple[str, dict[str, object]]:
    if not isinstance(value, dict):
        raise InstalledMatrixError("platform entry must be an object")
    platform = _safe_text(value.get("platform"), label="platform")
    if platform not in PLATFORMS:
        raise InstalledMatrixError(f"unsupported platform: {platform}")
    if value.get("package_version") != expected_version:
        raise InstalledMatrixError(f"package version mismatch for {platform}")
    runtime_sha = value.get("runtime_sha256")
    if not isinstance(runtime_sha, str) or _SHA64.fullmatch(runtime_sha) is None:
        raise InstalledMatrixError(f"runtime digest is missing for {platform}")
    scenarios = value.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise InstalledMatrixError(f"scenarios are missing for {platform}")
    by_name: dict[str, dict[str, object]] = {}
    for scenario_value in scenarios:
        name, record = _scenario_record(scenario_value, platform=platform, expected_version=expected_version)
        if name in by_name:
            raise InstalledMatrixError(f"scenario set is invalid for {platform}")
        by_name[name] = record
    if set(by_name) != REQUIRED_SCENARIOS:
        raise InstalledMatrixError(f"scenario set is incomplete for {platform}")
    return platform, {
        "platform": platform,
        "package_version": expected_version,
        "runtime_sha256": runtime_sha,
        "scenarios": by_name,
    }


def validate_matrix(
    payload: Mapping[str, object],
    *,
    expected_version: str,
    expected_source_sha: str,
    expected_rule_digest: str,
    windows_waiver: str | None = None,
) -> dict[str, object]:
    """Validate a matrix and return a normalized, privacy-safe projection."""

    _reject_sensitive_keys(payload)
    if payload.get("schema") != "hol-guard-installed-release-matrix.v1":
        raise InstalledMatrixError("unsupported installed matrix schema")
    if payload.get("package_version") != expected_version:
        raise InstalledMatrixError("matrix package version does not match release")
    if payload.get("source_sha") != expected_source_sha or _SHA40.fullmatch(expected_source_sha) is None:
        raise InstalledMatrixError("matrix source SHA does not match release")
    if payload.get("rule_digest") != expected_rule_digest or _SHA64.fullmatch(expected_rule_digest) is None:
        raise InstalledMatrixError("matrix rule digest does not match release")
    if windows_waiver is not None and (
        _SAFE_WAIVER.fullmatch(windows_waiver) is None
        or any(fragment in windows_waiver for fragment in ("/Users/", "/home/", "/tmp/", "\\", "~/", "-----BEGIN"))
    ):
        raise InstalledMatrixError("Windows waiver is not bounded release text")
    entries = payload.get("platforms")
    if not isinstance(entries, list) or not entries:
        raise InstalledMatrixError("matrix has no platform entries")
    normalized: dict[str, dict[str, object]] = {}
    for item in entries:
        platform, record = _platform_record(item, expected_version=expected_version)
        if platform in normalized:
            raise InstalledMatrixError(f"duplicate platform entry: {platform}")
        normalized[platform] = record
    present = set(normalized)
    if not present >= NON_WINDOWS_PLATFORMS:
        raise InstalledMatrixError(
            f"matrix is missing non-Windows platforms: {sorted(NON_WINDOWS_PLATFORMS - present)}"
        )
    if "windows-x64" not in present and not windows_waiver:
        raise InstalledMatrixError("Windows omission requires an explicit waiver")
    if "windows-x64" in present and windows_waiver:
        raise InstalledMatrixError("Windows waiver cannot accompany Windows evidence")
    if set(normalized) - PLATFORMS:
        raise InstalledMatrixError("matrix contains an unsupported platform")
    return {
        "schema": "hol-guard-installed-release-matrix.v1",
        "package_version": expected_version,
        "source_sha": expected_source_sha,
        "rule_digest": expected_rule_digest,
        "platforms": [normalized[key] for key in sorted(normalized)],
        "windows_waiver": windows_waiver,
    }


def _load(path: Path) -> Mapping[str, object]:
    try:
        value = json.loads(_bounded_bytes(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstalledMatrixError("matrix file is not valid JSON") from error
    if not isinstance(value, dict):
        raise InstalledMatrixError("matrix root must be an object")
    return value


def _bounded_bytes(path: Path) -> bytes:
    """Read a bounded regular evidence file without following a symlink."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_MATRIX_BYTES:
        raise InstalledMatrixError("matrix file is not a bounded regular file")
    with path.open("rb") as handle:
        content = handle.read(_MAX_MATRIX_BYTES + 1)
    if len(content) > _MAX_MATRIX_BYTES:
        raise InstalledMatrixError("matrix file is not a bounded regular file")
    return content


def matrix_digest(path: Path) -> str:
    """Return the evidence file digest for a final manifest reference."""

    content = _bounded_bytes(path)
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstalledMatrixError("matrix file is not valid JSON") from error
    if not isinstance(value, dict):
        raise InstalledMatrixError("matrix root must be an object")
    return hashlib.sha256(content).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--windows-waiver")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        normalized = validate_matrix(
            _load(args.matrix),
            expected_version=args.version,
            expected_source_sha=args.source_sha,
            expected_rule_digest=args.rule_digest,
            windows_waiver=args.windows_waiver,
        )
    except InstalledMatrixError as error:
        print(f"Installed matrix validation failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
