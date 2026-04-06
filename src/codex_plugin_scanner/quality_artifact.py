"""Submission artifact generation for plugin quality results."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

from codex_plugin_scanner.models import ScanResult
from codex_plugin_scanner.policy import PolicyEvaluation
from codex_plugin_scanner.reporting import build_json_payload
from codex_plugin_scanner.verification import VerificationResult
from codex_plugin_scanner.version import __version__

DEFAULT_EXCLUSIONS = (".git/*", "*.pyc", "__pycache__/*", ".venv/*", "dist/*", "build/*")
DEFAULT_EXCLUDED_DIRECTORIES = frozenset({".git", "__pycache__", ".venv", "build", "dist"})


def _is_excluded(relative_path: str, exclusions: tuple[str, ...]) -> bool:
    return any(fnmatch(relative_path, pattern) for pattern in exclusions)


def _digest_plugin(plugin_dir: Path, exclusions: tuple[str, ...] = DEFAULT_EXCLUSIONS) -> dict[str, object]:
    hasher = hashlib.sha256()
    included = 0
    for root, dir_names, file_names in os.walk(plugin_dir):
        current_root = Path(root)
        dir_names[:] = sorted(name for name in dir_names if name not in DEFAULT_EXCLUDED_DIRECTORIES)
        for file_name in sorted(file_names):
            path = current_root / file_name
            relative = path.relative_to(plugin_dir).as_posix()
            if _is_excluded(relative, exclusions):
                continue
            included += 1
            hasher.update(relative.encode("utf-8"))
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
    return {
        "algorithm": "sha256",
        "value": hasher.hexdigest(),
        "included_files": included,
        "exclusions": list(exclusions),
    }


def build_quality_artifact(
    plugin_dir: Path,
    scan_result: ScanResult,
    verification: VerificationResult,
    policy: PolicyEvaluation,
    profile: str,
    *,
    raw_score: int | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "plugin-quality.v1",
        "tool_version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "digest": _digest_plugin(plugin_dir),
        "scan": {
            "score": scan_result.score,
            "raw_score": scan_result.score if raw_score is None else raw_score,
            "effective_score": scan_result.score,
            "grade": scan_result.grade,
            "findings_total": len(scan_result.findings),
            "severity_counts": scan_result.severity_counts,
            "trust": build_json_payload(scan_result)["trust"],
        },
        "verify": {
            "verify_pass": verification.verify_pass,
            "workspace": verification.workspace,
            "cases": [asdict(case) for case in verification.cases],
        },
        "policy": {
            "policy_pass": policy.policy_pass,
            "severity_failures": list(policy.severity_failures),
            "missing_required_rules": list(policy.missing_required_rules),
            "failed_required_pass_rules": list(policy.failed_required_pass_rules),
        },
    }


def write_quality_artifact(path: Path, artifact: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
