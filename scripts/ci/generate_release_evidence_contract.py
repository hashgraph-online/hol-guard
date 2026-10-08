#!/usr/bin/env python3
"""Create bounded contract fixtures for the release-evidence workflow.

The release workflow produces real artifact and installed-matrix evidence in
the platform-specific jobs.  This small contract job still exercises the
validators on every change, using deterministic aggregate-only fixtures when
those platform artifacts are not available in the pull-request job.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Final

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.ci.final_release_evidence import REQUIRED_GATES  # noqa: E402
from scripts.ci.verify_installed_release_matrix import ALL_HARNESSES, REQUIRED_SCENARIOS  # noqa: E402

_PLATFORMS: Final = ("manylinux-x64", "macos-arm64", "macos-x64")
_WINDOWS_WAIVER: Final = "contract-fixture"
_SCENARIOS: Final = tuple(sorted(REQUIRED_SCENARIOS))


def _write_json(path: Path, payload: object) -> str:
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(rendered, encoding="utf-8")
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _installed_matrix(version: str, source_sha: str, rule_digest: str) -> dict[str, object]:
    platforms: list[dict[str, object]] = []
    for platform in _PLATFORMS:
        scenarios = [
            {
                "name": scenario,
                "package_version": version,
                "env_unset": True,
                "native_selected": True,
                "python_fallback": False,
                "path_search": False,
                "download_attempted": False,
                "outcome": "pass",
                "evidence_count": 1,
                "harness_count": len(ALL_HARNESSES),
                "harnesses": list(ALL_HARNESSES),
            }
            for scenario in _SCENARIOS
        ]
        platforms.append(
            {
                "platform": platform,
                "package_version": version,
                "runtime_sha256": "0" * 64,
                "scenarios": scenarios,
            }
        )
    return {
        "schema": "hol-guard-installed-release-matrix.v1",
        "package_version": version,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "platforms": platforms,
    }


def generate(output_dir: Path, *, version: str, source_sha: str, rule_digest: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = output_dir / "installed-release-matrix.json"
    matrix_digest = _write_json(matrix_path, _installed_matrix(version, source_sha, rule_digest))

    artifact_path = output_dir / "artifact-evidence.json"
    artifact_digest = _write_json(
        artifact_path,
        {
            "schema": "hol-guard-release-artifact-evidence.v1",
            "package_version": version,
            "source_sha": source_sha,
            "rule_digest": rule_digest,
            "platforms": list(_PLATFORMS),
            "windows_waiver": _WINDOWS_WAIVER,
            "status": "pass",
        },
    )
    desktop_path = output_dir / "desktop-core-evidence.json"
    desktop_digest = _write_json(
        desktop_path,
        {
            "schema": "hol-guard-desktop-core-evidence.v1",
            "package_version": version,
            "source_sha": source_sha,
            "status": "pass",
        },
    )
    _write_json(
        output_dir / "final-release-evidence.json",
        {
            "schema": "hol-guard-final-release-evidence.v1",
            "release": {
                "version": version,
                "source_sha": source_sha,
                "rule_digest": rule_digest,
                "commit_sha": source_sha,
                "base_sha": source_sha,
            },
            "evidence": {
                "artifacts": {"name": artifact_path.name, "sha256": artifact_digest, "status": "pass"},
                "desktop_core": {"name": desktop_path.name, "sha256": desktop_digest, "status": "pass"},
                "installed_matrix": {"name": matrix_path.name, "sha256": matrix_digest, "status": "pass"},
            },
            "gates": {gate: True for gate in REQUIRED_GATES},
            "review": {
                "ci_run": "contract-fixture",
                "exact_head": True,
                "unresolved_non_outdated": 0,
                "pending_required": 0,
            },
            "coverage": {
                "platforms": list(_PLATFORMS),
                "windows": {"status": "waived", "reason": _WINDOWS_WAIVER},
            },
            "approval": {
                "capable": False,
                "status": "fail_closed_external_provisioning_required",
                "root_configured": False,
                "signer_ceremony": False,
            },
            "reproducibility": {
                "deterministic": True,
                "commands": [
                    "validate_installed_release_matrix",
                    "validate_final_release_evidence",
                ],
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    generate(args.output_dir, version=args.version, source_sha=args.source_sha, rule_digest=args.rule_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
