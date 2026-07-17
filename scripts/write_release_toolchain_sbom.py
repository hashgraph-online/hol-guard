#!/usr/bin/env python3
"""Verify uv and write a CycloneDX release-toolchain SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

_UV_VERSION_OUTPUT = re.compile(r"^uv\s+(?P<version>\d+\.\d+\.\d+)(?:\s+.*)?$")


class ToolchainVerificationError(RuntimeError):
    """Raised when the installed release toolchain is not the reviewed toolchain."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _installed_uv_version(executable: Path) -> str:
    result = subprocess.run(
        [str(executable), "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ToolchainVerificationError(f"uv --version failed with exit code {result.returncode}")
    match = _UV_VERSION_OUTPUT.fullmatch(result.stdout.strip())
    if match is None:
        raise ToolchainVerificationError("uv returned an unrecognized version string")
    return match.group("version")


def write_release_toolchain_sbom(
    *,
    output: Path,
    release_version: str,
    expected_uv_version: str,
    setup_action_ref: str,
    uv_executable: Path | None = None,
) -> dict[str, object]:
    """Verify the exact uv runtime and persist its digest as CycloneDX."""

    resolved_executable = uv_executable
    if resolved_executable is None:
        discovered = shutil.which("uv")
        if discovered is None:
            raise ToolchainVerificationError("uv is not available on PATH")
        resolved_executable = Path(discovered)
    resolved_executable = resolved_executable.resolve(strict=True)
    actual_uv_version = _installed_uv_version(resolved_executable)
    if actual_uv_version != expected_uv_version:
        raise ToolchainVerificationError(
            f"uv version mismatch: expected {expected_uv_version}, received {actual_uv_version}"
        )

    payload: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "hol-guard-release-toolchain",
                "version": release_version,
            }
        },
        "components": [
            {
                "type": "application",
                "name": "uv",
                "version": actual_uv_version,
                "hashes": [{"alg": "SHA-256", "content": _sha256(resolved_executable)}],
                "properties": [
                    {"name": "hol-guard:installer-action", "value": "astral-sh/setup-uv"},
                    {"name": "hol-guard:installer-action-ref", "value": setup_action_ref},
                ],
            }
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--expected-uv-version", required=True)
    parser.add_argument("--setup-action-ref", required=True)
    parser.add_argument("--uv-executable", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        write_release_toolchain_sbom(
            output=args.output,
            release_version=args.release_version,
            expected_uv_version=args.expected_uv_version,
            setup_action_ref=args.setup_action_ref,
            uv_executable=args.uv_executable,
        )
    except (OSError, ToolchainVerificationError) as exc:
        print(f"Release toolchain verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
