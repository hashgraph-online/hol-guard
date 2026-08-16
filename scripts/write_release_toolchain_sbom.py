#!/usr/bin/env python3
"""Verify release tooling, enforce Secrets claims, and write a toolchain SBOM."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

_UV_VERSION_OUTPUT = re.compile(r"^uv\s+(?P<version>\d+\.\d+\.\d+)(?:\s+.*)?$")
_GIT_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_CAPABILITY_MANIFEST = Path("docs/guard/contracts/guard-secrets-capability-evidence.v2.json")
_PRODUCT_BOUNDARIES_MANIFEST = Path("docs/guard/contracts/guard-secrets-product-boundaries.v2.json")
_SOURCE_CAPABILITIES_MANIFEST = Path("docs/guard/contracts/guard-secrets-source-capabilities.v2.json")
_REASON_CODES_MANIFEST = Path("docs/guard/contracts/guard-secrets-reason-codes.v2.json")
_CLAIM_GATE = Path("scripts/ci/guard_secrets_release_claim_gate.py")


class ToolchainVerificationError(RuntimeError):
    """Raised when release tooling or claim evidence is not reviewed and exact."""


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


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ToolchainVerificationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_list(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
        raise ToolchainVerificationError(f"{label} must be a non-empty array of strings")
    result = tuple(cast(list[str], value))
    if len(set(result)) != len(result):
        raise ToolchainVerificationError(f"{label} must contain unique values")
    return result


def resolve_release_commit(repository_root: Path) -> str:
    """Resolve the exact checked-out commit used by the protected build job."""

    result = subprocess.run(
        ["git", "rev-parse", "HEAD^{commit}"],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or _GIT_COMMIT.fullmatch(commit) is None:
        detail = result.stderr.strip() or "git did not return a canonical commit"
        raise ToolchainVerificationError(f"unable to resolve release commit: {detail}")
    return commit


def build_guard_secrets_claim_gate_command(
    *,
    repository_root: Path,
    release_commit: str,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    """Build the complete fail-closed Secrets gate command from checked-in policy."""

    if _GIT_COMMIT.fullmatch(release_commit) is None:
        raise ToolchainVerificationError("release commit must be a full lowercase SHA")
    capability_path = repository_root / _CAPABILITY_MANIFEST
    try:
        capability_payload = _mapping(
            json.loads(capability_path.read_text(encoding="utf-8")),
            label=str(_CAPABILITY_MANIFEST),
        )
    except (json.JSONDecodeError, OSError) as error:
        raise ToolchainVerificationError(f"unable to read Secrets capability policy: {error}") from error
    policy = _mapping(capability_payload.get("claim_policy"), label="claim_policy")
    required_capabilities = _string_list(
        policy.get("required_capabilities"),
        label="claim_policy.required_capabilities",
    )
    public_parity_enabled = policy.get("public_parity_claim_enabled")
    if not isinstance(public_parity_enabled, bool):
        raise ToolchainVerificationError("claim_policy.public_parity_claim_enabled must be boolean")

    command: list[str] = [
        python_executable,
        str(repository_root / _CLAIM_GATE),
        "--manifest",
        str(capability_path),
        "--product-boundaries",
        str(repository_root / _PRODUCT_BOUNDARIES_MANIFEST),
        "--source-capabilities",
        str(repository_root / _SOURCE_CAPABILITIES_MANIFEST),
        "--reason-codes",
        str(repository_root / _REASON_CODES_MANIFEST),
        "--release-commit",
        release_commit,
    ]
    if public_parity_enabled:
        command.append("--require-parity")
    for capability_id in required_capabilities:
        command.extend(("--required-capability", capability_id))
    return tuple(command)


def run_guard_secrets_claim_gate(
    *,
    repository_root: Path,
    release_commit: str,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    """Run the exact checked-in claim gate before release tooling can succeed."""

    command = build_guard_secrets_claim_gate_command(
        repository_root=repository_root,
        release_commit=release_commit,
        python_executable=python_executable,
    )
    result = subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise ToolchainVerificationError(
            f"HOL Guard Secrets release claim gate failed with exit code {result.returncode}: {detail}"
        )
    return command


def write_release_toolchain_sbom(
    *,
    output: Path,
    release_version: str,
    expected_uv_version: str,
    setup_action_ref: str,
    uv_executable: Path | None = None,
    claim_gate_command: Sequence[str] = (),
    release_commit: str | None = None,
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

    properties: list[dict[str, str]] = [
        {"name": "hol-guard:installer-action", "value": "astral-sh/setup-uv"},
        {"name": "hol-guard:installer-action-ref", "value": setup_action_ref},
    ]
    if claim_gate_command:
        properties.extend(
            (
                {"name": "hol-guard:secrets-claim-gate", "value": "passed"},
                {
                    "name": "hol-guard:secrets-claim-gate-command-sha256",
                    "value": hashlib.sha256("\0".join(claim_gate_command).encode("utf-8")).hexdigest(),
                },
            )
        )
    if release_commit is not None:
        if _GIT_COMMIT.fullmatch(release_commit) is None:
            raise ToolchainVerificationError("release commit must be a full lowercase SHA")
        properties.append({"name": "hol-guard:source-commit", "value": release_commit})

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
                "properties": properties,
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
    parser.add_argument("--repository-root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repository_root = (
        args.repository_root.resolve(strict=True)
        if args.repository_root is not None
        else Path(__file__).resolve().parents[1]
    )
    try:
        release_commit = resolve_release_commit(repository_root)
        claim_gate_command = run_guard_secrets_claim_gate(
            repository_root=repository_root,
            release_commit=release_commit,
        )
        write_release_toolchain_sbom(
            output=args.output,
            release_version=args.release_version,
            expected_uv_version=args.expected_uv_version,
            setup_action_ref=args.setup_action_ref,
            uv_executable=args.uv_executable,
            claim_gate_command=claim_gate_command,
            release_commit=release_commit,
        )
    except (OSError, ToolchainVerificationError) as exc:
        print(f"Release toolchain verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
