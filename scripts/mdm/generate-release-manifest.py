#!/usr/bin/env python3
"""Generate a deterministic release manifest before platform signing."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import platform
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "hol-guard-release-manifest.v1"
POLICY_SCHEMA = "hol-guard-mdm-policy.v1"


def _commit() -> str:
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--platform", required=True, choices=("macos", "windows"))
    parser.add_argument("--architecture", default=platform.machine().lower())
    parser.add_argument("--installer-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path)
    parser.add_argument("--key-id")
    args = parser.parse_args()
    root = args.runtime_root.resolve(strict=True)
    output = args.output.resolve()
    files = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.resolve() == output:
            continue
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    payload = {
        "schemaVersion": SCHEMA,
        "version": args.version,
        "buildId": args.build_id,
        "sourceCommit": _commit(),
        "platform": args.platform,
        "architecture": args.architecture,
        "policySchemaVersion": POLICY_SCHEMA,
        "installerIdentity": args.installer_identity,
        "files": files,
    }
    if (args.signing_key is None) != (args.key_id is None):
        parser.error("--signing-key and --key-id must be supplied together")
    if args.signing_key is not None:
        private_key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            parser.error("--signing-key must contain an Ed25519 private key")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        payload["signature"] = {
            "keyId": args.key_id,
            "value": base64.b64encode(private_key.sign(canonical)).decode(),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
