"""Bounded executable identity probes for native release assembly."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

_MAX_CAPABILITIES_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class RuntimeCapabilities:
    protocol_version: int
    runtime_version: str
    rule_digest: str
    build_sha: str


def runtime_capabilities(path: Path, error_type) -> RuntimeCapabilities:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "COMSPEC",
            "HOME",
            "LANG",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "WINDIR",
        }
        or key.upper().startswith("LC_")
    }
    try:
        completed = subprocess.run(
            (str(path.resolve(strict=True)), "capabilities", "--json"),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5.0,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise error_type("runtime capabilities probe failed") from exc
    if completed.returncode != 0 or len(completed.stdout) > _MAX_CAPABILITIES_BYTES:
        raise error_type("runtime capabilities probe failed")
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_type("runtime capabilities response is invalid") from exc
    if not isinstance(payload, dict):
        raise error_type("runtime capabilities response is invalid")
    protocol_version = payload.get("protocol_version")
    runtime_version = payload.get("runtime_version")
    rule_digest = payload.get("rule_digest")
    build_sha = payload.get("build_sha")
    if (
        not isinstance(protocol_version, int)
        or not isinstance(runtime_version, str)
        or not isinstance(rule_digest, str)
        or not isinstance(build_sha, str)
    ):
        raise error_type("runtime capabilities response is invalid")
    return RuntimeCapabilities(
        protocol_version=protocol_version,
        runtime_version=runtime_version,
        rule_digest=rule_digest,
        build_sha=build_sha,
    )
