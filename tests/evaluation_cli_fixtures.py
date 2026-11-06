"""Synthetic evaluator CLI records shared by source and isolated wheel tests."""

from __future__ import annotations

import copy
import json
import os
import platform
from hashlib import sha256
from pathlib import Path

from codex_plugin_scanner.guard.evaluation_contracts import EVALUATION_PROFILE_SCHEMA_VERSION


def _host_os() -> str:
    value = platform.system().lower()
    return "macos" if value == "darwin" else value


def _host_architecture() -> str:
    value = platform.machine().lower().replace("-", "_")
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(value, value)


def _profile(tmp_path: Path, executable: Path) -> dict[str, object]:
    root = tmp_path
    artifact_digest = "sha256:" + sha256(b"synthetic artifact").hexdigest()
    endpoint = "http://127.0.0.1:8765/receiver"
    return {
        "schemaVersion": EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": "synthetic-cli-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.5.0",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": {
            "product": "synthetic-agent",
            "version": "0.1.0",
            "os": _host_os(),
            "architecture": _host_architecture(),
            "runtimeLocation": "local",
            "requiredPrivilege": ("administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user"),
            "executable": str(executable),
        },
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.5.0",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "b" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root)],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _write_profile(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    executable = tmp_path / "synthetic-agent"
    marker = tmp_path / "host-ran"
    executable.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = \"--version\" ]; then touch '{marker}'; printf '%s\\n' 'synthetic-agent 0.1.0'; exit 0; fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    artifact = tmp_path / "core-fixture.bin"
    artifact.write_bytes(b"synthetic artifact")
    profile = _profile(tmp_path, executable)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, marker, profile


def _result(profile: dict[str, object], *, profile_id: str | None = None) -> dict[str, object]:
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    return {
        "schemaVersion": "guard.evaluation-result.v1",
        "resultId": "result-1",
        "profileId": profile_id if profile_id is not None else profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {"kind": "none"},
            }
        ],
        "summary": {"passed": 1, "failed": 0, "unsupported": 0, "blockedEnvironment": 0, "notRun": 0},
    }


def _payload(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)
