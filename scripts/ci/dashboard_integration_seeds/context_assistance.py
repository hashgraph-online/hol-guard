"""Opt-in real SDK seed; ordinary dashboard runs never start or enroll CIGAR."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import SeedContext


def seed(context: SeedContext) -> dict[str, Any]:
    selection_path = os.environ.get("GUARD_CIGAR_TEST_SELECTION")
    approval_path = os.environ.get("GUARD_CIGAR_TEST_APPROVAL")
    if not selection_path or not approval_path:
        return {"candidateEnrolled": False}
    binary = os.environ["HOL_GUARD_NATIVE_BINARY"]

    def operator(command: str, request: dict[str, Any]) -> dict[str, Any]:
        result = subprocess.run(
            [binary, command, "--stdin"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        payload = json.loads(result.stdout)
        if payload.get("ok") is not True:
            raise RuntimeError(f"{command} refused the explicitly selected candidate: {payload.get('error')}")
        return payload

    approval = json.loads(Path(approval_path).read_text(encoding="utf-8"))
    runtime_id = "browser-candidate"
    (context.workspace / "README.md").write_text(
        "Integration workspace uses a reviewed release process.\n", encoding="utf-8"
    )
    operator(
        "context-assistance-enroll-local",
        {
            "schema": "guard-cigar-enroll-local.v1",
            "guard_home": str(context.guard_home),
            "runtime_id": runtime_id,
            "local_candidate_approved": True,
            "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
            "selection": json.loads(Path(selection_path).read_text(encoding="utf-8")),
            "approval": approval,
        },
    )
    operator(
        "guard-config-update",
        {
            "schema": "guard-config-update.v1",
            "guard_home": str(context.guard_home),
            "kind": "settings",
            "value_text": json.dumps({"context_assistance": {"enabled": False, "runtime_id": runtime_id}}),
        },
    )
    return {
        "candidateEnrolled": True,
        "runtimeId": runtime_id,
        "workerFingerprint": approval["worker_sha256"],
        "pythonExecutable": sys.executable,
    }
