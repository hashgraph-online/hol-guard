"""Shared helpers for package-shim intercept and execution proofs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_fake_manager_script(
    *,
    fake_bin: Path,
    manager: str,
    marker_path: Path,
    exit_code: int,
    stdout_text: str | None = None,
    stderr_text: str | None = None,
) -> Path:
    """Write a fake package manager that records argv/cwd when invoked."""

    script_path = fake_bin / manager
    script_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "from __future__ import annotations",
                "import json",
                "import os",
                "import sys",
                f"marker_path = {str(marker_path)!r}",
                "payload = {",
                "    'argv': sys.argv,",
                "    'cwd': os.getcwd(),",
                "    'path': os.environ.get('PATH', ''),",
                "    'shim_var': os.environ.get('SHIM_TEST_VAR'),",
                "}",
                "with open(marker_path, 'w', encoding='utf-8') as handle:",
                "    json.dump(payload, handle)",
                f"if {stdout_text!r} is not None:",
                f"    print({stdout_text!r})",
                f"if {stderr_text!r} is not None:",
                f"    print({stderr_text!r}, file=sys.stderr)",
                f"raise SystemExit({exit_code})",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script_path.chmod(script_path.stat().st_mode | 0o755)
    return script_path


def parse_protect_json_output(stdout: str) -> dict[str, Any]:
    """Parse JSON emitted by `hol-guard protect --json`."""

    text = stdout.strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def protect_evaluator_evidence(payload: dict[str, Any]) -> dict[str, object]:
    """Extract evaluator invocation evidence from a protect payload."""

    supply_chain = payload.get("supply_chain_evaluation")
    supply_chain_dict = supply_chain if isinstance(supply_chain, dict) else {}
    verdict = payload.get("verdict")
    verdict_dict = verdict if isinstance(verdict, dict) else {}
    evidence_ids = supply_chain_dict.get("evidence_ids")
    normalized_evidence_ids = (
        [str(item) for item in evidence_ids if isinstance(item, str)]
        if isinstance(evidence_ids, list)
        else []
    )
    return {
        "evaluator_invoked": "supply_chain_evaluation" in payload or "verdict" in payload,
        "protect_decision": verdict_dict.get("action"),
        "evidence_ids": normalized_evidence_ids,
        "dry_run": payload.get("dry_run"),
    }


_MANAGER_PROBE_ARGS: dict[str, tuple[str, ...]] = {
    "npm": ("install", "lodash@4.17.21"),
    "pnpm": ("add", "lodash@4.17.21"),
    "yarn": ("add", "lodash@4.17.21"),
    "bun": ("add", "lodash@4.17.21"),
    "pip": ("install", "requests==2.32.3"),
    "pip3": ("install", "requests==2.32.3"),
    "uv": ("add", "requests==2.32.3"),
    "poetry": ("add", "requests@2.32.3"),
    "pipenv": ("install", "requests==2.32.3"),
    "pipx": ("install", "requests==2.32.3"),
    "cargo": ("add", "serde@1.0.203"),
    "go": ("install", "github.com/pkg/errors@v0.9.1"),
    "composer": ("require", "monolog/monolog:3.6.0"),
    "bundle": ("add", "rails", "--version", "7.1.3"),
}


def manager_probe_args(manager: str) -> tuple[str, ...]:
    """Return install-shaped probe args that route through package protect."""

    return _MANAGER_PROBE_ARGS.get(manager, ("--version",))
