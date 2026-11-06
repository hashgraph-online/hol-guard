"""Shared helpers for package-shim intercept and execution proofs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.runtime.package_execution_policy import is_execution_permitted
from codex_plugin_scanner.guard.shim_probe import _PACKAGE_SHIM_PROBE_ARGS
from codex_plugin_scanner.guard.stable_digest import sha256_content_digest

__all__ = [
    "manager_probe_args",
    "parse_protect_json_output",
    "protect_evaluator_evidence",
    "write_fake_manager_script",
]


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


def parse_protect_json_output(stdout: str):
    """Backward-compatible alias for protect stdout parsing."""

    return parse_protect_json_stdout(stdout)


def manager_probe_args(manager: str) -> tuple[str, ...]:
    """Backward-compatible alias for install-shaped probe args."""

    return package_shim_probe_args(manager)


def package_shim_probe_args(manager: str) -> tuple[str, ...]:
    """Return install-shaped probe args that route through package protect."""

    return _PACKAGE_SHIM_PROBE_ARGS.get(manager, ("--version",))


def parse_protect_json_stdout(stdout: str) -> dict[str, Any]:
    """Parse the first JSON object emitted by `hol-guard protect --json`."""

    text = stdout.lstrip()
    if not text:
        return {}
    decoder = json.JSONDecoder()
    try:
        payload, _index = decoder.raw_decode(text)
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
        [str(item) for item in evidence_ids if item is not None] if isinstance(evidence_ids, list) else []
    )
    evaluator_source = supply_chain_dict.get("source")
    if not isinstance(evaluator_source, str) or not evaluator_source.strip():
        evaluator_source = supply_chain_dict.get("decision_source")
    if not isinstance(evaluator_source, str) or not evaluator_source.strip():
        evaluator_source = verdict_dict.get("source")
    if not isinstance(evaluator_source, str) or not evaluator_source.strip():
        evaluator_source = "local-heuristic"
    policy_action = supply_chain_dict.get("policy_action")
    if not isinstance(policy_action, str):
        policy_action = verdict_dict.get("action")
    return {
        "evaluator_invoked": "supply_chain_evaluation" in payload or "verdict" in payload,
        "evaluator_source": evaluator_source,
        "protect_decision": verdict_dict.get("action"),
        "execution_permitted": is_execution_permitted(policy_action),
        "evidence_ids": normalized_evidence_ids,
        "dry_run": payload.get("dry_run"),
    }


def build_shim_content_hash(content: bytes) -> str:
    """Expected manifest content hash of generated shim bytes (hex SHA-256)."""

    return sha256_content_digest(content)
