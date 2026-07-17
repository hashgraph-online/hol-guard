"""Shared helpers for package-shim intercept probes."""

from __future__ import annotations

import json
from typing import Any

from .runtime.package_execution_policy import is_execution_permitted

SHIM_PROBE_ENV_VAR = "HOL_GUARD_SHIM_PROBE"
SHIM_PROBE_ENV_VALUE = "1"

_PACKAGE_SHIM_PROBE_ARGS: dict[str, tuple[str, ...]] = {
    "brew": ("install", "--dry-run", "jq"),
    "npm": ("install", "--dry-run", "lodash@4.17.21"),
    "npx": ("-y", "lodash@4.17.21"),
    "pnpm": ("add", "--dry-run", "lodash@4.17.21"),
    "yarn": ("add", "--dry-run", "lodash@4.17.21"),
    "bun": ("add", "--dry-run", "lodash@4.17.21"),
    "bunx": ("--version",),
    "pip": ("install", "--dry-run", "requests==2.32.3"),
    "pip3": ("install", "--dry-run", "requests==2.32.3"),
    "uv": ("add", "--dry-run", "requests==2.32.3"),
    "poetry": ("add", "--dry-run", "requests@2.32.3"),
    "pipenv": ("install", "--dry-run", "requests==2.32.3"),
    "pipx": ("install", "--dry-run", "requests==2.32.3"),
    "cargo": ("add", "serde@1.0.203"),
    "go": ("install", "-n", "github.com/pkg/errors@v0.9.1"),
    "composer": ("require", "--dry-run", "monolog/monolog:3.6.0"),
    "bundle": ("add", "rails", "--version", "7.1.3"),
}


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
