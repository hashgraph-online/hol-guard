"""The trusted Plugin Release workflow pins the composite HOL's verifier trusts."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "plugin-release.yml"
COMPOSITE_USE = re.compile(r"(?m)^[ \t]*(?:-[ \t]+)?uses:[ \t]*hashgraph-online/hol-guard/plugin-release@(\S+)")


def test_the_composite_is_pinned_by_full_commit_sha() -> None:
    pins = COMPOSITE_USE.findall(WORKFLOW.read_text(encoding="utf-8"))

    assert len(pins) == 1
    assert re.fullmatch(r"[0-9a-f]{40}", pins[0])


def test_the_workflow_is_only_callable_and_registers_with_hol() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = workflow.get("on", workflow.get(True))

    assert set(triggers) == {"workflow_call"}
    step = next(item for item in workflow["jobs"]["release"]["steps"] if item.get("id") == "release")
    assert step["with"]["release_endpoint"] == "https://hol.org/api/guard/plugins/releases/attestations"
    assert triggers["workflow_call"]["inputs"]["register_release"]["default"] is True


def test_every_composite_input_is_forwarded() -> None:
    composite = yaml.safe_load((ROOT / "plugin-release" / "action.yml").read_text(encoding="utf-8"))
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(item for item in workflow["jobs"]["release"]["steps"] if item.get("id") == "release")

    assert set(step["with"]) == set(composite["inputs"])
