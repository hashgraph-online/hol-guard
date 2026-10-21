"""The edge's package-script receipts match what the protected sinks run.

`rust/crates/guard-command/tests/pretool_package_script_routes.rs` classifies
the same fixture cases. A case with a reason must be run by the sink that
reason names; a case without one must be refused by every sink, so the edge
never issues a narrow receipt the sink then rejects.
"""

import json
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_node_tool as tool
from codex_plugin_scanner.guard.runtime.restricted_package_test import (
    PACKAGE_TEST_REASON,
    is_package_test,
    resolve_package_test,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

FIXTURE = Path(__file__).parent / "fixtures" / "package-script-routes.v1.json"
CASES = json.loads(FIXTURE.read_text())["cases"]
NODE_TOOL = "native_node_tool_readonly_containment_required"
NODE_BUILD = "native_node_build_output_containment_required"


def _project(root: Path, case: dict) -> Path:
    project = root / case["name"]
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": case["name"], "scripts": case["scripts"]}))
    for entry in case["entries"]:
        path = project / "node_modules" / entry
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    return project


def _sink_reason(command: list[str], project: Path, monkeypatch) -> str | None:
    if is_package_test(command):
        try:
            resolve_package_test(command, workspace=project, cwd=project)
        except RestrictedPytestError:
            return None
        return PACKAGE_TEST_REASON
    base = SimpleNamespace(workspace=project, cwd=project, executable="/usr/bin/node", denied_capabilities=())
    monkeypatch.setattr(tool, "prepare_restricted_node_test", lambda *args, **kwargs: base)
    monkeypatch.setattr(tool, "replace", lambda original, **changes: SimpleNamespace(**{**vars(original), **changes}))
    try:
        plan = tool.prepare_restricted_node_tool(command, workspace=project, cwd=project)
    except RestrictedPytestError:
        return None
    return NODE_BUILD if plan.profile_version == tool.NODE_BUILD_OUTPUT_PROFILE_VERSION else NODE_TOOL


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_sink_runs_exactly_the_scripts_the_edge_routes_to_it(case, tmp_path, monkeypatch):
    project = _project(tmp_path.resolve(), case)
    assert _sink_reason(shlex.split(case["command"]), project, monkeypatch) == case["reason"]
