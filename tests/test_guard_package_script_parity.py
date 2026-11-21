"""The edge's package-script receipts match what the protected sinks run.

`rust/crates/guard-command/tests/pretool_package_script_routes.rs` classifies
the same fixture cases. A case with a reason must be run by the sink that
reason names; a case without one must be refused by every sink, so the edge
never issues a narrow receipt the sink then rejects.
"""

import json
import shlex
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_package_test import (
    PACKAGE_TEST_REASON,
    resolve_package_test,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError
from tests.restricted_native_clients import is_package_test

FIXTURE = Path(__file__).parent / "fixtures" / "package-script-routes.v1.json"
CASES = json.loads(FIXTURE.read_text())["cases"]


def _project(root: Path, case: dict) -> Path:
    project = root / case["name"]
    project.mkdir()
    (project / "package.json").write_text(json.dumps({"name": case["name"], "scripts": case["scripts"]}))
    for entry in case["entries"]:
        path = project / "node_modules" / entry
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    return project


def _sink_reason(command: list[str], project: Path) -> str | None:
    try:
        resolve_package_test(command, workspace=project, cwd=project)
    except RestrictedPytestError:
        return None
    return PACKAGE_TEST_REASON


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_sink_runs_exactly_the_scripts_the_edge_routes_to_it(case, tmp_path):
    project = _project(tmp_path.resolve(), case)
    command = shlex.split(case["command"])
    if not is_package_test(command):
        # The Node tool sink plans natively; `node_tool_plan_tests.rs` reads
        # these cases against the plan it builds.
        assert case["reason"] != PACKAGE_TEST_REASON
        return
    assert _sink_reason(command, project) == case["reason"]
