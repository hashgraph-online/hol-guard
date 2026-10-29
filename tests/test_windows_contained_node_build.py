"""Windows contains a direct local Node tool run of a flat install, staged in an AppContainer.

A Vite build publishes its output directory back; ESLint, no-emit TypeScript
and Prettier in a checking mode publish nothing, so their staged copy is
discarded whole.
"""

import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime import restricted_node_tool
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError
from tests.containment_resident import native_containment_sink

NODE = r"C:\Users\tester\tools\node\node.exe"
RUNTIME = r"C:\Program Files\HOL Guard\hol-guard-runtime.exe"
PROFILE = "node-build-output-v1"
TOOL_PROFILE = "node-tool-readonly-v1"
# What the resident resolves for each tool the route admits.
ENTRIES = {
    "eslint": "node_modules/eslint/bin/eslint.js",
    "tsc": "node_modules/typescript/bin/tsc",
    "vite": "node_modules/vite/bin/vite.js",
    "prettier": "node_modules/prettier/bin/prettier.cjs",
}


def _project(tmp_path: Path) -> Path:
    app = tmp_path / "dashboard"
    (app / "node_modules/vite/bin").mkdir(parents=True)
    (app / "package.json").write_text("{}", encoding="utf-8")
    return app


def _plan(
    workspace: Path,
    cwd: Path,
    *,
    tool: str = "vite",
    arguments: Sequence[str] = ("build",),
    profile: str | None = None,
) -> dict[str, object]:
    build = tool == "vite"
    entry = (cwd / ENTRIES[tool]).as_posix()
    return {
        "profile_version": profile or (PROFILE if build else TOOL_PROFILE),
        "backend": "windows-appcontainer",
        "backend_executable": RUNTIME,
        "workspace": str(workspace),
        "cwd": str(cwd),
        "command": [NODE, entry, *arguments],
        "executable": NODE,
        "allowed_executables": [NODE],
        "denied_capabilities": ["network", "workspace-source-write" if build else "workspace-write"],
    }


# Which spelling names which tool, which modes only report and which arguments
# write are one reading in native authority, tested there
# (`contained_node_tool_tests.rs`). These tests stand the Windows sink on that
# answer and cover what stays here: the staged plan, the output root it names
# and the runner invocation.
def _route(
    tool: str,
    arguments: Sequence[str],
    *,
    expected_entry: str | None = None,
    runtime_arguments: Sequence[str] = (),
) -> dict[str, object]:
    return {
        "kind": "tool",
        "name": tool,
        "mode": "build" if tool == "vite" else "report",
        "expected_entry": expected_entry,
        "entries": [ENTRIES[tool]],
        "arguments": list(arguments),
        "runtime_arguments": list(runtime_arguments),
    }


class _Resident:
    """Native authority's answers, and the questions the sink asked for them."""

    def __init__(self, route: dict[str, object] | RestrictedPytestError) -> None:
        self.route = route
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, operation: str, fields: dict[str, object], _expected: object) -> dict[str, object]:
        self.calls.append((operation, dict(fields)))
        if operation == "node_tool_route":
            if isinstance(self.route, RestrictedPytestError):
                raise self.route
            return self.route
        return _plan(
            Path(str(fields["workspace"])),
            Path(str(fields["cwd"])),
            tool=str(fields["tool"]),
            arguments=[str(word) for word in fields["arguments"]],
        )

    @property
    def staged(self) -> dict[str, object]:
        """The fields the one staging call carried, after the one route read."""
        assert [operation for operation, _ in self.calls] == ["node_tool_route", "prepare_node_build"]
        return self.calls[1][1]


@pytest.fixture
def windows(monkeypatch):
    """Install the resident's answer for a run, and report what it was asked."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(restricted_node_tool, "_normalized_command", tuple)

    def install(route: dict[str, object] | RestrictedPytestError) -> _Resident:
        resident = _Resident(route)
        monkeypatch.setattr(restricted_node_tool, "restricted_native", resident)
        return resident

    return install


@pytest.mark.parametrize("profile", [PROFILE, TOOL_PROFILE])
def test_a_staged_node_plan_decodes_only_on_windows(monkeypatch, tmp_path, profile):
    tool = "vite" if profile == PROFILE else "eslint"
    native = _plan(tmp_path, tmp_path, tool=tool, arguments=["src"])
    monkeypatch.setattr(sys, "platform", "win32")
    assert transport.decode_native_plan(native, (profile,)).backend == "windows-appcontainer"
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(_plan(tmp_path, tmp_path, tool=tool, profile="vitest-readonly-v1"), (profile,))
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(native, (profile,))


@pytest.mark.parametrize(
    ("arguments", "expected_entry", "output"),
    [
        (["build"], None, "dist"),
        (["build", "--outDir", "build"], None, "build"),
        (["build"], "node_modules/vite/bin/vite.js", "dist"),
    ],
)
def test_windows_vite_build_is_planned_by_the_resident(windows, tmp_path, arguments, expected_entry, output):
    app = _project(tmp_path)
    resident = windows(_route("vite", arguments, expected_entry=expected_entry))
    plan = restricted_node_tool.prepare_restricted_node_tool(["vite", *arguments], workspace=tmp_path, cwd=app)
    assert resident.staged["arguments"] == arguments
    assert resident.staged["expected_entry"] == expected_entry
    assert plan.profile_version == PROFILE
    assert plan.output_roots == (app / output,)
    # The private copy is writable; no config loader is forced.
    assert "--configLoader" not in plan.command


def test_the_runner_outlives_the_builds_own_deadline(windows, monkeypatch, tmp_path):
    """The runner stages a copy of the workspace and publishes the output
    around the build, neither of which the build's deadline covers. Killing it
    on that same number would land mid-publish."""
    app = _project(tmp_path)
    windows(_route("vite", ["build"]))
    plan = restricted_node_tool.prepare_restricted_node_tool(["npx", "vite", "build"], workspace=tmp_path, cwd=app)
    launched: list[tuple[list[str], int]] = []

    def launch(argv, **keywords):
        launched.append((list(argv), keywords["timeout_seconds"]))
        return 0

    monkeypatch.setattr(restricted_node_tool, "_run_backend_process", launch)
    assert restricted_node_tool.run_restricted_node_tool(plan, timeout_seconds=600) == 0
    argv, waited = launched[0]
    assert argv[argv.index("--timeout-seconds") + 1] == "600"
    assert waited > 600


@pytest.mark.parametrize(
    ("tool", "arguments", "expected_entry"),
    [
        ("eslint", ["src"], None),
        ("tsc", ["--noEmit"], None),
        ("prettier", ["--check", "src"], None),
        ("eslint", ["src"], "node_modules/eslint/bin/eslint.js"),
    ],
)
def test_windows_plans_reporting_node_tools_contained(windows, tmp_path, tool, arguments, expected_entry):
    """Lint, typecheck and format checks reach the same resident the build does."""
    app = _project(tmp_path)
    resident = windows(_route(tool, arguments, expected_entry=expected_entry))
    plan = restricted_node_tool.prepare_restricted_node_tool([tool, *arguments], workspace=tmp_path, cwd=app)
    fields = resident.staged
    assert fields["tool"] == tool
    assert fields["arguments"] == arguments
    assert fields["expected_entry"] == expected_entry
    assert plan.profile_version == TOOL_PROFILE
    # Nothing is published back, so the staged copy is discarded whole.
    assert plan.output_roots == ()
    assert "workspace-write" in plan.denied_capabilities


def test_windows_stages_nothing_a_refused_route_names(windows, tmp_path):
    """A package script, a rewriting argument and an unknown tool are all
    refused where the route is read. Windows stages nothing after that answer,
    so a refusal never reaches the resident as a run to prepare."""
    app = _project(tmp_path)
    (app / "package.json").write_text('{"scripts":{"build":"vite build"}}', encoding="utf-8")
    resident = windows(RestrictedPytestError("node_tool_invalid_command", "The input has write or shell effects."))
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(
            [r"C:\Program Files\nodejs\npm.exe", "run", "build"], workspace=tmp_path, cwd=app
        )
    assert caught.value.reason_code == "node_tool_invalid_command"
    assert [operation for operation, _ in resident.calls] == ["node_tool_route"]


def test_windows_reporting_tools_run_without_publishing_an_output(windows, monkeypatch, tmp_path):
    app = _project(tmp_path)
    windows(_route("eslint", ["src"]))
    plan = restricted_node_tool.prepare_restricted_node_tool(["npx", "eslint", "src"], workspace=tmp_path, cwd=app)
    calls: list[list[str]] = []
    monkeypatch.setattr(restricted_node_tool, "_run_backend_process", lambda argv, **_: calls.append(list(argv)) or 0)
    assert restricted_node_tool.run_restricted_node_tool(plan, timeout_seconds=30) == 0
    assert calls[0] == [
        RUNTIME,
        "contained-readonly-windows",
        "--profile",
        TOOL_PROFILE,
        "--workspace",
        str(tmp_path),
        "--cwd",
        str(app),
        "--timeout-seconds",
        "30",
        "--",
        *plan.command,
    ]


def test_a_reporting_plan_that_names_an_output_is_refused(windows, tmp_path):
    """Only a build publishes. A reporting plan carrying an output root would
    write into the live workspace, so the run side refuses it outright."""
    app = _project(tmp_path)
    windows(_route("eslint", ["src"]))
    plan = restricted_node_tool.prepare_restricted_node_tool(["npx", "eslint", "src"], workspace=tmp_path, cwd=app)
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.run_restricted_node_tool(replace(plan, output_roots=(app / "dist",)), timeout_seconds=30)
    assert caught.value.reason_code == "node_tool_invalid_command"


def test_windows_build_output_must_be_conventional(windows, tmp_path):
    app = _project(tmp_path)
    windows(_route("vite", ["build", "--outDir", "src"]))
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(
            ["npx", "vite", "build", "--outDir", "src"], workspace=tmp_path, cwd=app
        )
    assert caught.value.reason_code == "node_build_invalid_output"


def test_windows_build_runs_through_the_native_runner(windows, monkeypatch, tmp_path):
    app = _project(tmp_path)
    windows(_route("vite", ["build"]))
    plan = restricted_node_tool.prepare_restricted_node_tool(
        ["./node_modules/.bin/vite", "build"], workspace=tmp_path, cwd=app
    )
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return 0

    monkeypatch.setattr(restricted_node_tool, "_run_backend_process", run)
    assert restricted_node_tool.run_restricted_node_tool(plan, timeout_seconds=30) == 0
    argv, kwargs = calls[0]
    assert argv == [
        RUNTIME,
        "contained-readonly-windows",
        "--profile",
        PROFILE,
        "--workspace",
        str(tmp_path),
        "--cwd",
        str(app),
        "--timeout-seconds",
        "30",
        "--output",
        str(app / "dist"),
        "--",
        *plan.command,
    ]
    assert kwargs["cwd"] == app
    assert not (app / "node_modules/.vite-temp").exists()


def test_windows_contains_every_staged_node_profile(containment_resident, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "vite build"}}

    def sink(reason: str, profile: str) -> tuple[str | None, str | None]:
        receipt = {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": reason,
            "required_execution_profile": profile,
        }
        return native_containment_sink(
            receipt, harness="claude-code", bridge=False, payload=payload, guard_home=containment_resident
        )

    assert sink("native_node_build_output_containment_required", PROFILE) == (PROFILE, None)
    assert sink("native_node_tool_readonly_containment_required", TOOL_PROFILE) == (TOOL_PROFILE, None)
    package = sink("native_package_test_readonly_containment_required", "package-test-readonly-v1")
    assert package == (None, "platform_has_no_sink")
