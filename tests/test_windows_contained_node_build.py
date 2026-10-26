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
from codex_plugin_scanner.guard.native_hook_containment_route import native_containment_sink
from codex_plugin_scanner.guard.runtime import restricted_node_tool
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

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


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(restricted_node_tool, "_normalized_command", tuple)
    calls: list[tuple[str, dict[str, object]]] = []

    def native(operation, fields, _expected):
        calls.append((operation, dict(fields)))
        return _plan(
            Path(fields["workspace"]),
            Path(fields["cwd"]),
            tool=str(fields["tool"]),
            arguments=list(fields["arguments"]),
        )

    monkeypatch.setattr(restricted_node_tool, "restricted_native", native)
    return calls


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
    ("command", "expected_entry", "output"),
    [
        (["./node_modules/.bin/vite", "build"], None, "dist"),
        (["npx", "vite", "build", "--outDir", "build"], None, "build"),
        (["node", "node_modules/vite/bin/vite.js", "build"], "node_modules/vite/bin/vite.js", "dist"),
    ],
)
def test_windows_vite_build_is_planned_by_the_resident(windows, tmp_path, command, expected_entry, output):
    app = _project(tmp_path)
    plan = restricted_node_tool.prepare_restricted_node_tool(command, workspace=tmp_path, cwd=app)
    assert [operation for operation, _ in windows] == ["prepare_node_build"]
    fields = windows[0][1]
    assert fields["arguments"] == list(command[command.index("build") :])
    assert fields["expected_entry"] == expected_entry
    assert plan.profile_version == PROFILE
    assert plan.output_roots == (app / output,)
    # The private copy is writable; no config loader is forced.
    assert "--configLoader" not in plan.command


def test_a_resolved_image_is_the_program_it_names(windows, tmp_path):
    """Windows hands over `node.exe`, which is the program the receipt names."""
    app = _project(tmp_path)
    entry = "node_modules/vite/bin/vite.js"
    for runner in (NODE, "node.exe", "node.EXE"):
        windows.clear()
        plan = restricted_node_tool.prepare_restricted_node_tool([runner, entry, "build"], workspace=tmp_path, cwd=app)
        assert [operation for operation, _ in windows] == ["prepare_node_build"]
        assert windows[0][1]["expected_entry"] == entry
        assert windows[0][1]["arguments"] == ["build"]
        assert plan.profile_version == PROFILE
        assert plan.output_roots == (app / "dist",)


def test_the_runner_outlives_the_builds_own_deadline(windows, monkeypatch, tmp_path):
    """The runner stages a copy of the workspace and publishes the output
    around the build, neither of which the build's deadline covers. Killing it
    on that same number would land mid-publish."""
    app = _project(tmp_path)
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


def test_a_resolved_package_manager_image_is_still_a_package_script(windows, tmp_path):
    """`npm.exe run build` runs the same script `npm run build` does, which
    this sink does not run on Windows. Reading the image name as an unknown
    tool would have planned a direct build the command never asked for."""
    app = _project(tmp_path)
    (app / "package.json").write_text('{"scripts":{"build":"vite build"}}', encoding="utf-8")
    for runner in (r"C:\Program Files\nodejs\npm.exe", "pnpm.exe", "bun.exe"):
        with pytest.raises(RestrictedPytestError) as caught:
            restricted_node_tool.prepare_restricted_node_tool([runner, "run", "build"], workspace=tmp_path, cwd=app)
        assert caught.value.reason_code == "pytest_restricted_sandbox_unavailable"
    assert windows == []


@pytest.mark.parametrize("command", [["npm", "run", "build"], ["pnpm", "run", "lint"]])
def test_windows_refuses_package_scripts_before_planning(windows, tmp_path, command):
    """The package-script route is a separate gate and stays shut here."""
    app = _project(tmp_path)
    (app / "package.json").write_text('{"scripts":{"build":"vite build","lint":"eslint src"}}', encoding="utf-8")
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(command, workspace=tmp_path, cwd=app)
    assert caught.value.reason_code == "pytest_restricted_sandbox_unavailable"
    assert windows == []


@pytest.mark.parametrize(
    ("command", "tool", "expected_entry"),
    [
        (["npx", "eslint", "src"], "eslint", None),
        (["./node_modules/.bin/eslint", ".", "--max-warnings", "0"], "eslint", None),
        (["npx", "tsc", "--noEmit"], "tsc", None),
        (["pnpm", "exec", "tsc", "--noEmit", "-p", "tsconfig.json"], "tsc", None),
        (["npm", "exec", "tsc", "--noEmit"], "tsc", None),
        (["npm", "x", "--", "eslint", "src"], "eslint", None),
        (["yarn", "exec", "prettier", "--check", "src"], "prettier", None),
        (["npx", "prettier", "--check", "src"], "prettier", None),
        (["bunx", "prettier", "-l", "."], "prettier", None),
        (
            ["node", "node_modules/eslint/bin/eslint.js", "src"],
            "eslint",
            "node_modules/eslint/bin/eslint.js",
        ),
    ],
)
def test_windows_plans_reporting_node_tools_contained(windows, tmp_path, command, tool, expected_entry):
    """Lint, typecheck and format checks reach the same resident the build does."""
    app = _project(tmp_path)
    plan = restricted_node_tool.prepare_restricted_node_tool(command, workspace=tmp_path, cwd=app)
    assert [operation for operation, _ in windows] == ["prepare_node_build"]
    fields = windows[0][1]
    assert fields["tool"] == tool
    assert fields["expected_entry"] == expected_entry
    assert plan.profile_version == TOOL_PROFILE
    # Nothing is published back, so the staged copy is discarded whole.
    assert plan.output_roots == ()
    assert "workspace-write" in plan.denied_capabilities


@pytest.mark.parametrize(
    "command",
    [
        ["npx", "eslint", "src", "--fix"],
        ["npx", "eslint", "src", "--output-file=report.json"],
        ["npx", "tsc"],
        ["npx", "tsc", "--noEmit", "--emitDeclarationOnly"],
        ["npx", "prettier", "src"],
        ["npx", "prettier", "--write", "src"],
    ],
)
def test_windows_refuses_node_tool_runs_that_rewrite_their_input(windows, tmp_path, command):
    app = _project(tmp_path)
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(command, workspace=tmp_path, cwd=app)
    assert caught.value.reason_code == "node_tool_invalid_command"
    assert windows == []


def test_windows_reporting_tools_run_without_publishing_an_output(windows, monkeypatch, tmp_path):
    app = _project(tmp_path)
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
    plan = restricted_node_tool.prepare_restricted_node_tool(["npx", "eslint", "src"], workspace=tmp_path, cwd=app)
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.run_restricted_node_tool(replace(plan, output_roots=(app / "dist",)), timeout_seconds=30)
    assert caught.value.reason_code == "node_tool_invalid_command"


def test_windows_build_output_must_be_conventional(windows, tmp_path):
    app = _project(tmp_path)
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(
            ["npx", "vite", "build", "--outDir", "src"], workspace=tmp_path, cwd=app
        )
    assert caught.value.reason_code == "node_build_invalid_output"


def test_windows_build_runs_through_the_native_runner(windows, monkeypatch, tmp_path):
    app = _project(tmp_path)
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
