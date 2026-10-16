"""Windows contains a direct Vite build of a flat install, staged in an AppContainer."""

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.adapters.zcode_contained_tests import platform_contains
from codex_plugin_scanner.guard.runtime import restricted_node_tool
from codex_plugin_scanner.guard.runtime.contained_wrapper import peel_contained_wrapper
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError

NODE = r"C:\Users\tester\tools\node\node.exe"
RUNTIME = r"C:\Program Files\HOL Guard\hol-guard-runtime.exe"
PROFILE = "node-build-output-v1"


def _project(tmp_path: Path) -> Path:
    app = tmp_path / "dashboard"
    (app / "node_modules/vite/bin").mkdir(parents=True)
    (app / "package.json").write_text("{}", encoding="utf-8")
    return app


def _plan(workspace: Path, cwd: Path, *, profile: str = PROFILE) -> dict[str, object]:
    entry = (cwd / "node_modules/vite/bin/vite.js").as_posix()
    return {
        "profile_version": profile,
        "backend": "windows-appcontainer",
        "backend_executable": RUNTIME,
        "workspace": str(workspace),
        "cwd": str(cwd),
        "command": [NODE, entry, "build"],
        "executable": NODE,
        "allowed_executables": [NODE],
        "denied_capabilities": ["network", "workspace-source-write"],
    }


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(restricted_node_tool, "_normalized_command", tuple)
    calls: list[tuple[str, dict[str, object]]] = []

    def native(operation, fields, _expected):
        calls.append((operation, dict(fields)))
        return _plan(Path(fields["workspace"]), Path(fields["cwd"]))

    monkeypatch.setattr(restricted_node_tool, "restricted_native", native)
    return calls


def test_node_build_plan_decodes_only_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    plan = transport.decode_native_plan(_plan(tmp_path, tmp_path), (PROFILE,))
    assert plan.backend == "windows-appcontainer"
    with pytest.raises(RestrictedPytestError):
        tool = "node-tool-readonly-v1"
        transport.decode_native_plan(_plan(tmp_path, tmp_path, profile=tool), (tool,))
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(RestrictedPytestError):
        transport.decode_native_plan(_plan(tmp_path, tmp_path), (PROFILE,))


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


@pytest.mark.parametrize(
    "command",
    [
        ["npm", "run", "build"],
        ["npx", "eslint", "src"],
        ["npx", "tsc", "--noEmit"],
    ],
)
def test_windows_refuses_other_node_tools_before_planning(windows, tmp_path, command):
    app = _project(tmp_path)
    (app / "package.json").write_text('{"scripts":{"build":"vite build"}}', encoding="utf-8")
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_node_tool.prepare_restricted_node_tool(command, workspace=tmp_path, cwd=app)
    assert caught.value.reason_code == "pytest_restricted_sandbox_unavailable"
    assert windows == []


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


def test_windows_contains_node_builds(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert platform_contains({"required_execution_profile": PROFILE})
    assert not platform_contains({"required_execution_profile": "node-tool-readonly-v1"})


def test_windows_peels_a_relative_cd_into_the_workspace(monkeypatch, tmp_path):
    app = _project(tmp_path)
    command = "cd dashboard && ./node_modules/.bin/vite build 2>&1 | tail -15"
    monkeypatch.setattr(sys, "platform", "win32")
    core, directory, output = peel_contained_wrapper(command, workspace=tmp_path, cwd=tmp_path)
    assert core == "./node_modules/.bin/vite build"
    assert directory == app.resolve()
    assert output is not None
    assert (output.kind, output.count, output.merge_stderr) == ("tail", 15, True)
    for refused in ("cd dashboard; ./node_modules/.bin/vite build", "cd .. && ./node_modules/.bin/vite build"):
        with pytest.raises((ValueError, OSError)):
            peel_contained_wrapper(refused, workspace=tmp_path, cwd=tmp_path)
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(ValueError):
        peel_contained_wrapper(command, workspace=tmp_path, cwd=tmp_path)
