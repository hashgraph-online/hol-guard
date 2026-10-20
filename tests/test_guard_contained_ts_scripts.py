"""Test-named JavaScript and TypeScript scripts reuse the contained profiles."""

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import restricted_esbuild as esbuild
from codex_plugin_scanner.guard.runtime import restricted_inline_eval as inline
from codex_plugin_scanner.guard.runtime import restricted_vitest as vitest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import (
    NODE_EVAL_READ_ONLY_PROFILE_VERSION,
    VITEST_READ_ONLY_PROFILE_VERSION,
    RestrictedPytestError,
    RestrictedPytestPlan,
)

pytestmark = [
    pytest.mark.usefixtures("native_context_digest"),
    pytest.mark.skipif(os.name != "posix", reason="native preparation requires Unix"),
]


@pytest.fixture(autouse=True)
def native_preparation(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.native_restricted_pytest import native_launch_plan

    binary = tmp_path / "bin/node"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELFnative-fixture")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary.parent))

    def prepare(operation, command, **kwargs):
        workspace = kwargs["workspace"]
        local = workspace / "bin/node"
        if not local.exists():
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(binary.read_bytes())
            local.chmod(0o755)
        monkeypatch.setenv("PATH", str(local.parent))
        kwargs.update(platform="darwin", backend_executable=Path("/usr/bin/true"))
        return native_launch_plan(operation, command, **kwargs)

    monkeypatch.setattr(inline, "native_launch_plan", prepare)
    monkeypatch.setattr(vitest, "native_launch_plan", prepare)


def _workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "src" / "math.test.ts").write_text("export {};\n")
    loader = tmp_path / "node_modules" / "tsx" / "dist" / "loader.mjs"
    loader.parent.mkdir(parents=True)
    loader.write_text("")
    (loader.parent / "cli.mjs").write_text("")
    return tmp_path


@pytest.mark.parametrize(
    "argv",
    [
        ["node", "math.test.mjs"],
        ["node", "--experimental-strip-types", "src/math.test.ts"],
        ["node", "--no-warnings", "--experimental-strip-types", "tests/api.spec.ts", "--verbose"],
        ["node", "--disable-warning=ExperimentalWarning", "test_calc.js"],
        ["nodejs", "tests.js"],
    ],
)
def test_test_named_node_scripts_share_the_inline_profile(argv):
    assert inline.is_inline_eval(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["node", "build.ts"],
        ["node", "math.test.py"],
        ["node", "../math.test.ts"],
        ["node", "/tmp/math.test.ts"],
        ["node", "--import", "./evil.mjs", "math.test.ts"],
        ["node", "--experimental-strip-types"],
        ["node", "./node_modules/tsx/dist/cli.mjs", "src/math.test.ts"],
    ],
)
def test_other_node_scripts_do_not_inherit_the_inline_profile(argv):
    assert not inline.is_inline_eval(argv)


def test_node_test_script_plan_keeps_its_flags(tmp_path, monkeypatch):
    workspace = _workspace(tmp_path)
    argv = ["node", "--experimental-strip-types", "src/math.test.ts", "--verbose"]
    plan = inline.prepare_restricted_inline_eval(argv, workspace=workspace)
    assert plan.profile_version == NODE_EVAL_READ_ONLY_PROFILE_VERSION
    assert plan.command == (str(workspace / "bin/node"), *argv[1:])


@pytest.mark.parametrize("target", ["missing", "outside", "directory"])
def test_node_test_script_must_be_a_workspace_file(tmp_path, monkeypatch, target):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.test.ts"
    outside.write_text("export {};\n")
    if target == "outside":
        (workspace / "math.test.ts").symlink_to(outside)
    elif target == "directory":
        (workspace / "math.test.ts").mkdir()
    with pytest.raises(RestrictedPytestError):
        inline.prepare_restricted_inline_eval(["node", "math.test.ts"], workspace=workspace)


@pytest.mark.parametrize(
    "launcher",
    [["tsx"], ["./node_modules/.bin/tsx"], ["npx", "tsx"], ["npx", "--no-install", "tsx"]],
)
def test_tsx_test_scripts_load_through_the_local_loader(tmp_path, monkeypatch, launcher):
    workspace = _workspace(tmp_path)
    plan = vitest.prepare_restricted_vitest([*launcher, "src/math.test.ts", "--flag"], workspace=workspace)
    loader = (workspace / "node_modules/tsx/dist/loader.mjs").resolve()
    assert plan.profile_version == VITEST_READ_ONLY_PROFILE_VERSION
    # The CLI's IPC server is never started; Node imports the loader directly.
    assert plan.command == (str(workspace / "bin/node"), "--import", loader.as_uri(), "src/math.test.ts", "--flag")


def test_node_tsx_entrypoint_must_be_the_local_package(tmp_path, monkeypatch):
    workspace = _workspace(tmp_path)
    plan = vitest.prepare_restricted_vitest(
        ["node", "./node_modules/tsx/dist/cli.mjs", "src/math.test.ts"], workspace=workspace
    )
    assert plan.command[1] == "--import"
    other = workspace / "vendor" / "tsx" / "dist" / "cli.mjs"
    other.parent.mkdir(parents=True)
    other.write_text("")
    with pytest.raises(RestrictedPytestError):
        vitest.prepare_restricted_vitest(["node", str(other), "src/math.test.ts"], workspace=workspace)


@pytest.mark.parametrize(
    "command",
    [
        ["tsx", "scripts/deploy.ts"],
        ["tsx", "watch", "src/math.test.ts"],
        ["tsx", "../math.test.ts"],
        ["npx", "tsx@latest", "src/math.test.ts"],
        ["npx", "--yes", "tsx", "src/math.test.ts"],
    ],
)
def test_other_tsx_forms_are_not_test_scripts(command):
    assert vitest.tsx_test_invocation(command) is None


@pytest.mark.parametrize("problem", ["no-loader", "outside-script"])
def test_tsx_requires_a_local_loader_and_a_workspace_script(tmp_path, monkeypatch, problem):
    workspace = _workspace(tmp_path / "workspace")
    if problem == "no-loader":
        (workspace / "node_modules/tsx/dist/loader.mjs").unlink()
    else:
        outside = tmp_path / "outside.test.ts"
        outside.write_text("export {};\n")
        (workspace / "src/math.test.ts").unlink()
        (workspace / "src/math.test.ts").symlink_to(outside)
    with pytest.raises(RestrictedPytestError):
        vitest.prepare_restricted_vitest(["tsx", "src/math.test.ts"], workspace=workspace)


def test_group_or_world_writable_transform_image_is_rejected(tmp_path, monkeypatch):
    """Another local account can replace a 0777 image it can reach before the private copy."""
    monkeypatch.setattr(esbuild, "_private_ancestor", lambda _path: False)
    monkeypatch.setattr(esbuild.sys, "platform", "darwin")
    monkeypatch.setattr(esbuild.platform, "machine", lambda: "arm64")
    package = tmp_path / "node_modules/esbuild"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"name":"esbuild","version":"0.25.4"}')
    image = tmp_path / "node_modules/@esbuild/darwin-arm64/bin/esbuild"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\xcf\xfa\xed\xfe" + b"fixture")
    image.chmod(0o777)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    with pytest.raises(RestrictedPytestError):
        esbuild.snapshot_esbuild(tmp_path, private)


def _native_esbuild(root: Path, version: str) -> Path:
    package = root / "node_modules/esbuild"
    package.mkdir(parents=True)
    (package / "package.json").write_text(f'{{"name":"esbuild","version":"{version}"}}')
    image = root / "node_modules/@esbuild/darwin-arm64/bin/esbuild"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"\xcf\xfa\xed\xfe" + version.encode())
    image.chmod(0o700)
    return image


def test_tsx_uses_the_esbuild_nested_beside_its_loader(tmp_path, monkeypatch):
    monkeypatch.setattr(esbuild.sys, "platform", "darwin")
    monkeypatch.setattr(esbuild.platform, "machine", lambda: "arm64")
    workspace = _workspace(tmp_path)
    hoisted = _native_esbuild(workspace, "0.19.12")
    nested = _native_esbuild(workspace / "node_modules/tsx", "0.25.4")
    loader = (workspace / "node_modules/tsx/dist/loader.mjs").resolve()
    plan = RestrictedPytestPlan(
        profile_version=VITEST_READ_ONLY_PROFILE_VERSION,
        backend="macos-seatbelt",
        backend_executable=Path("/usr/bin/sandbox-exec"),
        workspace=workspace,
        cwd=workspace,
        command=("/usr/bin/node", "--import", loader.as_uri(), "src/math.test.ts"),
        executable=Path("/usr/bin/node"),
        allowed_executables=(Path("/usr/bin/node"),),
        denied_capabilities=(),
    )
    holder: dict[str, dict[str, str]] = {}

    def environment(*args, **kwargs):
        return {}

    def linux(plan, *, environment, **kwargs):
        holder["env"] = environment
        return environment

    monkeypatch.setattr(vitest, "_restricted_environment", environment)
    monkeypatch.setattr(vitest, "linux_node_environment", linux)
    monkeypatch.setattr(vitest, "_backend_argv", lambda *args, **kwargs: [])
    captured: dict[str, bytes] = {}

    def launch(*args, **kwargs):
        captured["bytes"] = Path(holder["env"]["ESBUILD_BINARY_PATH"]).read_bytes()
        return 0

    monkeypatch.setattr(vitest, "_run_backend_process", launch)
    checked = []
    assert vitest.run_restricted_node_plan(plan, env={}, authorize_capability=checked.append) == 0
    assert captured["bytes"] == nested.read_bytes()
    assert captured["bytes"] != hoisted.read_bytes()
    assert checked == [(str(nested), "--service=0.25.4", "--ping")]
