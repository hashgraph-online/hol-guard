"""A Vite config's literal output directory becomes the build's only write grant."""

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import restricted_node_tool as tool
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError
from codex_plugin_scanner.guard.runtime.restricted_vite_output import declared_vite_output


def _dashboard(workspace, config):
    app = workspace / "dashboard"
    app.mkdir(parents=True)
    (app / "package.json").write_text("{}")
    (app / "vite.config.ts").write_text(config)
    return app


def _config(out_dir):
    return (
        'import path, { resolve } from "path";\n'
        "export default defineConfig({\n"
        f"  build: {{ outDir: {out_dir}, emptyOutDir: true }},\n"
        "});\n"
    )


@pytest.mark.parametrize(
    "spelling",
    [
        'resolve(__dirname, "../src/pkg/daemon/static")',
        "path.resolve(__dirname, '../src/pkg/daemon/static')",
        'path.join(__dirname, "../src/pkg/daemon/static")',
        '"../src/pkg/daemon/static"',
    ],
)
def test_a_literal_out_dir_inside_the_workspace_is_the_output_root(tmp_path, spelling):
    app = _dashboard(tmp_path, _config(spelling))
    static = tmp_path / "src/pkg/daemon/static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<html></html>")
    (static / "assets/index-abc.js").write_text("export {}")
    assert declared_vite_output(app, tmp_path) == static
    tool.validate_build_output_root(static, workspace=tmp_path, cwd=app)
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(static, workspace=tmp_path)


def test_a_config_without_out_dir_keeps_the_default(tmp_path):
    app = _dashboard(tmp_path, "export default defineConfig({ plugins: [react()] });\n")
    assert declared_vite_output(app, tmp_path) is None


@pytest.mark.parametrize(
    "spelling",
    [
        "process.env.OUT_DIR",
        "`${root}/static`",
        'resolve(__dirname, "../..")',
        '"../../elsewhere"',
        '"/etc/static"',
        '"."',
        '".."',
        'resolve(__dirname, "../.github/static")',
        '"node_modules/.cache/static"',
        '"../src"',
        '"../other-package/dist"',
        '"../linked/static"',
    ],
)
def test_unverifiable_or_unsafe_out_dirs_are_refused(tmp_path, spelling):
    app = _dashboard(tmp_path / "ws", _config(spelling))
    workspace = tmp_path / "ws"
    (workspace / "src").mkdir()
    (workspace / "src/server.py").write_text("print('source')")
    (workspace / "other-package").mkdir()
    (workspace / "other-package/package.json").write_text("{}")
    (workspace / "linked").symlink_to(tmp_path)
    with pytest.raises(RestrictedPytestError):
        declared_vite_output(app, workspace)


def test_two_out_dirs_are_refused(tmp_path):
    app = _dashboard(tmp_path, _config('"static"') + 'export const other = { outDir: "dist2" };\n')
    with pytest.raises(RestrictedPytestError):
        declared_vite_output(app, tmp_path)


def test_a_nested_package_is_never_emptied_by_a_build(tmp_path):
    app = _dashboard(tmp_path, _config('"../packages"'))
    nested = tmp_path / "packages/lib"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text("{}")
    (nested / "index.js").write_text("export {}")
    with pytest.raises(RestrictedPytestError):
        declared_vite_output(app, tmp_path)


def test_a_directory_holding_sources_is_never_emptied_by_a_build(tmp_path):
    app = _dashboard(tmp_path, _config('"../web"'))
    (tmp_path / "web").mkdir()
    (tmp_path / "web/index.html").write_text("<html></html>")
    (tmp_path / "web/setup.sh").write_text("echo keep")
    with pytest.raises(RestrictedPytestError):
        declared_vite_output(app, tmp_path)


def _plan(monkeypatch, app, workspace, *args):
    entry = app / "node_modules/vite/bin/vite.js"
    entry.parent.mkdir(parents=True)
    entry.write_text("// fixture bundler")
    base = SimpleNamespace(workspace=workspace, cwd=app, executable="/usr/bin/node", denied_capabilities=())
    monkeypatch.setattr(tool, "prepare_restricted_node_test", lambda *a, **kw: base)
    monkeypatch.setattr(tool, "replace", lambda original, **changes: SimpleNamespace(**{**vars(original), **changes}))
    return tool.prepare_restricted_node_tool(
        ["node", "node_modules/vite/bin/vite.js", "build", *args], workspace=workspace
    )


def test_the_build_plan_grants_the_declared_directory(monkeypatch, tmp_path):
    app = _dashboard(tmp_path, _config('resolve(__dirname, "../src/pkg/static")'))
    plan = _plan(monkeypatch, app, tmp_path)
    assert plan.output_roots == (tmp_path / "src/pkg/static", app / "node_modules/.vite-temp")


@pytest.mark.parametrize("args", [("--outDir", "dist"), ("--config", "vite.alt.ts")])
def test_command_line_output_or_config_overrides_the_declared_directory(monkeypatch, tmp_path, args):
    app = _dashboard(tmp_path, _config("process.env.OUT_DIR"))
    plan = _plan(monkeypatch, app, tmp_path, *args)
    assert plan.output_roots[0] == app / "dist"


def test_a_named_config_keeps_its_own_literal_output(tmp_path):
    """`--config` selects that file. It does not discard the outDir the file names."""

    app = _dashboard(tmp_path, _config("process.env.OUT_DIR"))
    (app / "vite.alt.ts").write_text(_config('resolve(__dirname, "../src/pkg/static")'))
    static = tmp_path / "src/pkg/static"
    static.mkdir(parents=True)
    (static / "index.html").write_text("<html></html>")
    assert declared_vite_output(app, tmp_path, config=app / "vite.alt.ts") == static
    assert declared_vite_output(app, tmp_path, config=app / "missing.config.ts") is None


def test_an_explicit_output_still_rechecks_the_bundle_directory(tmp_path):
    app = _dashboard(tmp_path, _config("process.env.OUT_DIR"))
    (app / "node_modules").mkdir()
    bundle = app / "node_modules/.vite-temp"
    tool.validate_build_output_root(bundle, workspace=tmp_path, cwd=app)


def test_the_default_config_loader_gets_only_its_bundle_directory(monkeypatch, tmp_path):
    app = _dashboard(tmp_path, "export default {};\n")
    plan = _plan(monkeypatch, app, tmp_path)
    assert plan.command[-1] == "build"
    assert plan.output_roots == (app / "dist", app / "node_modules/.vite-temp")
    tool.validate_build_output_root(app / "node_modules/.vite-temp", workspace=tmp_path, cwd=app)
    with pytest.raises(RestrictedPytestError):
        tool.validate_build_output_root(app / "node_modules/.vite-temp", workspace=tmp_path)


@pytest.mark.parametrize("args", [("--config", "vite.alt.ts"), ("--configLoader", "native")])
def test_an_explicit_config_or_loader_gets_no_bundle_directory(monkeypatch, tmp_path, args):
    app = _dashboard(tmp_path, "export default {};\n")
    plan = _plan(monkeypatch, app, tmp_path, *args)
    assert plan.output_roots == (app / "dist",)
    assert plan.command[-2:] == (args if "--configLoader" in args else ("--configLoader", "runner"))


@pytest.mark.parametrize("problem", ["linked-temp", "linked-entry", "linked-modules", "other-modules"])
def test_an_unverifiable_bundle_directory_keeps_the_runner_loader(monkeypatch, tmp_path, problem):
    app = _dashboard(tmp_path / "ws", "export default {};\n")
    workspace = tmp_path / "ws"
    modules = app / "node_modules"
    modules.mkdir()
    if problem == "linked-temp":
        (modules / ".vite-temp").symlink_to(tmp_path)
    elif problem == "linked-entry":
        (modules / ".vite-temp").mkdir()
        (modules / ".vite-temp/x.mjs").symlink_to(tmp_path / "elsewhere.mjs")
    elif problem == "linked-modules":
        modules.rmdir()
        (tmp_path / "outside").mkdir()
        modules.symlink_to(tmp_path / "outside")
    assert (
        tool.config_bundle_directory(
            app, workspace, workspace / "node_modules" if problem == "other-modules" else modules
        )
        is None
    )


def test_vite_temp_is_created_only_through_real_directories(tmp_path):
    modules = tmp_path / "app/node_modules"
    modules.mkdir(parents=True)
    created = modules / ".vite-temp"
    tool._create_vite_temp_directory(created, tmp_path)
    assert created.is_dir() and not created.is_symlink()

    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    escaped = linked / "node_modules/.vite-temp"
    (linked / "node_modules").mkdir()
    with pytest.raises(RestrictedPytestError):
        tool._create_vite_temp_directory(escaped, tmp_path)
    assert not (outside / "node_modules/.vite-temp").exists()

    target = tmp_path / "elsewhere"
    target.mkdir()
    planted = modules / ".vite-temp-link"
    planted.symlink_to(target, target_is_directory=True)
    with pytest.raises(RestrictedPytestError):
        tool._create_vite_temp_directory(planted, tmp_path)
    assert planted.is_symlink()


def test_a_linked_ancestor_of_node_modules_is_not_a_bundle_grant(tmp_path):
    app = _dashboard(tmp_path / "ws", "export default {};\n")
    workspace = tmp_path / "ws"
    linked = workspace / "linked"
    linked.symlink_to(app, target_is_directory=True)
    modules = linked / "node_modules"
    modules.mkdir()
    assert tool.config_bundle_directory(linked, workspace, modules) is None
