"""Isolated daemon dependency loading for pipx installations."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


@pytest.mark.parametrize("symlinked_home", [False, True])
@pytest.mark.parametrize("different_shared_suffix", [False, True])
def test_pipx_daemon_imports_shared_dependencies_without_running_startup_hooks(
    tmp_path, monkeypatch, symlinked_home, different_shared_suffix
):
    pipx_home = tmp_path / "pipx"
    prefix = pipx_home / "venvs" / "hol-guard"
    relative_library = Path("lib") / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    local_library = prefix / relative_library
    shared_suffix = Path("lib/guard-test/site-packages") if different_shared_suffix else relative_library
    shared_library = pipx_home / "shared" / shared_suffix
    local_library.mkdir(parents=True)
    shared_library.mkdir(parents=True)
    if different_shared_suffix:
        (local_library / "pipx_shared.pth").write_text(f"{shared_library}\n", encoding="utf-8")
    configured_prefix = prefix
    configured_library = local_library
    if symlinked_home:
        linked_home = tmp_path / "linked-pipx"
        linked_home.symlink_to(pipx_home, target_is_directory=True)
        configured_prefix = linked_home / "venvs" / "hol-guard"
        configured_library = configured_prefix / relative_library
    ambient_library = tmp_path / "ambient"
    ambient_library.mkdir()
    pth_marker = tmp_path / "pth-marker"
    customize_marker = tmp_path / "customize-marker"
    (shared_library / "shared_dependency_probe.py").write_text("value = 'pipx-shared'\n", encoding="utf-8")
    (shared_library / "startup-hook.pth").write_text(
        f"import pathlib; pathlib.Path({str(pth_marker)!r}).touch()\n",
        encoding="utf-8",
    )
    (shared_library / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(customize_marker)!r}).touch()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(daemon_manager_module.sys, "prefix", str(configured_prefix))
    monkeypatch.setattr(
        daemon_manager_module.sysconfig,
        "get_paths",
        lambda *_args, **_kwargs: {"purelib": str(configured_library), "platlib": str(configured_library)},
    )
    monkeypatch.syspath_prepend(str(ambient_library))
    import_paths = daemon_manager_module._trusted_daemon_import_paths()
    assert import_paths.index(local_library) < import_paths.index(shared_library)
    assert import_paths.count(shared_library) == 1
    assert ambient_library not in import_paths
    result = subprocess.run(
        [
            str(daemon_manager_module._trusted_daemon_interpreter()),
            "-I",
            "-S",
            "-c",
            "import json,sys; sys.path[:0]=json.loads(sys.argv[1]); "
            "import shared_dependency_probe; print(shared_dependency_probe.value)",
            json.dumps([str(path) for path in import_paths]),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "pipx-shared"
    assert not pth_marker.exists()
    assert not customize_marker.exists()


def test_daemon_does_not_add_shared_libraries_for_an_ordinary_venv(tmp_path, monkeypatch):
    prefix = tmp_path / "env"
    local_library = prefix / "lib" / "python3" / "site-packages"
    shared_library = tmp_path / "shared" / "lib" / "python3" / "site-packages"
    local_library.mkdir(parents=True)
    shared_library.mkdir(parents=True)
    monkeypatch.setattr(daemon_manager_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(daemon_manager_module.sysconfig, "get_paths", lambda: {"purelib": str(local_library)})
    assert shared_library not in daemon_manager_module._trusted_daemon_import_paths()


@pytest.mark.parametrize(
    "metadata",
    ["import poison", "relative/path", "{outside}", "{shared}\nimport poison", "{shared}" + "/." * 2100],
)
def test_invalid_pipx_metadata_does_not_add_untrusted_import_paths(tmp_path, metadata):
    from codex_plugin_scanner.guard.daemon.pipx_import_paths import pipx_shared_import_paths

    prefix = tmp_path / "pipx/venvs/hol-guard"
    local = prefix / "lib/python3/site-packages"
    shared = tmp_path / "pipx/shared/lib/python3/site-packages"
    outside = tmp_path / "outside/site-packages"
    for directory in (local, shared, outside):
        directory.mkdir(parents=True)
    (local / "pipx_shared.pth").write_text(metadata.format(outside=outside, shared=shared), encoding="utf-8")
    assert pipx_shared_import_paths(prefix, {"purelib": str(local)}) == ()
