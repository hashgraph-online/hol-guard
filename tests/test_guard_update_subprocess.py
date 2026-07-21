"""Adversarial contracts for Guard's trusted update subprocess boundary."""

from __future__ import annotations

import ctypes
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import update_subprocess as update_subprocess_module
from codex_plugin_scanner.guard.cli.update_subprocess import (
    TrustedProcessResult,
    TrustedUpdateContext,
    UpdateSubprocessError,
    build_trusted_update_context,
)


def _write_executable(path: Path, body: str = "raise SystemExit(0)\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(0o755)
    return path


def _replace_executable(path: Path, body: str) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    _write_executable(replacement, body)
    replacement.replace(path)


def _path_value(*directories: Path) -> str:
    return os.pathsep.join(str(directory.resolve()) for directory in directories)


def _manager_layout(tmp_path: Path, installer_kind: str) -> tuple[Path, Path]:
    user_root = tmp_path / f"{installer_kind}-user"
    marker = "venvs" if installer_kind == "pipx" else "tools"
    prefix = user_root / installer_kind / marker / "hol-guard"
    prefix.mkdir(parents=True)
    bin_dir = user_root / "bin"
    bin_dir.mkdir(parents=True)
    return prefix, bin_dir


def _build_pip_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    **kwargs: object,
) -> TrustedUpdateContext:
    monkeypatch.setattr(TrustedUpdateContext, "verify_pip_origin", lambda self: None)
    python_bin = Path(sys.executable).resolve().parent
    monkeypatch.setenv("PATH", _path_value(python_bin))
    return build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=tmp_path / "workspace",
        installer_kind="pip",
        proxy_mode="none",
        **kwargs,
    )


def _build_manager_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installer_kind: str,
    *,
    manager: Path | None = None,
    workspace_dir: Path | None = None,
    path_entries: tuple[Path, ...] | None = None,
    guard_home: Path | None = None,
    source_url: str | None = None,
) -> tuple[TrustedUpdateContext, Path]:
    prefix, manager_bin = _manager_layout(tmp_path, installer_kind)
    manager_path = manager or _write_executable(manager_bin / installer_kind)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    entries = path_entries or (manager_path.parent, Path(sys.executable).resolve().parent)
    monkeypatch.setenv("PATH", _path_value(*entries))
    context = build_trusted_update_context(
        guard_home=guard_home or (tmp_path / "guard-home"),
        workspace_dir=workspace_dir,
        installer_kind=installer_kind,
        source_url=source_url,
        proxy_mode="none",
    )
    return context, manager_path


def _error_reason(error: pytest.ExceptionInfo[UpdateSubprocessError]) -> str:
    return error.value.reason_code


def _windows_descendant_parent_script(mode: str) -> str:
    descendant_script = (
        "import sys,time; "
        "from pathlib import Path; "
        "time.sleep(float(sys.argv[1])); "
        "Path(sys.argv[2]).write_text('escaped', encoding='utf-8')"
    )
    lines = [
        "import subprocess",
        "import sys",
        "import time",
        "from pathlib import Path",
        f"descendant_script = {descendant_script!r}",
        "subprocess.Popen([sys.executable, '-I', '-S', '-c', descendant_script, sys.argv[1], sys.argv[2]])",
        "Path(sys.argv[3]).write_text('spawned', encoding='utf-8')",
    ]
    if mode == "timeout":
        lines.append("time.sleep(30)")
    elif mode == "overflow":
        lines.extend(
            [
                "sys.stdout.write('x' * (1024 * 1024))",
                "sys.stdout.flush()",
                "time.sleep(30)",
            ]
        )
    elif mode != "parent_exit":
        raise ValueError(f"unsupported process-tree test mode: {mode}")
    return "\n".join(lines)


def test_update_context_scrubs_hostile_ambient_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    hostile_environment = {
        "PYTHONPATH": str(project / "python"),
        "PYTHONHOME": str(project / "python-home"),
        "PYTHONSTARTUP": str(project / "startup.py"),
        "PYTHONUSERBASE": str(project / "user-site"),
        "PYTHONINSPECT": "1",
        "PIP_CONFIG_FILE": str(project / "pip.conf"),
        "PIP_INDEX_URL": "https://ambient.invalid/simple",
        "PIP_EXTRA_INDEX_URL": "https://ambient-extra.invalid/simple",
        "PIP_FIND_LINKS": str(project / "wheels"),
        "PIPX_HOME": str(project / "pipx-home"),
        "PIPX_BIN_DIR": str(project / "pipx-bin"),
        "PIPX_DEFAULT_PYTHON": str(project / "python"),
        "UV_CONFIG_FILE": str(project / "uv.toml"),
        "UV_INDEX_URL": "https://ambient.invalid/simple",
        "UV_EXTRA_INDEX_URL": "https://ambient-extra.invalid/simple",
        "UV_PROJECT": str(project),
        "UV_PYTHON": str(project / "python"),
        "UV_TOOL_DIR": str(project / "uv-tools"),
        "VIRTUAL_ENV": str(project / ".venv"),
        "CONDA_PREFIX": str(project / "conda"),
        "CONDA_DEFAULT_ENV": "hostile",
        "CONDA_PYTHON_EXE": str(project / "conda" / "python"),
        "LD_PRELOAD": str(project / "inject.so"),
        "LD_LIBRARY_PATH": str(project),
        "DYLD_INSERT_LIBRARIES": str(project / "inject.dylib"),
        "DYLD_LIBRARY_PATH": str(project),
        "COMSPEC": str(project / "cmd.exe"),
        "PATHEXT": ".EVIL;.PY",
        "SHELL": str(project / "evil-shell"),
        "SYSTEMDRIVE": "Z:",
        "SYSTEMROOT": str(project / "Windows"),
        "WINDIR": str(project / "Windows"),
        "HTTP_PROXY": "http://ambient-proxy.invalid:8080",
        "HTTPS_PROXY": "http://ambient-proxy.invalid:8080",
        "ALL_PROXY": "socks5://ambient-proxy.invalid:1080",
        "NO_PROXY": "*",
        "PIP_CERT": str(project / "ambient-ca.pem"),
        "REQUESTS_CA_BUNDLE": str(project / "ambient-ca.pem"),
        "SSL_CERT_FILE": str(project / "ambient-ca.pem"),
        "HOME": str(project),
        "TMPDIR": str(project / "tmp"),
        "UNRELATED_UPDATE_SECRET": "must-not-cross-boundary",
    }
    for key, value in hostile_environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("PYTHONNOUSERSITE", "0")
    monkeypatch.setenv("PYTHONSAFEPATH", "0")

    context = _build_pip_context(tmp_path, monkeypatch)
    environment = dict(context.environment)

    reconstructed_keys = {"HOME", "PIP_CONFIG_FILE", "TMPDIR"}
    if os.name == "nt":
        reconstructed_keys.update({"COMSPEC", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR"})
    assert not (set(hostile_environment) - reconstructed_keys).intersection(environment)
    assert environment["HOME"] != hostile_environment["HOME"]
    assert environment["TMPDIR"] != hostile_environment["TMPDIR"]
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONSAFEPATH"] == "1"
    assert environment["PIP_CONFIG_FILE"] == os.devnull
    assert environment["HOME"] == str(context.neutral_home)
    assert environment["TMPDIR"].startswith(str(context.neutral_cwd))
    assert "UNRELATED_UPDATE_SECRET" not in environment
    if os.name == "nt":
        for key in ("COMSPEC", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR"):
            assert environment[key] != hostile_environment[key]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle and native-path regression")
def test_windows_update_context_ignores_ambient_os_roots_and_binds_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_windows = tmp_path / "hostile-windows"
    hostile_system = hostile_windows / "System32"
    hostile_system.mkdir(parents=True)
    fake_cmd = hostile_system / "cmd.exe"
    fake_cmd.write_bytes(b"not a trusted command processor")
    monkeypatch.setenv("COMSPEC", str(fake_cmd))
    monkeypatch.setenv("PATHEXT", ".EVIL;.PY")
    monkeypatch.setenv("SYSTEMDRIVE", "Z:")
    monkeypatch.setenv("SYSTEMROOT", str(hostile_windows))
    monkeypatch.setenv("WINDIR", str(hostile_windows))

    context = _build_pip_context(tmp_path, monkeypatch)

    assert context.environment["COMSPEC"] != str(fake_cmd)
    assert context.environment["PATHEXT"] == ".COM;.EXE;.BAT;.CMD"
    assert context.environment["SYSTEMROOT"] != str(hostile_windows)
    assert context.environment["WINDIR"] != str(hostile_windows)
    assert Path(context.environment["COMSPEC"]).is_file()
    assert Path(context.environment["SYSTEMROOT"]).is_dir()
    assert context.neutral_identities
    for identity in context.neutral_identities:
        identity.revalidate(changed_reason="unexpected_change")
    assert any(
        identity.canonical_path == Path(context.environment["COMSPEC"]).resolve()
        for identity in context.installer_interpreters
    )


def test_windows_legacy_pipx_prefix_uses_profile_local_bin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    prefix = profile / "pipx" / "venvs" / "hol-guard"
    prefix.mkdir(parents=True)
    monkeypatch.setattr(update_subprocess_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)

    manager_home, manager_bin = update_subprocess_module._manager_home_from_prefix("pipx")

    assert manager_home == profile / "pipx"
    assert manager_bin == profile / ".local" / "bin"


def test_windows_manager_prefix_matching_is_case_insensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = tmp_path / "profile"
    prefix = profile / "PIPX" / "VENVS" / "HOL-GUARD"
    prefix.mkdir(parents=True)
    monkeypatch.setattr(update_subprocess_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)

    manager_home, manager_bin = update_subprocess_module._manager_home_from_prefix("pipx")

    assert manager_home == profile / "PIPX"
    assert manager_bin == profile / ".local" / "bin"


@pytest.mark.skipif(os.name == "nt", reason="POSIX same-file casing regression")
@pytest.mark.parametrize(
    "prefix_suffix",
    [
        ("UV", "tools", "hol-guard"),
        ("uv", "Tools", "hol-guard"),
        ("uv", "tools", "HOL-GUARD"),
    ],
)
def test_case_sensitive_posix_manager_prefix_rejects_distinct_component_casing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prefix_suffix: tuple[str, str, str],
) -> None:
    prefix = tmp_path.joinpath(*prefix_suffix)
    prefix.mkdir(parents=True)
    original_samefile = Path.samefile

    def case_sensitive_samefile(path: Path, other: str | os.PathLike[str]) -> bool:
        if str(path) != str(other) and str(path).casefold() == str(other).casefold():
            return False
        return original_samefile(path, other)

    monkeypatch.setattr(Path, "samefile", case_sensitive_samefile)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))

    with pytest.raises(UpdateSubprocessError) as error:
        update_subprocess_module._manager_home_from_prefix("uv")

    assert _error_reason(error) == "update_installer_untrusted"


@pytest.mark.skipif(os.name == "nt", reason="POSIX same-file casing regression")
def test_case_insensitive_posix_manager_prefix_accepts_samefile_aliases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "Share" / "UV" / "Tools" / "HOL-GUARD"
    prefix.mkdir(parents=True)
    original_samefile = Path.samefile

    def case_insensitive_samefile(path: Path, other: str | os.PathLike[str]) -> bool:
        if str(path).casefold() == str(other).casefold():
            return True
        return original_samefile(path, other)

    monkeypatch.setattr(Path, "samefile", case_insensitive_samefile)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))

    manager_home, manager_bin = update_subprocess_module._manager_home_from_prefix("uv")

    assert manager_home == tmp_path / "Share" / "UV" / "Tools"
    assert manager_bin == tmp_path / "bin"


@pytest.mark.skipif(os.name == "nt", reason="POSIX same-file casing regression")
def test_case_sensitive_posix_share_like_parent_does_not_redirect_manager_bin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = tmp_path / "Share" / "uv" / "tools" / "hol-guard"
    prefix.mkdir(parents=True)
    original_samefile = Path.samefile

    def case_sensitive_samefile(path: Path, other: str | os.PathLike[str]) -> bool:
        if str(path) != str(other) and str(path).casefold() == str(other).casefold():
            return False
        return original_samefile(path, other)

    monkeypatch.setattr(Path, "samefile", case_sensitive_samefile)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))

    manager_home, manager_bin = update_subprocess_module._manager_home_from_prefix("uv")

    assert manager_home == tmp_path / "Share" / "uv" / "tools"
    assert manager_bin == tmp_path / "Share" / "bin"


def test_windows_search_uses_known_folder_roaming_appdata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_directory = tmp_path / "Windows"
    system_directory = windows_directory / "System32"
    profile = tmp_path / "profile"
    roaming_appdata = tmp_path / "redirected" / "Roaming"
    python_scripts = roaming_appdata / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts"
    base_scripts = tmp_path / "base-prefix" / "Scripts"
    for directory in (windows_directory, system_directory, profile / ".local" / "bin", python_scripts, base_scripts):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        update_subprocess_module,
        "os",
        SimpleNamespace(name="nt", pathsep=os.pathsep),
    )
    monkeypatch.setattr(update_subprocess_module.sys, "base_prefix", str(base_scripts.parent))
    monkeypatch.setattr(
        update_subprocess_module,
        "trusted_windows_system_directories",
        lambda: (windows_directory, system_directory),
    )
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_roaming_appdata", lambda: roaming_appdata)

    search_path = update_subprocess_module._trusted_runtime_search_path(installer_kind="pip")

    entries = {Path(entry) for entry in search_path.split(os.pathsep)}
    assert python_scripts.resolve() in entries
    assert (profile / "AppData" / "Roaming" / "Python").resolve() not in entries


@pytest.mark.skipif(os.name != "nt", reason="Windows reparse-point regression")
def test_windows_filesystem_identity_rejects_directory_reparse_points(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "directory-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symbolic-link creation is unavailable")

    with pytest.raises(UpdateSubprocessError) as exc_info:
        update_subprocess_module.FilesystemIdentity.capture(
            link,
            kind="directory",
            failure_reason="windows_reparse_rejected",
        )

    assert _error_reason(exc_info) == "windows_reparse_rejected"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_windows_update_context_rejects_preexisting_runtime_junction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    runtime = guard_home / "update-runtime"
    outside = tmp_path / "outside-runtime"
    outside.mkdir()
    command_processor = update_subprocess_module.trusted_windows_system_executable("cmd.exe")
    result = subprocess.run(
        [str(command_processor), "/d", "/c", "mklink", "/J", str(runtime), str(outside)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        pytest.skip("Windows junction creation is unavailable")
    monkeypatch.setattr(TrustedUpdateContext, "verify_pip_origin", lambda self: None)

    with pytest.raises(UpdateSubprocessError) as exc_info:
        build_trusted_update_context(
            guard_home=guard_home,
            workspace_dir=None,
            installer_kind="pip",
            proxy_mode="none",
        )

    assert _error_reason(exc_info) == "update_neutral_cwd_unavailable"


def test_devnull_pip_config_disables_global_and_site_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    try:
        import ensurepip
    except ImportError:
        pytest.skip("ensurepip is unavailable")
    bundled = Path(ensurepip.__file__).resolve().parent / "_bundled"
    pip_wheels = sorted(bundled.glob("pip-*.whl"))
    if not pip_wheels:
        pytest.skip("the runtime has no bundled pip wheel")
    fake_prefix = tmp_path / "hostile-prefix"
    fake_prefix.mkdir()
    (fake_prefix / "pip.conf").write_text(
        "[global]\nno-index = true\nextra-index-url = https://attacker.invalid/simple\n",
        encoding="utf-8",
    )
    context = _build_pip_context(tmp_path, monkeypatch)
    script = "\n".join(
        [
            "import json",
            "import sys",
            f"sys.path.insert(0, {str(pip_wheels[-1])!r})",
            f"sys.prefix = {str(fake_prefix)!r}",
            "from pip._internal.configuration import Configuration",
            "configuration = Configuration(isolated=True)",
            "configuration.load()",
            "print(json.dumps(list(configuration.items())))",
        ]
    )

    result = subprocess.run(
        [str(context.python.launch_path), "-I", "-S", "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env=dict(context.environment),
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []
    assert "attacker.invalid" not in result.stdout


def test_update_context_reconstructs_explicit_managed_source_proxy_and_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ca_bundle = tmp_path / "enterprise-ca.pem"
    ca_bundle.write_text("enterprise test CA\n", encoding="utf-8")
    monkeypatch.setenv("PIP_INDEX_URL", "https://ambient.invalid/simple")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:8080")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "ambient-ca.pem"))
    monkeypatch.setattr(TrustedUpdateContext, "verify_pip_origin", lambda self: None)
    monkeypatch.setenv("PATH", _path_value(Path(sys.executable).resolve().parent))

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="pip",
        source_url="https://packages.enterprise.example/simple/",
        source_kind="managed_index",
        proxy_mode="explicit",
        proxy_url="http://proxy.enterprise.example:8443",
        ca_bundle_path=str(ca_bundle),
    )

    expected_source = "https://packages.enterprise.example/simple"
    assert context.source.kind == "managed_index"
    assert context.source.public_name == "managed_index"
    assert context.source.index_url == expected_source
    assert context.source.fingerprint == hashlib.sha256(expected_source.encode("utf-8")).hexdigest()
    assert context.environment["HTTP_PROXY"] == "http://proxy.enterprise.example:8443"
    assert context.environment["HTTPS_PROXY"] == "http://proxy.enterprise.example:8443"
    assert context.environment["PIP_CERT"] == str(ca_bundle.resolve())
    assert context.environment["REQUESTS_CA_BUNDLE"] == str(ca_bundle.resolve())
    assert context.environment["SSL_CERT_FILE"] == str(ca_bundle.resolve())
    assert "ambient.invalid" not in json.dumps(dict(context.environment))


def test_update_context_reconstructs_platform_proxy_instead_of_ambient_proxy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://ambient.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient.invalid:8080")
    monkeypatch.setattr(
        update_subprocess_module,
        "platform_system_proxies",
        lambda: {"http": "http://system-proxy.example:8080", "https": "http://system-proxy.example:8443"},
    )
    monkeypatch.setattr(TrustedUpdateContext, "verify_pip_origin", lambda self: None)
    monkeypatch.setenv("PATH", _path_value(Path(sys.executable).resolve().parent))

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="pip",
        proxy_mode="system",
    )

    assert context.environment["HTTP_PROXY"] == "http://system-proxy.example:8080"
    assert context.environment["HTTPS_PROXY"] == "http://system-proxy.example:8443"


def test_python_command_uses_only_python_310_compatible_isolation_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    monkeypatch.setattr(update_subprocess_module.sys, "version_info", (3, 10, 20, "final", 0))

    command = context.python_command("print('trusted')", "argument")

    assert command == [
        str(context.python.launch_path),
        "-I",
        "-S",
        "-c",
        update_subprocess_module._TRUSTED_SCRIPT_BOOTSTRAP,
        json.dumps([str(path) for path in context.python_import_paths], separators=(",", ":")),
        "print('trusted')",
        "argument",
    ]
    assert "-P" not in command


def test_python_bootstrap_skips_sitecustomize_and_pth_startup_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    hostile_site = tmp_path / "hostile-site"
    hostile_site.mkdir()
    site_marker = tmp_path / "sitecustomize-ran"
    pth_marker = tmp_path / "pth-ran"
    (hostile_site / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(site_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    (hostile_site / "startup.pth").write_text(
        f"import pathlib; pathlib.Path({str(pth_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    isolated_context = replace(
        context,
        python_import_paths=(hostile_site, *context.python_import_paths),
    )

    result = isolated_context.run(
        isolated_context.python_command("import sys; print('site' in sys.modules)"),
    )

    assert result.returncode == 0
    assert result.stdout == "False"
    assert site_marker.exists() is False
    assert pth_marker.exists() is False


def test_python_bootstrap_ignores_fake_project_pip_and_package_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fake_pip_marker = tmp_path / "fake-pip-ran"
    fake_package_marker = tmp_path / "fake-package-ran"
    fake_site_marker = tmp_path / "fake-site-ran"
    (workspace / "pip.py").write_text(
        f"from pathlib import Path\nPath({str(fake_pip_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    fake_package = workspace / "codex_plugin_scanner"
    fake_package.mkdir()
    (fake_package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(fake_package_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    (workspace / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(fake_site_marker)!r}).write_text('owned')\n",
        encoding="utf-8",
    )
    trusted_packages = tmp_path / "trusted-packages"
    trusted_package = trusted_packages / "codex_plugin_scanner"
    trusted_package.mkdir(parents=True)
    (trusted_package / "__init__.py").write_text("SOURCE = 'trusted'\n", encoding="utf-8")
    trusted_pip = trusted_packages / "pip"
    trusted_pip.mkdir()
    (trusted_pip / "__init__.py").write_text("SOURCE = 'trusted-pip'\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(workspace))
    monkeypatch.chdir(workspace)
    context = _build_pip_context(tmp_path, monkeypatch)
    isolated_context = replace(
        context,
        python_import_paths=(trusted_packages, *context.python_import_paths),
    )
    script = (
        "import codex_plugin_scanner, json, pip; "
        "print(json.dumps({'package': codex_plugin_scanner.SOURCE, 'pip': pip.SOURCE}, sort_keys=True))"
    )

    result = isolated_context.run(isolated_context.python_command(script))

    assert result.returncode == 0
    observed = json.loads(result.stdout)
    assert observed["package"] == "trusted"
    assert observed["pip"] == "trusted-pip"
    assert fake_pip_marker.exists() is False
    assert fake_package_marker.exists() is False
    assert fake_site_marker.exists() is False


def test_pip_execution_argv_is_isolated_absolute_and_source_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(
        tmp_path,
        monkeypatch,
        source_url="https://packages.enterprise.example/simple",
        source_kind="managed_index",
    )
    display = [str(context.python.launch_path), "-m", "pip", "install", "--upgrade", "hol-guard"]

    command = context.build_installer_command(display)

    assert Path(command[0]).is_absolute()
    assert context.python.canonical_path.is_absolute()
    assert command == [
        str(context.python.launch_path),
        *update_subprocess_module._trusted_python_flags(),
        "-S",
        "-c",
        update_subprocess_module._TRUSTED_MODULE_BOOTSTRAP,
        json.dumps([str(path) for path in context.python_import_paths], separators=(",", ":")),
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "--no-input",
        "install",
        "--upgrade",
        "hol-guard",
        "--index-url",
        "https://packages.enterprise.example/simple",
    ]


@pytest.mark.skipif(
    os.name == "nt",
    reason="uses an extensionless POSIX shebang executable as the uv manager fixture",
)
def test_uv_execution_argv_is_isolated_absolute_and_source_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, manager = _build_manager_context(
        tmp_path,
        monkeypatch,
        "uv",
        source_url="https://packages.enterprise.example/simple",
    )

    command = context.build_installer_command(["uv", "tool", "install", "--force", "hol-guard==2.0.0"])

    assert command == [
        str(manager),
        "--no-config",
        "--no-progress",
        "--no-python-downloads",
        "tool",
        "install",
        "--python",
        str(context.python.launch_path),
        "--no-sources",
        "--default-index",
        "https://packages.enterprise.example/simple",
        "--force",
        "hol-guard==2.0.0",
    ]
    assert context.installer is not None
    assert context.installer.launch_path == manager
    assert context.installer.canonical_path == manager.resolve()
    assert context.installer.sha256 == hashlib.sha256(manager.read_bytes()).hexdigest()
    assert context.environment["UV_TOOL_DIR"].endswith("/uv/tools")
    assert context.environment["UV_NO_CONFIG"] == "1"


@pytest.mark.parametrize(
    "display",
    [
        ["pipx", "install", "--force", "hol-guard==2.0.0"],
        ["pipx", "install", "--force", "/tmp/hol_guard.whl"],
    ],
)
@pytest.mark.skipif(
    os.name == "nt",
    reason="uses an extensionless POSIX shebang executable as the pipx manager fixture",
)
def test_pipx_execution_argv_is_absolute_and_source_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    display: list[str],
) -> None:
    context, manager = _build_manager_context(tmp_path, monkeypatch, "pipx")

    command = context.build_installer_command(display)

    assert command[0] == str(manager)
    assert command == [
        str(manager),
        "install",
        "--backend",
        "pip",
        "--fetch-python",
        "never",
        "--index-url",
        "https://pypi.org/simple",
        "--python",
        str(context.python.launch_path),
        *display[2:],
    ]
    assert context.installer is not None
    assert context.installer.canonical_path == manager.resolve()
    assert context.environment["PIPX_HOME"].endswith("/pipx")
    assert Path(context.environment["PIPX_HOME"]) / "venvs" / "hol-guard" == Path(
        str(update_subprocess_module.sys.prefix)
    )
    assert context.environment["PIPX_DEFAULT_BACKEND"] == "pip"
    assert context.environment["PIPX_DEFAULT_PYTHON"] == str(context.python.launch_path)
    assert context.environment["PIPX_FETCH_PYTHON"] == "never"


@pytest.mark.parametrize("installer_kind", ["uv", "pipx"])
@pytest.mark.skipif(
    os.name == "nt",
    reason="executes extensionless POSIX shebang manager fixtures to test workspace isolation",
)
def test_workspace_path_collision_is_excluded_and_never_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installer_kind: str,
) -> None:
    workspace = tmp_path / "workspace"
    project_bin = workspace / "bin"
    fake_marker = tmp_path / f"project-{installer_kind}-ran"
    trusted_marker = tmp_path / f"trusted-{installer_kind}.json"
    _write_executable(
        project_bin / installer_kind,
        f"from pathlib import Path\nPath({str(fake_marker)!r}).write_text('owned', encoding='utf-8')\n",
    )
    prefix, trusted_bin = _manager_layout(tmp_path, installer_kind)
    trusted_manager = _write_executable(
        trusted_bin / installer_kind,
        "\n".join(
            [
                "import json",
                "import os",
                "import sys",
                "from pathlib import Path",
                f"Path({str(trusted_marker)!r}).write_text(json.dumps({{",
                "    'argv': sys.argv,",
                "    'cwd': os.getcwd(),",
                "    'pythonpath': os.environ.get('PYTHONPATH'),",
                "}), encoding='utf-8')",
                "",
            ]
        ),
    )
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv(
        "PATH",
        _path_value(project_bin, trusted_bin, Path(sys.executable).resolve().parent),
    )

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=workspace,
        installer_kind=installer_kind,
        proxy_mode="none",
    )
    display_command = (
        ["uv", "tool", "upgrade", "hol-guard"] if installer_kind == "uv" else ["pipx", "upgrade", "hol-guard"]
    )
    command = context.build_installer_command(display_command)
    result = context.run(command)

    assert result.returncode == 0
    assert context.installer is not None
    assert context.installer.launch_path == trusted_manager
    assert str(project_bin.resolve()) not in context.environment["PATH"].split(os.pathsep)
    assert fake_marker.exists() is False
    recorded = json.loads(trusted_marker.read_text(encoding="utf-8"))
    assert recorded["argv"] == command
    assert recorded["cwd"] == str(context.neutral_cwd)
    assert recorded["pythonpath"] is None


@pytest.mark.skipif(
    os.name == "nt",
    reason="uses extensionless POSIX shebang files as the ambient and trusted manager fixtures",
)
def test_nonstandard_ambient_manager_path_is_rejected_without_workspace_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attacker_bin = tmp_path / "ambient-attacker-bin"
    attacker_marker = tmp_path / "ambient-uv-ran"
    _write_executable(
        attacker_bin / "uv",
        f"from pathlib import Path\nPath({str(attacker_marker)!r}).write_text('owned')\n",
    )
    prefix, trusted_bin = _manager_layout(tmp_path, "uv")
    trusted_manager = _write_executable(trusted_bin / "uv")
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv(
        "PATH",
        _path_value(attacker_bin, trusted_bin, Path(sys.executable).resolve().parent),
    )

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="uv",
        proxy_mode="none",
    )

    assert context.installer is not None
    assert context.installer.launch_path == trusted_manager
    assert str(attacker_bin.resolve()) not in context.environment["PATH"].split(os.pathsep)
    assert attacker_marker.exists() is False


@pytest.mark.skipif(
    os.name == "nt",
    reason="uses an extensionless POSIX shebang executable in a POSIX conventional manager root",
)
def test_conventional_manager_root_is_used_when_tool_bin_has_no_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix, _tool_bin = _manager_layout(tmp_path, "pipx")
    conventional_bin = tmp_path / "conventional-system-bin"
    conventional_manager = _write_executable(conventional_bin / "pipx")
    ambient_empty_bin = tmp_path / "ambient-empty-bin"
    ambient_empty_bin.mkdir()
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(update_subprocess_module.os, "defpath", str(conventional_bin))
    monkeypatch.setenv("PATH", str(ambient_empty_bin))

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=tmp_path / "workspace",
        installer_kind="pipx",
        proxy_mode="none",
    )

    assert context.installer is not None
    assert context.installer.launch_path == conventional_manager
    assert context.installer.canonical_path == conventional_manager.resolve()
    assert str(ambient_empty_bin) not in context.environment["PATH"].split(os.pathsep)


@pytest.mark.skipif(
    os.name == "nt",
    reason="uses extensionless POSIX shebang manager fixtures across project working directories",
)
def test_update_context_has_identical_identity_and_source_from_two_project_cwds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix, trusted_bin = _manager_layout(tmp_path, "uv")
    trusted_manager = _write_executable(trusted_bin / "uv")
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    guard_home = tmp_path / "guard-home"
    snapshots: list[tuple[object, ...]] = []

    for project_name in ("project-a", "project-b"):
        workspace = tmp_path / project_name
        project_bin = workspace / "bin"
        _write_executable(project_bin / "uv", "raise SystemExit(91)\n")
        monkeypatch.chdir(workspace)
        monkeypatch.setenv("PATH", _path_value(project_bin, trusted_bin, Path(sys.executable).resolve().parent))
        context = build_trusted_update_context(
            guard_home=guard_home,
            workspace_dir=workspace,
            installer_kind="uv",
            proxy_mode="none",
        )
        command = context.build_installer_command(["uv", "tool", "upgrade", "hol-guard"])
        assert context.installer is not None
        snapshots.append(
            (
                context.python.canonical_path,
                context.installer.canonical_path,
                context.installer.sha256,
                context.source.kind,
                context.source.fingerprint,
                context.neutral_cwd,
                dict(context.environment),
                command,
            )
        )

    assert snapshots[0] == snapshots[1]
    assert snapshots[0][1] == trusted_manager.resolve()


def test_missing_manager_fails_before_any_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix, _ = _manager_layout(tmp_path, "uv")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()

    def unexpected_popen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unexpected process spawn")

    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.setattr(
        update_subprocess_module,
        "_trusted_runtime_search_path",
        lambda *, installer_kind: str(empty_bin),
    )
    monkeypatch.setattr(
        update_subprocess_module.subprocess,
        "Popen",
        unexpected_popen,
    )

    with pytest.raises(UpdateSubprocessError) as error:
        build_trusted_update_context(
            guard_home=tmp_path / "guard-home",
            workspace_dir=None,
            installer_kind="uv",
            proxy_mode="none",
        )

    assert _error_reason(error) == "update_installer_not_found"


def test_uv_managed_prefix_resolves_derived_manager_with_empty_ambient_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_python_import_paths = update_subprocess_module._trusted_python_import_paths()
    prefix, manager_bin = _manager_layout(tmp_path, "uv")
    if os.name == "nt":
        profile = tmp_path / "windows-profile"
        manager_bin = profile / ".local" / "bin"
        manager_bin.mkdir(parents=True)
        trusted_manager = manager_bin / "uv.exe"
        shutil.copy2(sys.executable, trusted_manager)
        monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)
    else:
        trusted_manager = _write_executable(manager_bin / "uv")
    empty_bin = tmp_path / "ambient-empty-bin"
    empty_bin.mkdir()
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(
        update_subprocess_module,
        "_trusted_python_import_paths",
        lambda: trusted_python_import_paths,
    )
    monkeypatch.setenv("PATH", str(empty_bin))

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="uv",
        proxy_mode="none",
    )

    assert context.installer is not None
    assert context.installer.launch_path == trusted_manager
    assert str(empty_bin) not in context.environment["PATH"].split(os.pathsep)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows executable resolution")
def test_windows_manager_resolution_prefers_trusted_exe_over_extensionless_project_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted_python_import_paths = update_subprocess_module._trusted_python_import_paths()
    profile = tmp_path / "windows-profile"
    trusted_bin = profile / ".local" / "bin"
    trusted_bin.mkdir(parents=True)
    trusted_manager = trusted_bin / "uv.exe"
    shutil.copy2(sys.executable, trusted_manager)
    workspace = tmp_path / "workspace"
    project_bin = workspace / "bin"
    project_manager = _write_executable(project_bin / "uv")
    prefix = tmp_path / "uv" / "tools" / "hol-guard"
    prefix.mkdir(parents=True)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(
        update_subprocess_module,
        "_trusted_python_import_paths",
        lambda: trusted_python_import_paths,
    )
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)
    monkeypatch.setenv("PATH", str(project_bin))

    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=workspace,
        installer_kind="uv",
        proxy_mode="none",
    )
    command = context.build_installer_command(["uv", "tool", "upgrade", "hol-guard"])

    assert context.installer is not None
    assert context.installer.launch_path == trusted_manager
    assert context.installer.canonical_path == trusted_manager.resolve()
    assert command[0] == str(trusted_manager)
    assert str(project_bin.resolve()) not in context.environment["PATH"].split(os.pathsep)
    assert project_manager.exists()


def test_windows_thread_first_failure_preserves_last_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    last_error = 0

    def set_last_error(value: int) -> None:
        nonlocal last_error
        last_error = value

    def get_last_error() -> int:
        return last_error

    def create_snapshot(_flags: int, _process_id: int) -> int:
        return 71

    def thread_first(_snapshot: int, _entry: object) -> int:
        set_last_error(5)
        return 0

    def thread_next(_snapshot: int, _entry: object) -> int:
        raise AssertionError("Thread32Next must not run after Thread32First fails")

    def open_thread(_access: int, _inherit: bool, _thread_id: int) -> int:
        raise AssertionError("OpenThread must not run after Thread32First fails")

    def resume_thread(_thread_handle: int) -> int:
        raise AssertionError("ResumeThread must not run after Thread32First fails")

    def close_handle(_handle: int) -> int:
        set_last_error(6)
        return 1

    kernel32 = SimpleNamespace(
        CreateToolhelp32Snapshot=create_snapshot,
        Thread32First=thread_first,
        Thread32Next=thread_next,
        OpenThread=open_thread,
        ResumeThread=resume_thread,
        CloseHandle=close_handle,
    )
    monkeypatch.setattr(update_subprocess_module.ctypes, "set_last_error", set_last_error, raising=False)
    monkeypatch.setattr(update_subprocess_module.ctypes, "get_last_error", get_last_error, raising=False)
    monkeypatch.setattr(update_subprocess_module, "_windows_kernel32", lambda: kernel32)

    with pytest.raises(OSError, match="Thread32First failed") as error:
        update_subprocess_module._resume_windows_process_primary_thread(4102)

    assert error.value.errno == 5


@pytest.mark.skipif(os.name == "nt", reason="symlink replacement semantics are POSIX-specific")
def test_manager_symlink_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix, manager_bin = _manager_layout(tmp_path, "uv")
    first = _write_executable(manager_bin / "uv-v1")
    replacement_marker = tmp_path / "replacement-ran"
    second = _write_executable(
        manager_bin / "uv-v2",
        f"from pathlib import Path\nPath({str(replacement_marker)!r}).write_text('ran')\n",
    )
    manager_link = manager_bin / "uv"
    manager_link.symlink_to(first)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv("PATH", _path_value(manager_bin, Path(sys.executable).resolve().parent))
    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="uv",
        proxy_mode="none",
    )
    command = context.build_installer_command(["uv", "tool", "upgrade", "hol-guard"])
    manager_link.unlink()
    manager_link.symlink_to(second)

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(command)

    assert _error_reason(error) == "update_installer_identity_changed"
    assert replacement_marker.exists() is False


@pytest.mark.skipif(os.name == "nt", reason="symlink creation may require elevated privileges on Windows")
def test_initial_manager_symlink_into_workspace_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    attacker_manager = _write_executable(workspace / "bin" / "uv")
    prefix, manager_bin = _manager_layout(tmp_path, "uv")
    (manager_bin / "uv").symlink_to(attacker_manager)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv("PATH", _path_value(manager_bin, Path(sys.executable).resolve().parent))

    with pytest.raises(UpdateSubprocessError) as error:
        build_trusted_update_context(
            guard_home=tmp_path / "guard-home",
            workspace_dir=workspace,
            installer_kind="uv",
            proxy_mode="none",
        )

    assert _error_reason(error) == "update_installer_untrusted"


@pytest.mark.skipif(
    os.name == "nt",
    reason="mutates an extensionless POSIX shebang manager fixture before execution",
)
def test_manager_content_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, manager = _build_manager_context(tmp_path, monkeypatch, "uv")
    command = context.build_installer_command(["uv", "tool", "upgrade", "hol-guard"])
    replacement_marker = tmp_path / "replacement-ran"
    _replace_executable(
        manager,
        f"from pathlib import Path\nPath({str(replacement_marker)!r}).write_text('ran')\n",
    )

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(command)

    assert _error_reason(error) == "update_installer_identity_changed"
    assert replacement_marker.exists() is False


@pytest.mark.skipif(
    os.name == "nt",
    reason="rewrites an extensionless POSIX shebang manager fixture before execution",
)
def test_manager_same_size_rewrite_with_restored_mtime_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, manager = _build_manager_context(tmp_path, monkeypatch, "uv")
    command = context.build_installer_command(["uv", "tool", "upgrade", "hol-guard"])
    metadata = manager.stat()
    original = manager.read_bytes()
    replacement = original.replace(b"SystemExit(0)", b"SystemExit(9)")
    assert replacement != original
    assert len(replacement) == len(original)
    manager.write_bytes(replacement)
    os.utime(manager, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(command)

    assert _error_reason(error) == "update_installer_identity_changed"


@pytest.mark.skipif(
    os.name == "nt",
    reason="depends on POSIX shebang interpreter chaining for an extensionless manager",
)
def test_manager_shebang_interpreter_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix, manager_bin = _manager_layout(tmp_path, "pipx")
    interpreter = _write_executable(tmp_path / "trusted-interpreter")
    manager = manager_bin / "pipx"
    manager.write_text(f"#!{interpreter}\nraise SystemExit(0)\n", encoding="utf-8")
    manager.chmod(0o755)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setenv("PATH", _path_value(manager_bin, Path(sys.executable).resolve().parent))
    context = build_trusted_update_context(
        guard_home=tmp_path / "guard-home",
        workspace_dir=None,
        installer_kind="pipx",
        proxy_mode="none",
    )
    command = context.build_installer_command(["pipx", "upgrade", "hol-guard"])
    replacement_marker = tmp_path / "replacement-interpreter-ran"
    _replace_executable(
        interpreter,
        f"from pathlib import Path\nPath({str(replacement_marker)!r}).touch()\n",
    )

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(command)

    assert _error_reason(error) == "update_installer_interpreter_identity_changed"
    assert replacement_marker.exists() is False


def test_trusted_process_timeout_has_stable_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(context.python_command("import time; time.sleep(5)"), timeout_seconds=0.05)

    assert _error_reason(error) == "update_installer_timeout"


def test_trusted_process_caps_and_redacts_stdout_and_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    script = (
        "import sys; "
        "print('SECRET=correct-horse-battery-staple', file=sys.stderr); "
        "print('AUTH_TOKEN=hunter2'); sys.stdout.flush(); sys.stderr.flush(); "
        "print('x' * 4096); "
        "print('y' * 4096, file=sys.stderr)"
    )

    result = context.run(context.python_command(script), output_limit_bytes=128)

    assert isinstance(result.returncode, int)
    assert result.output_limited is True
    assert len(result.stdout.encode("utf-8")) <= 128
    assert len(result.stderr.encode("utf-8")) <= 128
    assert "hunter2" not in result.stdout
    assert "correct-horse-battery-staple" not in result.stderr
    assert "[redacted]" in result.stdout
    assert "[redacted]" in result.stderr


def test_output_overflow_terminates_live_writer_promptly_and_retains_only_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    survived_marker = tmp_path / "writer-survived"
    script = "\n".join(
        [
            "import sys",
            "import time",
            "from pathlib import Path",
            "sys.stdout.write('AUTH_TOKEN=hunter2\\n')",
            "sys.stdout.flush()",
            "for _ in range(1000):",
            "    sys.stdout.write('x' * 4096)",
            "    sys.stdout.flush()",
            "    time.sleep(0.01)",
            f"Path({str(survived_marker)!r}).write_text('not terminated', encoding='utf-8')",
        ]
    )

    started = time.monotonic()
    result = context.run(
        context.python_command(script),
        timeout_seconds=5.0,
        output_limit_bytes=128,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert result.returncode != 0
    assert result.output_limited is True
    assert len(result.stdout.encode("utf-8")) <= 128
    assert len(result.stderr.encode("utf-8")) <= 128
    assert "hunter2" not in result.stdout
    assert survived_marker.exists() is False


def test_trusted_process_preserves_stdin_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)

    result = context.run(
        context.python_command("import sys; print(sys.stdin.read())"),
        input_text="trusted updater input",
    )

    assert result.returncode == 0
    assert result.stdout == "trusted updater input"
    assert result.stderr == ""
    assert result.output_limited is False


@pytest.mark.parametrize("allow_breakaway", [False, True])
def test_trusted_process_propagates_explicit_windows_job_breakaway_choice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allow_breakaway: bool,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    observed: list[bool] = []

    def fake_run_bounded_process(
        command: list[str],
        *,
        input_text: str | None,
        cwd: Path,
        environment: object,
        timeout_seconds: float,
        output_limit_bytes: int,
        allow_windows_job_breakaway: bool,
    ) -> update_subprocess_module._BoundedProcessResult:
        del command, input_text, cwd, environment, timeout_seconds, output_limit_bytes
        observed.append(allow_windows_job_breakaway)
        return update_subprocess_module._BoundedProcessResult(
            returncode=0,
            stdout=b"",
            stderr=b"",
            stdout_limited=False,
            stderr_limited=False,
        )

    monkeypatch.setattr(update_subprocess_module, "_run_bounded_process", fake_run_bounded_process)

    result = context.run(
        context.python_command("raise SystemExit(0)"),
        allow_windows_job_breakaway=allow_breakaway,
    )

    assert result.returncode == 0
    assert observed == [allow_breakaway]


@pytest.mark.parametrize(
    ("allow_breakaway", "expected_flags"),
    [
        (False, update_subprocess_module._WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
        (
            True,
            update_subprocess_module._WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | update_subprocess_module._WINDOWS_JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        ),
    ],
)
def test_windows_job_object_limits_scope_breakaway_to_explicit_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    allow_breakaway: bool,
    expected_flags: int,
) -> None:
    observed_flags: list[int] = []
    closed_handles: list[int] = []

    def create_job(_security_attributes: object, _name: object) -> int:
        return 71

    def set_information(
        _job_handle: object,
        information_class: int,
        information: int,
        information_size: int,
    ) -> int:
        assert information_class == update_subprocess_module._WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS
        assert information_size == ctypes.sizeof(update_subprocess_module._WindowsJobObjectExtendedLimitInformation)
        limits = ctypes.cast(
            information,
            ctypes.POINTER(update_subprocess_module._WindowsJobObjectExtendedLimitInformation),
        ).contents
        observed_flags.append(int(limits.basic_limit_information.limit_flags))
        return 1

    def close_handle(handle: ctypes.c_void_p) -> int:
        assert handle.value is not None
        closed_handles.append(int(handle.value))
        return 1

    kernel32 = SimpleNamespace(
        CreateJobObjectW=create_job,
        SetInformationJobObject=set_information,
        CloseHandle=close_handle,
    )
    monkeypatch.setattr(update_subprocess_module, "_windows_kernel32", lambda: kernel32)

    job = update_subprocess_module._create_windows_process_job(allow_breakaway=allow_breakaway)
    job.close()

    assert observed_flags == [expected_flags]
    assert closed_handles == [71]


def test_windows_suspended_spawn_failure_terminates_and_reaps_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeStream:
        closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 4102
            self.stdin = FakeStream()
            self.stdout = FakeStream()
            self.stderr = FakeStream()
            self.killed = False
            self.waited = False

        def poll(self) -> int | None:
            return -9 if self.killed else None

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            assert timeout > 0
            self.waited = True
            return -9

    class FakeJob:
        def __init__(self) -> None:
            self.terminated = False
            self.closed = False

        def terminate(self) -> None:
            self.terminated = True

        def close(self) -> None:
            self.closed = True

    fake_process = FakeProcess()
    fake_job = FakeJob()
    popen_kwargs: list[dict[str, object]] = []

    def fake_popen(command: list[str], **kwargs: object) -> FakeProcess:
        assert command == [str(tmp_path / "python.exe")]
        popen_kwargs.append(kwargs)
        return fake_process

    monkeypatch.setattr(update_subprocess_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(update_subprocess_module.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, raising=False)
    monkeypatch.setattr(update_subprocess_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(update_subprocess_module, "_create_windows_process_job", lambda **_kwargs: fake_job)
    monkeypatch.setattr(
        update_subprocess_module,
        "_assign_and_resume_windows_process",
        lambda *_args: (_ for _ in ()).throw(OSError("assignment failed")),
    )

    with pytest.raises(OSError, match="assignment failed"):
        update_subprocess_module._spawn_bounded_process(
            [str(tmp_path / "python.exe")],
            input_enabled=False,
            cwd=tmp_path,
            environment={},
        )

    assert len(popen_kwargs) == 1
    assert popen_kwargs[0]["creationflags"] == (0x00000200 | update_subprocess_module._WINDOWS_CREATE_SUSPENDED)
    assert fake_job.terminated is True
    assert fake_job.closed is True
    assert fake_process.killed is True
    assert fake_process.waited is True
    assert fake_process.stdin.closed is True
    assert fake_process.stdout.closed is True
    assert fake_process.stderr.closed is True


def test_windows_timeout_surfaces_job_close_failure_after_direct_child_is_reaped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 5101
            self.stdin = None
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.killed = False
            self.wait_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired(["fake-updater"], timeout)
            self.returncode = -9
            return self.returncode

    class FakeJob:
        def __init__(self) -> None:
            self.terminate_calls = 0
            self.close_calls = 0

        def terminate(self) -> None:
            self.terminate_calls += 1

        def close(self) -> None:
            self.close_calls += 1
            raise OSError("CloseHandle failed deterministically")

    fake_process = FakeProcess()
    fake_job = FakeJob()
    clock_values = iter((0.0, 2.0))

    def fake_monotonic() -> float:
        return next(clock_values, 2.0)

    monkeypatch.setattr(update_subprocess_module.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(
        update_subprocess_module,
        "_spawn_bounded_process",
        lambda *_args, **_kwargs: update_subprocess_module._SpawnedProcess(
            process=cast(subprocess.Popen[bytes], cast(object, fake_process)),
            windows_job=cast(update_subprocess_module._WindowsProcessJob, cast(object, fake_job)),
        ),
    )

    with pytest.raises(UpdateSubprocessError) as error:
        update_subprocess_module._run_bounded_process(
            [str(tmp_path / "python.exe")],
            input_text=None,
            cwd=tmp_path,
            environment={},
            timeout_seconds=1.0,
            output_limit_bytes=1024,
        )

    assert error.value.reason_code == "update_installer_failed"
    assert "CloseHandle failed deterministically" in error.value.detail
    assert isinstance(error.value.__cause__, UpdateSubprocessError)
    assert error.value.__cause__.reason_code == "update_installer_timeout"
    assert fake_job.terminate_calls == 2
    assert fake_job.close_calls == 2
    assert fake_process.killed is True
    assert fake_process.wait_calls == 2
    assert fake_process.returncode == -9


def test_windows_try_body_exception_preserved_when_job_cleanup_fails_after_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    primary_failure = RuntimeError("try body failed deterministically")

    class FakeProcess:
        def __init__(self) -> None:
            self.pid = 5102
            self.stdin = None
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.poll_calls = 0
            self.killed = False
            self.wait_calls = 0

        def poll(self) -> int | None:
            self.poll_calls += 1
            if self.poll_calls == 1:
                raise primary_failure
            return self.returncode

        def kill(self) -> None:
            self.killed = True

        def wait(self, *, timeout: float) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired(["fake-updater"], timeout)
            self.returncode = -9
            return self.returncode

    class FakeJob:
        def __init__(self) -> None:
            self.terminate_calls = 0
            self.close_calls = 0

        def terminate(self) -> None:
            self.terminate_calls += 1
            raise OSError("TerminateJobObject failed deterministically")

        def close(self) -> None:
            self.close_calls += 1
            raise OSError("CloseHandle failed deterministically")

    fake_process = FakeProcess()
    fake_job = FakeJob()
    monkeypatch.setattr(
        update_subprocess_module,
        "_spawn_bounded_process",
        lambda *_args, **_kwargs: update_subprocess_module._SpawnedProcess(
            process=cast(subprocess.Popen[bytes], cast(object, fake_process)),
            windows_job=cast(update_subprocess_module._WindowsProcessJob, cast(object, fake_job)),
        ),
    )

    with pytest.raises(UpdateSubprocessError) as error:
        update_subprocess_module._run_bounded_process(
            [str(tmp_path / "python.exe")],
            input_text=None,
            cwd=tmp_path,
            environment={},
            timeout_seconds=5.0,
            output_limit_bytes=1024,
        )

    assert error.value.reason_code == "update_installer_failed"
    assert "TerminateJobObject failed deterministically" in error.value.detail
    assert "CloseHandle failed deterministically" in error.value.detail
    assert error.value.__cause__ is primary_failure
    assert fake_job.terminate_calls == 2
    assert fake_job.close_calls == 2
    assert fake_process.killed is True
    assert fake_process.wait_calls == 2
    assert fake_process.returncode == -9


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object process-tree regression")
def test_windows_job_timeout_terminates_delayed_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    descendant_marker = tmp_path / "timeout-descendant-escaped"
    spawned_marker = tmp_path / "timeout-descendant-spawned"

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(
            context.python_command(
                _windows_descendant_parent_script("timeout"),
                "1.25",
                str(descendant_marker),
                str(spawned_marker),
            ),
            timeout_seconds=1.0,
        )

    assert _error_reason(error) == "update_installer_timeout"
    assert spawned_marker.read_text(encoding="utf-8") == "spawned"
    time.sleep(0.75)
    assert descendant_marker.exists() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object process-tree regression")
def test_windows_job_output_overflow_terminates_delayed_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    descendant_marker = tmp_path / "overflow-descendant-escaped"
    spawned_marker = tmp_path / "overflow-descendant-spawned"

    result = context.run(
        context.python_command(
            _windows_descendant_parent_script("overflow"),
            "0.75",
            str(descendant_marker),
            str(spawned_marker),
        ),
        timeout_seconds=5.0,
        output_limit_bytes=64,
    )

    assert result.returncode != 0
    assert result.output_limited is True
    assert spawned_marker.read_text(encoding="utf-8") == "spawned"
    time.sleep(1.0)
    assert descendant_marker.exists() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object process-tree regression")
def test_windows_job_reaps_descendant_pipe_after_direct_parent_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    descendant_marker = tmp_path / "pipe-descendant-escaped"
    spawned_marker = tmp_path / "pipe-descendant-spawned"

    result = context.run(
        context.python_command(
            _windows_descendant_parent_script("parent_exit"),
            "0.75",
            str(descendant_marker),
            str(spawned_marker),
        ),
        timeout_seconds=5.0,
    )

    assert result.returncode == 0
    assert spawned_marker.read_text(encoding="utf-8") == "spawned"
    time.sleep(1.0)
    assert descendant_marker.exists() is False


def _context_with_distribution_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: TrustedProcessResult,
) -> tuple[TrustedUpdateContext, Path]:
    context = _build_pip_context(tmp_path, monkeypatch)
    install_prefix = tmp_path / "installed-environment"
    install_prefix.mkdir(exist_ok=True)
    context = replace(context, install_prefix=install_prefix)
    monkeypatch.setattr(TrustedUpdateContext, "run", lambda self, command, **kwargs: result)
    return context, install_prefix


def test_distribution_query_accepts_one_strict_json_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "installed-environment" / "site-packages"
    root.mkdir(parents=True)
    result = TrustedProcessResult(
        args=(str(sys.executable),),
        returncode=0,
        stdout=json.dumps({"direct_url": None, "name": "hol-guard", "root": str(root), "version": "2.0.0"}),
        stderr="",
    )
    context, _ = _context_with_distribution_result(tmp_path, monkeypatch, result)

    distribution = context.query_distribution()

    assert distribution.name == "hol-guard"
    assert distribution.version == "2.0.0"
    assert distribution.root == root.resolve()


@pytest.mark.parametrize(
    "result",
    [
        TrustedProcessResult(
            args=("python",),
            returncode=0,
            stdout='sitecustomize noise\n{"direct_url":null,"name":"hol-guard","root":"/tmp","version":"2.0.0"}',
            stderr="",
        ),
        TrustedProcessResult(args=("python",), returncode=0, stdout="not-json", stderr=""),
        TrustedProcessResult(
            args=("python",),
            returncode=0,
            stdout='{"direct_url":null,"name":"hol-guard","root":"/tmp","version":"not-a-version"}',
            stderr="",
        ),
        TrustedProcessResult(
            args=("python",),
            returncode=0,
            stdout='{"direct_url":null,"extra":true,"name":"hol-guard","root":"/tmp","version":"2.0.0"}',
            stderr="",
        ),
        TrustedProcessResult(
            args=("python",),
            returncode=0,
            stdout='{"direct_url":null,"name":"hol-guard","root":"/tmp","version":"2.0.0"}',
            stderr="unexpected startup output",
        ),
    ],
)
def test_distribution_query_rejects_noise_and_invalid_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: TrustedProcessResult,
) -> None:
    context, _ = _context_with_distribution_result(tmp_path, monkeypatch, result)

    with pytest.raises(UpdateSubprocessError) as error:
        context.query_distribution()

    assert _error_reason(error) == "update_version_output_invalid"


def test_distribution_query_rejects_origin_outside_install_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outside_root = tmp_path / "project-shadow" / "site-packages"
    outside_root.mkdir(parents=True)
    result = TrustedProcessResult(
        args=("python",),
        returncode=0,
        stdout=json.dumps({"direct_url": None, "name": "hol-guard", "root": str(outside_root), "version": "2.0.0"}),
        stderr="",
    )
    context, _ = _context_with_distribution_result(tmp_path, monkeypatch, result)

    with pytest.raises(UpdateSubprocessError) as error:
        context.query_distribution()

    assert _error_reason(error) == "update_package_origin_mismatch"


def test_neutral_directories_are_private_real_directories(tmp_path: Path) -> None:
    runtime, neutral_home, neutral_tmp = update_subprocess_module._prepare_neutral_directories(tmp_path / "guard-home")

    assert runtime.name == "update-runtime"
    assert neutral_home == runtime / "home"
    assert neutral_tmp == runtime / "tmp"
    for directory in (runtime, neutral_home, neutral_tmp):
        assert directory.is_dir()
        assert directory.is_symlink() is False
        if os.name != "nt":
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="symlink creation may require elevated privileges on Windows")
@pytest.mark.parametrize("symlink_component", ["runtime", "home", "tmp"])
def test_neutral_directories_reject_symlink_components(
    tmp_path: Path,
    symlink_component: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    runtime = guard_home / "update-runtime"
    outside = tmp_path / "outside"
    outside.mkdir()
    guard_home.mkdir()
    if symlink_component == "runtime":
        runtime.symlink_to(outside, target_is_directory=True)
    else:
        runtime.mkdir()
        (runtime / symlink_component).symlink_to(outside, target_is_directory=True)

    with pytest.raises(UpdateSubprocessError) as error:
        update_subprocess_module._prepare_neutral_directories(guard_home)

    assert _error_reason(error) == "update_neutral_cwd_unavailable"


@pytest.mark.skipif(os.name == "nt", reason="symlink replacement semantics are POSIX-specific")
def test_neutral_directory_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    marker = tmp_path / "neutral-swap-ran"
    original_home = context.neutral_home
    moved_home = original_home.with_name("home-original")
    original_home.rename(moved_home)
    replacement_home = tmp_path / "replacement-home"
    replacement_home.mkdir()
    original_home.symlink_to(replacement_home, target_is_directory=True)

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(context.python_command(f"from pathlib import Path; Path({str(marker)!r}).touch()"))

    assert _error_reason(error) == "update_neutral_context_changed"
    assert marker.exists() is False


@pytest.mark.skipif(os.name == "nt", reason="symlink replacement semantics are POSIX-specific")
def test_python_import_root_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _build_pip_context(tmp_path, monkeypatch)
    trusted_import_root = tmp_path / "trusted-import-root"
    trusted_import_root.mkdir()
    import_identity = update_subprocess_module.FilesystemIdentity.capture(
        trusted_import_root,
        kind="directory",
        failure_reason="update_python_untrusted",
    )
    context = replace(
        context,
        python_import_paths=(trusted_import_root,),
        python_import_identities=(import_identity,),
    )
    marker = tmp_path / "import-swap-ran"
    trusted_import_root.rename(tmp_path / "trusted-import-root-original")
    replacement = tmp_path / "replacement-import-root"
    replacement.mkdir()
    trusted_import_root.symlink_to(replacement, target_is_directory=True)

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(context.python_command(f"from pathlib import Path; Path({str(marker)!r}).touch()"))

    assert _error_reason(error) == "update_python_import_path_changed"
    assert marker.exists() is False


def test_managed_ca_content_swap_is_rejected_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ca_bundle = tmp_path / "enterprise-ca.pem"
    ca_bundle.write_text("trusted enterprise CA\n", encoding="utf-8")
    context = _build_pip_context(tmp_path, monkeypatch, ca_bundle_path=str(ca_bundle))
    marker = tmp_path / "ca-swap-ran"
    ca_bundle.write_text("replacement enterprise CA\n", encoding="utf-8")

    with pytest.raises(UpdateSubprocessError) as error:
        context.run(context.python_command(f"from pathlib import Path; Path({str(marker)!r}).touch()"))

    assert _error_reason(error) == "update_ca_bundle_changed"
    assert marker.exists() is False
