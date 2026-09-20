"""Installed wheel and launcher identity checks for the Secrets probe."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .probe_installed_offline_secrets_api import probe_api


def _wrapper_templates(module: str) -> tuple[str, str]:
    uv = (
        "import sys\n"
        f"from {module} import main\n"
        'if __name__ == "__main__":\n'
        '    if sys.argv[0].endswith("-script.pyw"):\n'
        "        sys.argv[0] = sys.argv[0][:-11]\n"
        '    elif sys.argv[0].endswith(".exe"):\n'
        "        sys.argv[0] = sys.argv[0][:-4]\n"
        "    sys.exit(main())\n"
    )
    distlib = (
        "import re\nimport sys\n"
        f"from {module} import main\n"
        'if __name__ == "__main__":\n'
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        "    sys.exit(main())\n"
    )
    return uv, distlib


def _windows_launcher_resources(path: Path) -> dict[str, bytes] | None:
    """Read uv 0.9.26 resources as data; LoadLibrary does not execute its code."""
    _api = probe_api()
    import ctypes
    from ctypes import wintypes

    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
    library.LoadLibraryExW.restype = wintypes.HMODULE
    library.FindResourceW.argtypes = (wintypes.HMODULE, wintypes.LPCWSTR, ctypes.c_void_p)
    library.FindResourceW.restype = wintypes.HANDLE
    library.SizeofResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    library.SizeofResource.restype = wintypes.DWORD
    library.LoadResource.argtypes = (wintypes.HMODULE, wintypes.HANDLE)
    library.LoadResource.restype = wintypes.HANDLE
    library.LockResource.argtypes = (wintypes.HANDLE,)
    library.LockResource.restype = ctypes.c_void_p
    library.FreeLibrary.argtypes = (wintypes.HMODULE,)
    library.FreeLibrary.restype = wintypes.BOOL
    handle = library.LoadLibraryExW(str(path), None, 2)  # LOAD_LIBRARY_AS_DATAFILE
    _api._require(bool(handle), "launcher_resource_load")
    try:
        output = {}
        for name, limit in (
            ("UV_TRAMPOLINE_KIND", 1),
            ("UV_PYTHON_PATH", 4096),
            ("UV_SCRIPT_DATA", _api._MAX_WRAPPER + 1024),
        ):
            resource = library.FindResourceW(handle, name, ctypes.c_void_p(10))  # RT_RCDATA
            if not resource and name == "UV_TRAMPOLINE_KIND":
                return None
            _api._require(bool(resource), "launcher_resource_missing")
            size = library.SizeofResource(handle, resource)
            _api._require(0 < size <= limit, "launcher_resource_size")
            loaded = library.LoadResource(handle, resource)
            _api._require(bool(loaded), "launcher_resource_load")
            pointer = library.LockResource(loaded)
            _api._require(bool(pointer), "launcher_resource_pointer")
            output[name] = ctypes.string_at(pointer, size)
        return output
    finally:
        library.FreeLibrary(handle)


def _launcher_wrapper(
    content: bytes, *, module: str, interpreter: str, windows: bool, resources: dict[str, bytes] | None = None
) -> dict[str, object]:
    """Validate supported generated wrappers without executing their source."""
    _api = probe_api()
    _api._require(0 < len(content) <= _api._MAX_LAUNCHER, "launcher_size")
    try:
        if windows:
            _api._require(content.startswith(b"MZ"), "launcher_executable_format")
            if resources is not None:
                _api._require(resources["UV_TRAMPOLINE_KIND"] == b"\x01", "launcher_trampoline_kind")
                executable = resources["UV_PYTHON_PATH"].decode("utf-8")
                payload = resources["UV_SCRIPT_DATA"]
                _api._require(len(payload) <= _api._MAX_WRAPPER + 1024, "launcher_wrapper_size")
            else:
                payload = content
            with _api.zipfile.ZipFile(_api.io.BytesIO(payload)) as archive:
                _api._require(archive.namelist() == ["__main__.py"], "launcher_embedded_wrapper")
                info = archive.getinfo("__main__.py")
                _api._require(info.file_size <= _api._MAX_WRAPPER, "launcher_wrapper_size")
                source = archive.read(info)
                prefix = payload[: info.header_offset]
            if resources is None:
                marker = prefix.rfind(b"#!")
                _api._require(marker >= 2, "launcher_interpreter_directive")
                directive = prefix[marker:]
        else:
            directive, _ = content.split(b"\n", 1)
            directive += b"\n"
            # Keep the shebang: Python recognizes encoding cookies only on
            # the original first two lines when it loads source bytes.
            source = content
        if resources is None:
            _api._require(directive.startswith(b"#!") and directive.endswith(b"\n"), "launcher_interpreter_directive")
            executable = directive[2:].rstrip(b"\r\n").decode("utf-8")
            if windows and executable.startswith('"') and executable.endswith('"'):
                executable = executable[1:-1]
        paths = _api.ntpath if windows else _api.os.path
        _api._require(
            paths.isabs(executable)
            and paths.normcase(paths.normpath(executable)) == paths.normcase(paths.normpath(interpreter)),
            "launcher_interpreter_mismatch",
        )
        _api._require(len(source) <= _api._MAX_WRAPPER, "launcher_wrapper_size")
        observed = _api.ast.dump(_api.ast.parse(source), include_attributes=False)
        templates = _api._wrapper_templates(module)
        matches = [
            index
            for index, template in enumerate(templates)
            if observed == _api.ast.dump(_api.ast.parse(template), include_attributes=False)
        ]
        _api._require(len(matches) == 1, "launcher_entrypoint_wrapper_mismatch")
    except _api.ProbeError:
        raise
    except (ValueError, UnicodeError, SyntaxError, _api.zipfile.BadZipFile, KeyError):
        raise _api.ProbeError("launcher_wrapper_invalid") from None
    return {
        "interpreter_matches_current_installation": True,
        "wrapper": ("uv", "distlib")[matches[0]],
        "windows_embedded_wrapper": windows,
        "uv_pe_resources": resources is not None,
    }


def _launcher_binding(distribution: Any, launcher: Path, module: str) -> tuple[str, dict[str, object]]:
    _api = probe_api()
    _api._require(not launcher.is_symlink(), "launcher_symlink")
    _api._require(launcher.stat().st_size <= _api._MAX_LAUNCHER, "launcher_size")
    with launcher.open("rb") as stream:
        content = stream.read(_api._MAX_LAUNCHER + 1)
    _api._require(len(content) <= _api._MAX_LAUNCHER, "launcher_size")
    record = distribution.read_text("RECORD")
    _api._require(isinstance(record, str) and len(record) <= 4 * 1024 * 1024, "installed_record_missing_or_large")
    launcher_path = _api.os.path.normcase(_api.os.path.abspath(launcher))
    entries = [
        row
        for row in _api.csv.reader(_api.io.StringIO(record))
        if len(row) == 3
        and _api.os.path.normcase(_api.os.path.abspath(distribution.locate_file(row[0]))) == launcher_path
    ]
    expected_hash = (
        "sha256=" + _api.base64.urlsafe_b64encode(_api.hashlib.sha256(content).digest()).rstrip(b"=").decode()
    )
    _api._require(
        len(entries) == 1 and entries[0][1:] == [expected_hash, str(len(content))], "launcher_record_mismatch"
    )
    executable = _api.os.path.abspath(_api.sys.executable)
    prefix = _api.os.path.abspath(_api.sys.prefix)
    _api._require(_api.os.path.commonpath((prefix, executable)) == prefix, "launcher_interpreter_outside_prefix")
    # Do not resolve Python symlinks: different venvs can share the base inode.
    resources = _api._windows_launcher_resources(launcher) if _api.os.name == "nt" else None
    binding = _api._launcher_wrapper(
        content, module=module, interpreter=executable, windows=_api.os.name == "nt", resources=resources
    )
    with launcher.open("rb") as stream:
        _api._require(stream.read(_api._MAX_LAUNCHER + 1) == content, "launcher_changed_during_attestation")
    binding["record_verified"] = True
    return _api._digest(content), binding


def _attest(wheel: Path, source_sha: str) -> tuple[dict[str, object], dict[str, Path]]:
    _api = probe_api()
    _api._require(bool(_api.sys.flags.isolated), "isolated_interpreter_required")
    _api._require(_api.re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "source_identity")
    distribution = _api.importlib.metadata.distribution("hol-guard")
    origin = _api.json.loads(distribution.read_text("direct_url.json") or "{}")
    _api._require(not origin.get("dir_info", {}).get("editable", False), "editable_install")
    module_digests: dict[str, str] = {}
    with _api.zipfile.ZipFile(wheel) as archive:
        for name in _api._MODULES:
            relative = name.replace(".", "/") + ".py"
            expected = _api.Path(str(distribution.locate_file(relative))).resolve(strict=True)
            module = _api.importlib.import_module(name)
            _api._require(_api.Path(module.__file__).resolve() == expected, "wheel_import_required")
            _api._require("site-packages" in expected.parts, "wheel_location_required")
            content = expected.read_bytes()
            _api._require(content == archive.read(relative), "installed_module_differs_from_wheel")
            module_digests[name] = _api._digest(content)
        manifest_names = [name for name in archive.namelist() if name.endswith("/runtime-manifest.json")]
        native_identity: dict[str, object] = {"bundled": False}
        if manifest_names:
            _api._require(len(manifest_names) == 1, "wheel_manifest_count")
            manifest = _api.json.loads(archive.read(manifest_names[0]))
            _api._require(manifest.get("source_sha") == source_sha, "wheel_build_identity")
            native_identity = {"bundled": True, "manifest_sha256": _api._digest(archive.read(manifest_names[0]))}
    entrypoints = {entry.name: entry for entry in distribution.entry_points if entry.group == "console_scripts"}
    launchers: dict[str, Path] = {}
    launcher_digests, launcher_bindings = {}, {}
    for name, target in (
        ("hol-guard", "codex_plugin_scanner.cli:main"),
        ("hol-guard-secrets", "codex_plugin_scanner.guard.secrets.cli:main"),
    ):
        _api._require(name in entrypoints and entrypoints[name].value == target, "wheel_entrypoint")
        launcher = _api.Path(_api.sysconfig.get_path("scripts")) / (name + (".exe" if _api.os.name == "nt" else ""))
        _api._require(launcher.is_file(), "installed_launcher_missing")
        _api._require(
            launcher.resolve().parent == _api.Path(_api.sysconfig.get_path("scripts")).resolve(), "launcher_location"
        )
        launcher_digests[name], launcher_bindings[name] = _api._launcher_binding(
            distribution, launcher, target.split(":")[0]
        )
        launchers[name] = launcher.resolve()
    return {
        "package_version": distribution.version,
        "source_sha": source_sha,
        "wheel_sha256": _api._digest(wheel.read_bytes()),
        "module_sha256": module_digests,
        "launcher_sha256": launcher_digests,
        "launcher_binding": launcher_bindings,
        "native_artifact": native_identity,
    }, launchers
