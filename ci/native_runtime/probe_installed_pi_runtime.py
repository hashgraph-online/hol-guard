"""Installed Pi probe runtime helpers; dependencies remain bound to its public entry point."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .probe_installed_pi_api import probe_api


def _is_source_checkout_package(package_path: Path, repo_root: Path) -> bool:
    _api = probe_api()
    return package_path.is_relative_to((repo_root / "src" / "codex_plugin_scanner").resolve())


def _installed_package_path(repo_root: Path) -> Path:
    _api = probe_api()
    package = _api.importlib.import_module("codex_plugin_scanner")
    raw_path = getattr(package, "__file__", None)
    if not isinstance(raw_path, str) or not raw_path:
        raise _api.ProbeError("installed package origin is unavailable")
    raw_package_path = _api.Path(raw_path)
    try:
        if _api.stat.S_ISLNK(_api.os.lstat(raw_package_path).st_mode):
            raise _api.ProbeError("installed package module is symlinked")
    except OSError as exc:
        raise _api.ProbeError("installed package module origin could not be inspected") from exc
    package_path = raw_package_path.resolve()
    if _api._is_source_checkout_package(package_path, repo_root):
        raise _api.ProbeError(f"probe imported source tree package: {package_path}")
    try:
        distribution = _api.metadata.distribution("hol-guard")
        distribution_files = distribution.files
        direct_url_text = distribution.read_text("direct_url.json")
    except (_api.metadata.PackageNotFoundError, OSError, ValueError) as exc:
        raise _api.ProbeError("installed hol-guard distribution metadata is unavailable") from exc
    if not distribution_files:
        raise _api.ProbeError("installed hol-guard distribution file manifest is unavailable")
    if direct_url_text is not None:
        if not isinstance(direct_url_text, str) or not direct_url_text.strip():
            raise _api.ProbeError("installed hol-guard direct URL metadata is empty")
        try:
            direct_url = _api.json.loads(direct_url_text)
        except (TypeError, ValueError) as exc:
            raise _api.ProbeError("installed hol-guard direct URL metadata is invalid") from exc
        if not isinstance(direct_url, _api.Mapping):
            raise _api.ProbeError("installed hol-guard direct URL metadata is invalid")
        directory_info = direct_url.get("dir_info")
        if directory_info is not None and not isinstance(directory_info, _api.Mapping):
            raise _api.ProbeError("installed hol-guard direct URL metadata is invalid")
        if isinstance(directory_info, _api.Mapping):
            editable = directory_info.get("editable")
            if editable is not None and editable is not False:
                raise _api.ProbeError("editable hol-guard installation is not accepted")
    try:
        resolved_distribution_files = set()
        for path in distribution_files:
            manifest_path = distribution.locate_file(path)
            if _api.stat.S_ISLNK(_api.os.lstat(manifest_path).st_mode):
                raise _api.ProbeError("installed hol-guard distribution manifest contains a symlink")
            resolved_distribution_files.add(manifest_path.resolve())
    except _api.ProbeError:
        raise
    except (OSError, RuntimeError, TypeError) as exc:
        raise _api.ProbeError("installed hol-guard distribution file locations are unavailable") from exc
    if package_path not in resolved_distribution_files and not (
        package_path.suffix == ".pyc" and package_path.with_suffix(".py") in resolved_distribution_files
    ):
        raise _api.ProbeError("installed package module is outside the hol-guard distribution manifest")
    return package_path


def _short_temp_parent() -> str | None:
    _api = probe_api()
    candidate = _api.Path("/tmp")
    if candidate.is_dir() and _api.os.access(candidate, _api.os.W_OK | _api.os.X_OK):
        return str(candidate)
    return None


def _short(value: bytes | str, limit: int = 1_500) -> str:
    _api = probe_api()
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    return text if len(text) <= limit else text[:limit] + "..."


def _run(
    argv: list[str],
    *,
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    _api = probe_api()
    try:
        completed = _api.subprocess.run(
            argv,
            cwd=cwd,
            env=dict(env),
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, _api.subprocess.TimeoutExpired) as exc:
        raise _api.ProbeError(f"{label} did not complete: {exc}") from exc
    if completed.returncode != 0:
        raise _api.ProbeError(
            f"{label} failed with exit {completed.returncode}: "
            f"stdout={_api._short(completed.stdout)!r} stderr={_api._short(completed.stderr)!r}"
        )
    return completed


def _isolated_env(*, home: Path, python_path: Path) -> dict[str, str]:
    _api = probe_api()
    env = {key: value for key, value in _api.os.environ.items() if key in _api._ENV_ALLOWLIST}
    bin_dir = home / ".local" / "bin"
    env["PATH"] = _api.os.pathsep.join((str(bin_dir), str(python_path.parent), env.get("PATH", "")))
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["XDG_CONFIG_HOME"] = str(home / "config")
    env["XDG_CACHE_HOME"] = str(home / "cache")
    env["XDG_DATA_HOME"] = str(home / "data")
    env["XDG_STATE_HOME"] = str(home / "state")
    env.pop("PYTHONPATH", None)
    for key in tuple(_api.os.environ):
        if key.startswith("HOL_GUARD_") or key.startswith("GUARD_"):
            env.pop(key, None)
    return env


def _probe_python_path() -> Path:
    # Keep the venv launcher so its site-packages remain active; resolving a
    # symlink can escape the wheel-installed environment.
    _api = probe_api()
    return _api.Path(_api.sys.executable)


def _node_command() -> list[str]:
    _api = probe_api()
    node = _api.shutil.which("node")
    if not node:
        raise _api.ProbeError("Node is required for the generated Pi extension probe")
    try:
        with _api.tempfile.TemporaryDirectory(prefix="hg-node-capability-", dir=_api._short_temp_parent()) as directory:
            module = _api.Path(directory) / "capability-probe.ts"
            module.write_text(_api._NODE_PROBE_SOURCE, encoding="utf-8")
            for flags in (("--experimental-strip-types",), ()):
                try:
                    result = _api.subprocess.run(
                        [node, *flags, str(module)],
                        capture_output=True,
                        check=False,
                        timeout=_api._NODE_PROBE_TIMEOUT,
                    )
                except (OSError, _api.subprocess.TimeoutExpired):
                    continue
                if result.returncode == 0 and result.stdout == b"node-capability-probe":
                    return [node, "--no-warnings", *flags]
    except OSError as exc:
        raise _api.ProbeError("Node TypeScript capability probe could not complete") from exc
    raise _api.ProbeError("Node cannot execute erasable TypeScript modules")


def _probe_native_identity() -> tuple[Any, Any, Any]:
    _api = probe_api()
    from codex_plugin_scanner.guard.config import hook_fast_path_enabled
    from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

    if native_mode() != "auto":
        raise _api.ProbeError(f"unexpected native mode: {native_mode()}")
    if not hook_fast_path_enabled():
        raise _api.ProbeError("unset fast-path configuration must be enabled")
    status = native_runtime_status()
    if not status.available or not status.compatible or status.reason != "native_ready":
        raise _api.ProbeError(f"installed native runtime is not ready: {status}")
    if status.identity is None or status.capabilities is None:
        raise _api.ProbeError(f"installed native runtime identity is incomplete: {status}")
    return status, status.identity, status.capabilities
