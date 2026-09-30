"""Probe environment isolation for local MCP catalog discovery."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

_PROBE_ENV_LOCKED = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "__PYVENV_LAUNCHER__",
    }
)


def probe_search_path() -> str:
    """PATH for MCP probes, without Guard package-shim wrappers."""

    fallback = os.environ.get("PATH", "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin")
    filtered = [entry for entry in fallback.split(os.pathsep) if entry and not _is_package_shim_dir(entry)]
    for extra in ("/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"):
        if extra not in filtered and Path(extra).is_dir():
            filtered.append(extra)
    return os.pathsep.join(filtered)


def is_package_shim_executable(path: str) -> bool:
    candidate = Path(path)
    parent = candidate.parent
    return parent.name == "bin" and parent.parent.name == "package-shims"


def _is_package_shim_dir(entry: str) -> bool:
    path = Path(entry)
    return path.name == "bin" and path.parent.name == "package-shims"


def probe_env(tmp: str, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": probe_search_path(),
        "HOME": tmp,
        "TMPDIR": tmp,
        "LANG": "C",
        "LC_ALL": "C",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "npm_config_loglevel": "error",
    }
    env.update(_package_cache_env())
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            env["SYSTEMROOT"] = system_root
    if extra:
        for key, value in extra.items():
            name = key.strip()
            if not name or name.upper() in _PROBE_ENV_LOCKED:
                continue
            if "=" in name or "\x00" in name or "\x00" in value:
                continue
            env[name] = value
    return env


def _package_cache_env() -> dict[str, str]:
    extra: dict[str, str] = {}
    home = os.environ.get("HOME")
    npm_cache = _configured_cache("NPM_CONFIG_CACHE", "npm_config_cache")
    if not npm_cache and home:
        candidate = Path(home) / ".npm"
        if candidate.is_dir():
            npm_cache = str(candidate)
    if npm_cache:
        extra["npm_config_cache"] = npm_cache
        extra["NPM_CONFIG_CACHE"] = npm_cache
    uv_cache = _configured_cache("UV_CACHE_DIR")
    if not uv_cache and home:
        candidate = Path(home) / ".cache" / "uv"
        if candidate.is_dir():
            uv_cache = str(candidate)
    if uv_cache:
        extra["UV_CACHE_DIR"] = uv_cache
    bun_cache = _configured_cache("BUN_INSTALL_CACHE_DIR")
    if not bun_cache and home:
        candidate = Path(home) / ".bun" / "install" / "cache"
        if candidate.is_dir():
            bun_cache = str(candidate)
    if bun_cache:
        extra["BUN_INSTALL_CACHE_DIR"] = bun_cache
    return extra


def _configured_cache(*keys: str) -> str | None:
    raw = _first_env(*keys)
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    path = Path(stripped)
    if path.is_absolute():
        return stripped
    return str((Path.cwd() / path).resolve())


def _first_env(*keys: str) -> str | None:
    for key in keys:
        value = os.environ.get(key)
        if value:
            return value
    return None
