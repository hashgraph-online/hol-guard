"""Read a configured Guard proxy's upstream launch without granting authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from ..models import GuardArtifact

MAX_PROXY_UNWRAP_LAYERS = 4
_NATIVE_RELAY_COMMAND = "mcp-relay"
PROXY_LAUNCHER_ENV_KEYS = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONBREAKPOINT",
        "__PYVENV_LAUNCHER__",
        # Native-authority bindings are persisted by the launcher from the
        # installer's ambient env; server env must never inject them.
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_TEST_MODE",
    }
)


@dataclass(frozen=True, slots=True)
class ManagedMcpUpstream:
    command: str
    args: tuple[str, ...]
    env: dict[str, str]
    server_id: str
    source_scope: str
    config_path: str


def proxy_argument_tail(args: tuple[str, ...], commands: frozenset[str]) -> tuple[str, tuple[str, ...]] | None:
    if len(args) > 2 and args[0] == _NATIVE_RELAY_COMMAND:
        # ``<runtime> mcp-relay <python> <proxy argv>`` carries the generated module argv unchanged.
        relayed = args[2:]
        if len(relayed) >= 4 and relayed[:3] == ("-m", "codex_plugin_scanner.cli", "guard") and relayed[3] in commands:
            return relayed[3], relayed[4:]
        return None
    if args and args[0] in commands:
        return args[0], args[1:]
    if len(args) >= 2 and args[0] == "guard" and args[1] in commands:
        return args[1], args[2:]
    if len(args) >= 4 and args[:3] == ("-m", "codex_plugin_scanner.cli", "guard") and args[3] in commands:
        return args[3], args[4:]
    return None


def read_managed_mcp_upstream(artifact: GuardArtifact, commands: frozenset[str]) -> ManagedMcpUpstream | None:
    """Accept the generated launch grammar and its exact connection context.

    The claimed server ID must also be checked against the recovered launch
    by the caller. These fields describe inventory, never trusted tool schemas
    or execution permission. Unknown or ambiguous forms remain unavailable.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    configured_env = artifact.runtime_private_metadata.get("mcp_env", artifact.metadata.get("env", {}))
    if not isinstance(configured_env, dict):
        return None
    normalized_env = {
        key.strip(): value
        for key, value in cast(dict[object, object], configured_env).items()
        if isinstance(key, str) and key.strip() and isinstance(value, str)
    }
    saved = artifact.runtime_private_metadata.get("managed_mcp_origin")
    saved_home = artifact.runtime_private_metadata.get("managed_guard_home")
    request = {
        "op": "upstream",
        "commands": sorted(commands),
        "harness": artifact.harness,
        "name": artifact.name,
        "transport": artifact.transport or "stdio",
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "args": list(artifact.args),
        "saved_origin": list(saved) if isinstance(saved, tuple) and all(isinstance(v, str) for v in saved) else None,
        "saved_guard_home": saved_home if isinstance(saved_home, str) else None,
        # A key that cannot travel as UTF-8 is left out rather than refusing the
        # whole request: a proxy that forwards it names it in its argv, which
        # still refuses, and one that does not never needed it.
        "env_names": [name for name in normalized_env if _encodable(name)],
    }
    try:
        # A value that cannot travel as UTF-8 refuses, so its launch stays unavailable.
        found = native_runner_authority("harness_mcp_discovery", request)["upstream"]
        if found is None:
            return None
        upstream = ManagedMcpUpstream(
            command=_text(found["command"]),
            args=tuple(_text(value) for value in _list(found["args"])),
            env={name: normalized_env[name] for name in map(_text, _list(found["env_names"]))},
            server_id=_text(found["server_id"]),
            source_scope=_text(found["source_scope"]),
            config_path=_text(found["config_path"]),
        )
    except (NativeRunnerAuthorityError, KeyError, TypeError):
        return None
    return upstream


def _encodable(name: str) -> bool:
    try:
        name.encode("utf-8")
    except UnicodeError:
        return False
    return True


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("harness_mcp_discovery upstream field is malformed")
    return value


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise TypeError("harness_mcp_discovery upstream field is malformed")
    return cast(list[object], value)
