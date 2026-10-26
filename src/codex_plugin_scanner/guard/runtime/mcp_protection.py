"""MCP identity primitives used by Guard runtime protections."""

from __future__ import annotations

from dataclasses import dataclass

from ..native_context import context_mcp_identity, native_context_failure_reason


@dataclass(frozen=True, slots=True)
class McpServerIdentity:
    """Stable identity for a local MCP server definition."""

    config_path: str
    command: str
    args_hash: str
    package_name: str | None
    package_version: str | None
    package_source: str
    transport: str
    env_keys: tuple[str, ...]
    env_values_hash: str
    identity_hash: str


def build_mcp_server_identity(
    *,
    config_path: str,
    command: str,
    args: tuple[str, ...],
    transport: str,
    env: dict[str, str] | None = None,
    env_keys: tuple[str, ...] = (),
) -> McpServerIdentity:
    """Project the native server identity; native failure cannot bind approval."""
    identity = context_mcp_identity(
        "mcp_server_identity",
        {
            "config_path": config_path,
            "command": command,
            "args": list(args),
            "transport": transport,
            "environment": list(env.items()) if env is not None else None,
            "env_keys": list(env_keys),
        },
    )
    if identity is None:
        # This aborts an install, so the error is the only thing the person
        # reading it has. "unavailable" alone cannot tell a missing runtime
        # from an unprovisionable home or a resident that was merely slow,
        # which is the difference between a broken build and a busy machine.
        reason = native_context_failure_reason()
        raise ValueError("native_mcp_server_identity_unavailable" + (f":{reason}" if reason else ""))
    return McpServerIdentity(
        config_path=identity["config_path"],
        command=identity["command"],
        args_hash=identity["args_hash"],
        package_name=identity["package_name"],
        package_version=identity["package_version"],
        package_source=identity["package_source"],
        transport=identity["transport"],
        env_values_hash=identity["env_values_hash"],
        identity_hash=identity["identity_hash"],
        env_keys=tuple(identity["env_keys"]),
    )


__all__ = ["McpServerIdentity", "build_mcp_server_identity"]
