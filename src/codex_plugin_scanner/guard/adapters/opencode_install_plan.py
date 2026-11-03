"""OpenCode install plans from the native ``opencode_install_plan`` kind.

Which servers Guard manages, the root config's ``permission`` and ``mcp``
values and the runtime overlay are decided natively. Python keeps the file
I/O, the source config read and Guard's proxy argv. Every object in the answer
is a build spec evaluated here over the request's own objects, so user values
keep their objects and key order:

- ``["value", v]``: a string, bool, null or list of strings Guard chose;
- ``["ref", path]``: the request value at *path* (keys and list indices);
- ``["object", [[key, spec], ...]]``: a new dict, assigned in that order;
- ``["merge", [spec, ...]]``: a new dict updated with each dict in turn;
- ``["launch", server, "companion" | "override"]``: Guard's proxy argv for
  that request server, without or with the workspace.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ...ecosystems.opencode import _load_json_or_jsonc
from ..launcher import merge_guard_launcher_env
from .base import HarnessContext
from .hook_python import guard_cli_command
from .mcp_relay_native import mcp_proxy_command
from .mcp_servers import ManagedMcpServer, proxy_cli_args, proxy_process_env

_ANSWER_KEYS = frozenset({"managed", "skipped", "permission", "mcp", "overlay"})
_LAUNCHES = frozenset({"companion", "override"})


@dataclass(frozen=True)
class OpenCodeInstallPlan:
    """The servers Guard manages and the values it writes for them."""

    managed: tuple[ManagedMcpServer, ...]
    skipped: tuple[str, ...]
    permission: dict[str, object]
    mcp: dict[str, object]
    overlay: dict[str, object]


def _malformed(detail: str) -> ValueError:
    return ValueError(f"the native OpenCode install plan was malformed: {detail}")


def _source_entry(server: ManagedMcpServer, configs: dict[str, object]) -> dict[str, object] | None:
    """The server's own entry in its source config, read once per file."""

    if server.config_path not in configs:
        payload, parse_error, _ = _load_json_or_jsonc(Path(server.config_path))
        configs[server.config_path] = None if parse_error else payload
    payload = configs[server.config_path]
    mcp = payload.get("mcp") if isinstance(payload, dict) else None
    entry = mcp.get(server.name) if isinstance(mcp, dict) else None
    return entry if isinstance(entry, dict) else None


class _Builder:
    """Evaluate the answer's build specs over the request Python sent."""

    def __init__(self, context: HarnessContext, request: dict[str, object], servers: list[ManagedMcpServer]) -> None:
        self._context = context
        self._request = request
        self._servers = servers
        home_dir = context.home_dir
        self._home = str(home_dir) if home_dir.resolve() != Path.home().resolve() else None

    def build(self, spec: object) -> object:
        if not isinstance(spec, list) or not spec or not isinstance(spec[0], str):
            raise _malformed("a build spec is not a tagged list")
        tag = spec[0]
        if tag == "launch":
            return self._launch(spec)
        if len(spec) != 2:
            raise _malformed(f"a {tag!r} spec has {len(spec)} parts")
        body = spec[1]
        if tag == "value":
            return _literal(body)
        if tag == "ref":
            return self._resolve(body)
        if tag == "object":
            built: dict[str, object] = {}
            for key, item in _pairs(body):
                built[key] = self.build(item)
            return built
        if tag == "merge":
            if not isinstance(body, list):
                raise _malformed("merge parts are not a list")
            merged: dict[str, object] = {}
            for part in body:
                merged.update(self.object(part))
            return merged
        raise _malformed(f"unknown spec tag {tag!r}")

    def object(self, spec: object) -> dict[str, object]:
        built = self.build(spec)
        if not isinstance(built, dict):
            raise _malformed("a spec that must build an object did not")
        return built

    def _resolve(self, path: object) -> object:
        if not isinstance(path, list):
            raise _malformed("a reference path is not a list")
        current: object = self._request
        for step in path:
            current = _step(current, step, path)
        return current

    def _launch(self, spec: list[object]) -> list[str]:
        if len(spec) != 3 or type(spec[1]) is not int or spec[2] not in _LAUNCHES:
            raise _malformed("a launch spec is not [launch, server, companion|override]")
        index = spec[1]
        if not 0 <= index < len(self._servers):
            raise _malformed("a launch names no request server")
        workspace_dir = self._context.workspace_dir
        workspace = None
        if spec[2] == "override" and workspace_dir is not None:
            workspace = str(workspace_dir)
        args = proxy_cli_args(
            proxy_command="opencode-mcp-proxy",
            guard_home=str(self._context.guard_home),
            server=self._servers[index],
            home=self._home,
            workspace=workspace,
        )
        return mcp_proxy_command(guard_cli_command(self._context, args))


def _step(current: object, step: object, path: list[object]) -> object:
    if isinstance(step, str) and isinstance(current, dict) and step in current:
        return current[step]
    if type(step) is int and isinstance(current, list) and 0 <= step < len(current):
        return current[step]
    raise _malformed(f"reference {path!r} does not name a request value")


def _literal(value: object) -> object:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise _malformed("a literal is not a string, bool, null or list of strings")


def _pairs(body: object) -> list[tuple[str, object]]:
    if not isinstance(body, list):
        raise _malformed("object pairs are not a list")
    pairs: list[tuple[str, object]] = []
    for pair in body:
        if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str):
            raise _malformed("an object pair is not [key, spec]")
        pairs.append((pair[0], pair[1]))
    return pairs


def _strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _malformed(f"{field} is not a list of strings")
    return tuple(value)


def _managed(value: object, count: int) -> tuple[int, ...]:
    if not isinstance(value, list) or not all(type(item) is int for item in value):
        raise _malformed("managed is not a list of server indices")
    indices: tuple[int, ...] = tuple(value)
    previous = -1
    for index in indices:
        if index <= previous or index >= count:
            raise _malformed("managed indices are not increasing request positions")
        previous = index
    return indices


def plan_opencode_install(
    context: HarnessContext,
    *,
    servers: tuple[ManagedMcpServer, ...],
    skipped: tuple[str, ...],
    artifacts: tuple[str, ...],
    workspace_servers: set[str],
    permission: object,
    mcp: object,
) -> OpenCodeInstallPlan:
    """Plan an OpenCode install; raises ``ValueError`` when no valid plan comes back.

    *artifacts* are the detected MCP server artifact names; *permission* and
    *mcp* are the root config's current values.
    """

    # Imported here so adapter imports stay off the native runtime.
    from ..native_runner_authority import native_runner_authority

    configs: dict[str, object] = {}
    server_list = list(servers)
    request: dict[str, object] = {
        "op": "plan",
        "workspace": context.workspace_dir is not None,
        "servers": [
            {
                "name": server.name,
                "source_scope": server.source_scope,
                "command": server.command,
                "args": list(server.args),
                "env": dict(server.env),
                "enabled": server.enabled,
                "proxy_environment": merge_guard_launcher_env(proxy_process_env(server.env)),
                "source": None if server.source_scope == "project" else _source_entry(server, configs),
            }
            for server in server_list
        ],
        "skipped": list(skipped),
        "artifacts": list(artifacts),
        "workspace_servers": sorted(workspace_servers),
        "permission": permission,
        "mcp": mcp,
        "mcp_keys": list(mcp) if isinstance(mcp, dict) else [],
    }
    answer: dict[str, object] = native_runner_authority("opencode_install_plan", request)
    if answer.keys() != _ANSWER_KEYS:
        raise _malformed("the answer keys are wrong")
    builder = _Builder(context, request, server_list)
    managed = _managed(answer["managed"], len(server_list))
    return OpenCodeInstallPlan(
        managed=tuple(server_list[index] for index in managed),
        skipped=_strings(answer["skipped"], "skipped"),
        permission=builder.object(answer["permission"]),
        mcp=builder.object(answer["mcp"]),
        overlay=builder.object(answer["overlay"]),
    )


__all__ = ["OpenCodeInstallPlan", "plan_opencode_install"]
