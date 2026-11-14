"""Hermes through the native ``harness_adapter`` kind.

The kind owns Hermes's paths, detection, the MCP overlay, the pre-tool hook
payload, the Guard entries in ``config.yaml`` and its shell-hooks allowlist,
the authenticated manifest, uninstall, the launch environment, the runtime
probe and the doctor warning. An op that needs something only the Guard
process knows replies with one key, and this module answers it and asks again:
``launchers`` (Guard's proxy launch for each local stdio server), ``yaml``
(PyYAML's rendering of a rewritten ``config.yaml``) and, on Windows,
``skills`` (the skill directory identities the resident cannot walk there).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml as _yaml  # type: ignore[import-untyped]

from ..skill_directory_identity import inspect_skill_directory, skill_directory_identity_metadata
from .base import HarnessContext, PreparedHarnessInstall
from .native_harness import NativeHarnessAdapter

_HARNESS = "hermes"
# Each reply names something new, so an op settles within a handful of rounds.
_REPLY_LIMIT = 32


def _sorted_children(directory: Path) -> list[Path]:
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _portable_skill_identities(homes: list[str]) -> dict[str, dict[str, object]]:
    """Finished skill directory identities, keyed by SKILL.md path, for hosts the resident cannot walk."""

    identities: dict[str, dict[str, object]] = {}
    for home in homes:
        skills_dir = Path(home) / "skills"
        if not skills_dir.is_dir():
            continue
        for category_dir in _sorted_children(skills_dir):
            if not category_dir.is_dir():
                continue
            for skill_dir in _sorted_children(category_dir):
                skill_md = skill_dir / "SKILL.md"
                if not (skill_dir.is_dir() and skill_md.is_file()):
                    continue
                identity = inspect_skill_directory(skill_md, scope_root=skills_dir)
                identities[str(skill_md)] = {
                    "metadata": skill_directory_identity_metadata(
                        identity, version_label=f"{category_dir.name}/{skill_dir.name}"
                    ),
                    "complete": identity.status == "complete",
                    "failure_reason": identity.failure_reason,
                }
    return identities


def _launchers(context: HarnessContext, requests: list[dict[str, Any]]) -> str:
    """Guard's proxy launch for each local stdio server the kind names."""
    from ..stable_guard_cli import guard_cli_launcher
    from .mcp_servers import ManagedMcpServer, proxy_launcher_entry

    entries = [
        proxy_launcher_entry(
            proxy_command="hermes-mcp-proxy",
            context=context,
            server=ManagedMcpServer(
                harness=_HARNESS,
                name=str(request["name"]),
                source_scope="global",
                config_path=str(request["config_path"]),
                command=str(request["command"]),
                args=tuple(str(arg) for arg in request["args"]),
                transport="stdio",
                env={str(key): str(value) for key, value in request["env"]},
                enabled=True,
            ),
        )
        for request in requests
    ]
    return json.dumps({"requests": requests, "guard_cli": str(Path(guard_cli_launcher())), "entries": entries})


def _answer(context: HarnessContext, key: str, value: Any, fields: dict[str, Any]) -> None:
    """Merge this process's answer to one reply into the request."""
    if key == "launchers" and isinstance(value, list):
        fields["launchers"] = _launchers(context, value)
    elif key == "yaml" and isinstance(value, str):
        rendered = _yaml.dump(json.loads(value), default_flow_style=False, sort_keys=False)
        fields["yaml"] = json.dumps([value, rendered])
    elif key == "skills" and isinstance(value, list):
        fields["skills"] = json.dumps(_portable_skill_identities([str(home) for home in value]))
    else:
        raise ValueError("Hermes adapter reply is malformed")


class HermesHarnessAdapter(NativeHarnessAdapter):
    """Hermes skills, MCP servers and its ``hooks.pre_tool_call`` entry."""

    def __init__(self) -> None:
        super().__init__(_HARNESS, (), "")

    def install(self, context: HarnessContext) -> dict[str, object]:
        return super().prepare_install(context).publish(context.guard_home)

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Unavailable: the plan signs its manifest, which may create the state key."""
        from ..runtime_transition import TransitionError

        raise TransitionError("adapter_preparation_unavailable")

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        for _ in range(_REPLY_LIMIT):
            answer = super()._ask(op, context, **fields)
            reply = answer.get("reply")
            if set(answer) != {"reply"}:
                return answer
            if not isinstance(reply, dict) or len(reply) != 1:
                raise ValueError("Hermes adapter reply is malformed")
            ((key, value),) = reply.items()
            _answer(context, key, value, fields)
        raise RuntimeError("Hermes adapter request did not settle")
