"""Codex install and uninstall decisions answered by the native runtime.

The native ``codex_install_plan`` runner-authority kind names what to remove
from files Guard does not own; these helpers send the values and apply the
answer, refusing one they cannot read.
"""

from __future__ import annotations

from collections.abc import Mapping

SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"


def _install_plan(op: str, **fields: object) -> dict[str, object]:
    from ..native_runner_authority import native_runner_authority

    return native_runner_authority("codex_install_plan", {"op": op, **fields})


def _malformed() -> Exception:
    from ..native_runner_authority import NativeRunnerAuthorityError

    return NativeRunnerAuthorityError("Codex install plan answer is malformed")


def remove_managed_shell_guard_blocks(content: bytes) -> bytes:
    """Remove only legacy Guard marker blocks while preserving every other byte.

    The native runtime names the byte ranges the blocks occupy. A file without
    the begin marker holds no block, so it is not sent.
    """

    if SHELL_GUARD_BEGIN.encode("utf-8") not in content:
        return content
    ranges = _install_plan("shell_blocks", content=content.decode("latin-1")).get("ranges")
    if not isinstance(ranges, list):
        raise _malformed()
    kept = bytearray()
    position = 0
    for item in ranges:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(value, int) and not isinstance(value, bool) for value in item)
            or not position <= item[0] < item[1] <= len(content)
        ):
            raise _malformed()
        kept += content[position : item[0]]
        position = item[1]
    kept += content[position:]
    return bytes(kept)


def guard_proxy_server_names(servers: Mapping[str, object]) -> frozenset[str]:
    """The servers whose launch is a Guard MCP proxy, as the native runtime reads it.

    Only an entry with an argument list is a launch the test applies to.
    """

    launches: dict[str, dict[str, object]] = {}
    for name, server in servers.items():
        if not isinstance(name, str) or not isinstance(server, dict):
            continue
        args = server.get("args")
        if not isinstance(args, list):
            continue
        command = server.get("command")
        launches[name] = {
            "command": command if isinstance(command, str) else None,
            "args": [value for value in args if isinstance(value, str)],
        }
    if not launches:
        return frozenset()
    names = _install_plan("guard_proxies", servers=launches).get("names")
    if not isinstance(names, list) or not all(isinstance(name, str) and name in launches for name in names):
        raise _malformed()
    return frozenset(names)
