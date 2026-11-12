"""Native ``hermes_install_plan`` answers for the Hermes adapter (and OpenClaw's install state).

The native runtime decides which ``mcp_servers`` entries Guard owns, the
overlay names, the ``guard`` section and the install state. This module only
sends the request and checks the answer's shape; answers index into the
caller's own lists, so YAML key order survives the round trip.
"""

from __future__ import annotations

from typing import Any, NoReturn

_INSTALL_STATES = ("installed", "already_managed", "repaired_managed_install")


def overlay_names(source_configs: dict[str, dict[str, object]]) -> list[str]:
    """The overlay name of each source server, in order."""

    names = _plan(
        "overlay_names",
        servers=[[key, _str_or_none(server.get("name"))] for key, server in source_configs.items()],
    ).get("names")
    if not isinstance(names, list) or len(names) != len(source_configs) or not all(isinstance(n, str) for n in names):
        _invalid()
    return names


def kept_servers(
    mcp_servers: dict[Any, Any], managed_names: list[str], overlay: dict[str, dict[str, object]]
) -> tuple[dict[str, Any], list[str]]:
    """User ``mcp_servers`` entries Guard does not manage, plus the overlay under ``guard-`` keys.

    Also returns the overlay keys, which become the new managed-servers manifest.
    """

    items = list(mcp_servers.items())
    answer = _plan(
        "servers",
        names=[name if isinstance(name, str) else None for name, _ in items],
        managed=managed_names,
        overlay=list(overlay),
    )
    keep, add = answer.get("keep"), answer.get("add")
    if (
        not isinstance(keep, list)
        or not all(isinstance(i, int) and 0 <= i < len(items) for i in keep)
        or not isinstance(add, list)
        or len(add) != len(overlay)
        or not all(isinstance(key, str) for key in add)
    ):
        _invalid()
    kept: dict[str, Any] = {items[index][0]: items[index][1] for index in keep}
    for key, config in zip(add, overlay.values(), strict=True):
        kept[key] = config
    return kept, [str(key) for key in add]


def consumer_base_url(issuer: object) -> str:
    """The Guard Cloud consumer API URL for a stored OAuth issuer."""

    base_url = _plan("consumer_base_url", issuer=_str_or_none(issuer)).get("base_url")
    if not isinstance(base_url, str):
        _invalid()
    return base_url


def guard_section(*, base_url: str, timeout_seconds: int) -> dict[str, object]:
    """The ``guard`` section that turns on Hermes's runtime policy."""

    section = _plan("guard_section", base_url=base_url, timeout_seconds=timeout_seconds).get("section")
    if not isinstance(section, list) or not all(isinstance(pair, list) and len(pair) == 2 for pair in section):
        _invalid()
    return {str(key): value for key, value in section}


def install_state(*, manifest_empty: bool, overlay_exists: bool, pretool_exists: bool) -> str:
    """Whether the install is new, already managed or a repair."""

    state = _plan(
        "install_state",
        manifest_empty=manifest_empty,
        overlay_exists=overlay_exists,
        pretool_exists=pretool_exists,
    ).get("state")
    if state not in _INSTALL_STATES:
        _invalid()
    return str(state)


def _plan(op: str, **fields: object) -> dict[str, object]:
    from ..native_runner_authority import native_runner_authority

    answer = native_runner_authority("hermes_install_plan", {"op": op, **fields})
    if not isinstance(answer, dict):
        _invalid()
    return answer


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _invalid() -> NoReturn:
    from ..native_runner_authority import NativeRunnerAuthorityError

    raise NativeRunnerAuthorityError("native_hermes_install_plan_invalid")
