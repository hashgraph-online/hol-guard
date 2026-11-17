"""Exact ownership and legacy-adoption operations for Codex hook groups."""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from typing import Any

from .codex_config import _Wire
from .codex_hook_self_binding import answer_text, ask_hook_owners, install_fields


def legacy_binding_fields(
    *,
    expected_bindings: Sequence[Mapping[str, object]],
    current_argv: Sequence[str],
    legacy_argv: Sequence[str],
    legacy_status_messages: Collection[str],
) -> dict[str, object]:
    """What a pre-manifest handler of the current package is matched against."""

    return {
        "expected": json.dumps(list(expected_bindings), separators=(",", ":")),
        "argv": list(current_argv),
        "legacy_argv": list(legacy_argv),
        "statuses": sorted(legacy_status_messages),
    }


def exact_legacy_hook_bindings(
    hooks: Mapping[str, object],
    *,
    expected_bindings: Sequence[Mapping[str, object]],
    current_argv: Sequence[str],
    legacy_argv: Sequence[str],
    legacy_status_messages: set[str],
    windows: bool | None = None,
) -> list[dict[str, object]]:
    """Select exact current-package entries for explicit pre-manifest adoption."""

    wire = _Wire(hooks)
    answer = ask_hook_owners(
        "legacy",
        windows=windows,
        hooks=wire.text(hooks),
        **legacy_binding_fields(
            expected_bindings=expected_bindings,
            current_argv=current_argv,
            legacy_argv=legacy_argv,
            legacy_status_messages=legacy_status_messages,
        ),
    )
    return wire.decode(answer_text(answer, "bindings"))


def _live(command: str, windows: bool | None) -> dict[str, Any]:
    return ask_hook_owners("live", windows=windows, command=command)


def is_live_guard_codex_hook_command(command: str, *, windows: bool | None = None) -> bool:
    """Whether ``command`` runs a Guard Codex hook handler of any generation."""

    return _live(command, windows).get("live") is True


def missing_guard_hook_program(command: str, *, windows: bool | None = None) -> str | None:
    """Return the absolute launcher or bridge path a Guard hook needs that no longer exists.

    Codex cannot start such a handler, so it gives no protection. Bare names
    resolve through PATH at launch time and are not checked here.
    """

    missing = _live(command, windows).get("missing")
    return missing if isinstance(missing, str) else None


def require_codex_hook_owner(
    command: str,
    *,
    ownership: str,
    windows: bool | None = None,
    coordinate: str | None = None,
    source_path: str | None = None,
) -> None:
    """Reject competing Guard handlers without silently adopting or deleting them.

    The native runtime decides whether the handler runs Guard and writes the
    refusal: where the handler is, what it runs, that Guard changed nothing,
    and the one edit that clears it.
    """

    conflict = ask_hook_owners(
        "owner",
        windows=windows,
        command=command,
        ownership=ownership,
        coordinate=coordinate,
        source_path=source_path,
    ).get("conflict")
    if isinstance(conflict, str):
        raise RuntimeError(conflict)


def _matches(hooks: object, windows: bool | None) -> dict[str, Any]:
    return ask_hook_owners("matches", windows=windows, hooks=_Wire(hooks).text(hooks))


def live_owned_codex_event_matches(hooks: object, *, windows: bool | None = None) -> dict[str, bool]:
    """Return which managed Codex events still route a live Guard handler."""

    found = _matches(hooks, windows).get("matches")
    if not isinstance(found, dict):
        raise RuntimeError("codex_hook_owners answered without matches")
    return {str(event_name): matched is True for event_name, matched in found.items()}


def live_guard_codex_hooks_intercept(hooks: object, *, windows: bool | None = None) -> bool:
    """Return whether live Codex config still routes Guard's launchable intercept hooks."""

    return _matches(hooks, windows).get("intercept") is True


def install_managed_codex_hook_groups(
    hooks: dict[str, object],
    managed_groups: Mapping[str, dict[str, object]],
    *,
    current_guard_home: Path,
    current_package_root: Path | None = None,
) -> None:
    """Append the managed groups once every remaining Guard handler has a proven owner.

    The native runtime refuses while a Guard handler is not bound to
    ``current_guard_home``; ``hooks`` is then left unchanged.
    """

    wire = _Wire(hooks, dict(managed_groups))
    answer = ask_hook_owners(
        "install",
        hooks=wire.text(hooks),
        managed=wire.text(dict(managed_groups)),
        **install_fields(current_guard_home, current_package_root),
    )
    conflict = answer.get("conflict")
    if isinstance(conflict, str):
        raise RuntimeError(conflict)
    installed = wire.decode(answer_text(answer, "hooks"))
    hooks.clear()
    hooks.update(installed)


def codex_doctor_result(
    warnings: Sequence[str],
    hook_state: Mapping[str, object],
    base_status: object,
) -> tuple[list[str], object]:
    """Doctor's Codex warnings and setup status, decided from live hook proof."""

    answer = ask_hook_owners(
        "doctor",
        warnings=[str(item) for item in warnings],
        hook_state=dict(hook_state),
        base_status=base_status if isinstance(base_status, str) else None,
    )
    found = answer.get("warnings")
    if not isinstance(found, list):
        raise RuntimeError("codex_hook_owners answered without warnings")
    return [str(item) for item in found], answer.get("status")


__all__ = [
    "codex_doctor_result",
    "exact_legacy_hook_bindings",
    "install_managed_codex_hook_groups",
    "is_live_guard_codex_hook_command",
    "live_guard_codex_hooks_intercept",
    "live_owned_codex_event_matches",
    "missing_guard_hook_program",
    "require_codex_hook_owner",
]
