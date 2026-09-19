"""Frozen generic row ordering shared by preview and consuming lookups."""

from __future__ import annotations

from typing import Protocol

from .action_lattice import guard_action_severity

_SCOPE_PRIORITY = {"artifact": 0, "workspace": 1, "publisher": 2, "harness": 3, "global": 4}


class GenericPolicyRow(Protocol):
    def __getitem__(self, key: str, /) -> object: ...


def generic_policy_row_precedence(row: GenericPolicyRow) -> tuple[int, int, str, int, tuple[str, ...]]:
    """Return a descending key without granting precedence to source labels.

    Specificity and authenticated recency select generic authority. Only an
    otherwise tied group prefers the stricter action, followed by canonical
    selectors. Database row IDs are excluded because signed membership does
    not authenticate them. Independent managed and intrinsic restrictions
    are composed outside generic policy selection.
    """

    scope = str(row["scope"])
    specific = scope in {"workspace", "harness", "global"} and row["artifact_id"] is not None
    selectors = tuple(
        str(row[field]) if row[field] is not None else ""
        for field in (
            "harness",
            "artifact_id",
            "artifact_hash",
            "workspace",
            "publisher",
            "exact_command_sha256",
            "expires_at",
        )
    )
    return (
        -_SCOPE_PRIORITY.get(scope, 5),
        int(specific),
        str(row["updated_at"]),
        guard_action_severity(row["action"], unknown_action="block"),
        selectors,
    )


__all__ = ["GenericPolicyRow", "generic_policy_row_precedence"]
