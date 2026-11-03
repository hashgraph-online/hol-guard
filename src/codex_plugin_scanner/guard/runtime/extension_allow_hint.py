"""Queue-time hint: which configurable extension permissions would allow a reviewed command.

The hint is advisory. The native resident decides it (``extension_review_hint``,
``extension_allow_hint``): it re-evaluates the command against its own admitted
controls with hypothetical enabled permissions, so nothing is mutated and the
answer carries only catalog identifiers (no command text). The runtime also
shape-checks a stored or answered hint, the connector setup hint included
(``extension_hint_shape``).
Enabling a permission still requires the normal proof-bound extension-control
mutation.
"""

from __future__ import annotations

from urllib.parse import quote

from .extension_control_runtime import ExtensionControlRuntimeSnapshot
from .extension_coverage_hint import shaped_hint

EXTENSION_ALLOW_HINT_SCHEMA = "guard.extension-allow-hint.v1"


def hint_authority_admitted(snapshot: ExtensionControlRuntimeSnapshot) -> bool:
    """Whether an allow hint can be offered under this authority.

    A protected authority can apply the Allow now. A device that never enrolled
    can once it enrolls, so it gets the hint with the setup step in front of it.
    Any other failure (degraded, tampered, recovery) needs repair first.
    """

    return snapshot.authority_failure is None or snapshot.awaiting_enrollment


def validated_extension_allow_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored hint, or None."""

    return shaped_hint(value, "allow")


CONNECTOR_SETUP_HINT_SCHEMA = "guard.connector-setup-hint.v1"
CONNECTOR_SETUP_SURFACES = frozenset({"cli", "package-scripts", "mcp"})


def connector_setup_deep_link(cli_id: str) -> str:
    """Dashboard-relative Protect path for one connector; never carries a host."""

    return f"/extensions/local-cli/{quote(cli_id, safe='')}"


def validated_connector_setup_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored connector hint, or None."""

    return shaped_hint(value, "connector")
