"""Read the inspected Composio meta-tool execution boundaries from the resident.

Tool roles describe routing, never authority. Hosted execution takes an array
of exact tool slugs, arguments and optional account selectors. Missing account
selectors cannot be interpreted as an account identity by Guard.

The native runtime owns the contract. These helpers only ask it and fall back
to the stricter answer when it cannot be reached: no role at all, and the
provider review a wrapper would draw. Neither helper recomputes a role in
Python, so an absent resident can never route a call the way a reachable one
would have. The fallback is bounded by the name shape every role shares, so an
unreachable resident cannot turn a tool that was never Composio's into a
provider action.
"""

from __future__ import annotations

from typing import Literal, cast

from ..native_composio_role import composio_role_native

ComposioToolRole = Literal["discovery", "batch", "workbench", "connections", "unknown"]


def composio_tool_role(tool_name: str) -> ComposioToolRole | None:
    """The wrapper a tool name routes to, or ``None`` for one the contract does not place.

    An unreachable resident also answers ``None``: callers gate discovery-only
    work on an exact ``"discovery"``, so no role refuses that work rather than
    admitting it.
    """
    native = composio_role_native(tool_name)
    if native is None:
        return None
    # The client admits only the contract's own roles, so the published
    # Literal holds without re-deriving it here.
    return cast("ComposioToolRole | None", native.role)


def composio_names_a_wrapper(tool_name: str) -> bool:
    """Whether this name could route to a Composio wrapper at all.

    A superset of the contract's own routing rather than a copy of it: every
    role the runtime places sits in a trailing ``composio_`` segment, so a name
    without one carries no provider action whatever the resident would answer.
    The contract still decides which wrapper a matching name is and whether the
    call is reviewed; this only bounds what an unreachable resident, or a
    provider-catalog read taken ahead of one, is allowed to reach.
    """
    return tool_name.rsplit("__", 1)[-1].casefold().startswith("composio_")


def composio_requires_action_review(tool_name: str) -> bool:
    """Whether a call to this tool is reviewed as a provider action.

    An unreachable resident answers ``True`` for a name shaped like a wrapper:
    the call then draws the review a wrapper that could carry a provider action
    draws, never the quiet path. Any other name keeps the answer it has when
    the resident is reachable, so an outage does not move an ordinary tool's
    approval identity or refuse to remember its approval.
    """
    native = composio_role_native(tool_name)
    return composio_names_a_wrapper(tool_name) if native is None else native.requires_action_review
