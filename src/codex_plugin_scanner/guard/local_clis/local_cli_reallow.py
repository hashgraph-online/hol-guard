"""Always allow on a changed script's review allows the script's new version.

A script the user allowed as a custom extension is bound to its file content.
After an edit every call waits on review again, and the card's Always allow
used to save only the exact command text: the next call with a new PR number
or title asked again. When the user picks Always allow on a review held only
because the script changed, the grant moves to the new version with the
command choices the user already set, and the other calls held on that version
are allowed once.

This runs after the approval gate accepted the decision. It never widens a
grant: only a CLI still allowed for an earlier version of the same file moves,
and only to the version the review names. A block, an unset CLI, an MCP server
or a package script keeps its normal flow. A failure leaves the saved command
approval in place and never fails the resolution.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Mapping

from ..approval_gate_types import ApprovalGateError, ApprovalGateInput
from ..runtime.connector_setup_items import listed_public_items
from ..runtime.extension_allow_hint import validated_connector_setup_hint
from ..runtime.local_cli_identity import UnlistedCliIdentity
from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)


def _changed_cli(store: GuardStore, request_id: str) -> tuple[Mapping[str, object], str, str] | None:
    """The stored CLI a held request names, when it was allowed only for an earlier version."""

    request = store.get_approval_request(request_id, derive_scope=False)
    if request is None:
        return None
    hint = validated_connector_setup_hint(store.get_approval_extension_allow_hint(request_id))
    if hint is None or hint["surface"] != "cli":
        return None
    identity_hash, cli_id = str(hint["identity_hash"]), str(hint["cli_id"])
    if not str(request.get("queue_group_id") or "").startswith(f"connector:{identity_hash}:"):
        return None
    item = next((item for item in listed_public_items(store) if item.get("cli_id") == cli_id), None)
    if (
        item is None
        or item.get("identity_hash") != identity_hash
        or item.get("state") != "allowed"
        or item.get("stale") is not True
        or item.get("surface") != "cli"
    ):
        return None
    return item, cli_id, identity_hash


def _identity(item: Mapping[str, object], cli_id: str, identity_hash: str) -> UnlistedCliIdentity:
    interpreter = item.get("interpreter_name")
    return UnlistedCliIdentity(
        cli_id=cli_id,
        name=str(item.get("name") or cli_id),
        kind="script" if item.get("kind") == "script" else "executable",
        identity_hash=identity_hash,
        example_label=str(item.get("example_label") or ""),
        interpreter_name=interpreter if isinstance(interpreter, str) else None,
    )


def _allow_held_siblings(
    store: GuardStore,
    *,
    cli_id: str,
    identity_hash: str,
    request_id: str,
    approval_gate_input: ApprovalGateInput | None,
    now: str,
) -> int:
    from ..approvals import bulk_allow_read_only_once
    from .local_cli_connector_group import connector_group_request_ids

    ids = [
        item
        for item in connector_group_request_ids(store, cli_id=cli_id, identity_hash=identity_hash)
        if item != request_id
    ]
    if not ids:
        return 0
    outcome = bulk_allow_read_only_once(store=store, request_ids=ids, approval_gate_input=approval_gate_input, now=now)
    count = outcome.get("resolved_count")
    return count if isinstance(count, int) else 0


def reallow_changed_cli(
    store: GuardStore,
    *,
    request_id: str,
    approval_gate_input: ApprovalGateInput | None,
    now: str,
) -> dict[str, object] | None:
    """Move a changed CLI's allow to the version this review names; never raises."""

    from ..native_policy_snapshot import notify_native_policy_mutation
    from ..runtime.custom_extension_continuity import record_local_custom_extension_mutation

    try:
        # Capture the optimistic-lock revision before inspecting the allow or
        # its command choices. A concurrent block must make the write fail,
        # not supply the revision that would overwrite that newer decision.
        expected = store.read_local_cli_revision()
        changed = _changed_cli(store, request_id)
        if changed is None:
            return None
        item, cli_id, identity_hash = changed
        command_states = store.read_local_cli_command_states(cli_id)
        notify_native_policy_mutation(store.guard_home)
        try:
            revision = record_local_custom_extension_mutation(
                store,
                identity=_identity(item, cli_id, identity_hash),
                state="allowed",
                expected_revision=expected,
                # The writer replaces the command choices it is given, so the
                # stored ones are passed back unchanged.
                command_states=command_states,
                now=now,
            )
        finally:
            notify_native_policy_mutation(store.guard_home)
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        _LOGGER.warning("Changed CLI re-allow unavailable (%s)", type(error).__name__)
        return {"status": "failed", "error": type(error).__name__}
    result: dict[str, object] = {
        "status": "allowed",
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "revision": revision,
        "held_allowed_once": 0,
    }
    # The origin approval's stripe is still locked. Siblings must be resolved
    # by the outer approval wrapper after that stripe has been released.
    return result


def finalize_reallow_siblings(
    store: GuardStore,
    *,
    request_id: str,
    changed_cli: dict[str, object],
    approval_gate_input: ApprovalGateInput | None,
    now: str,
) -> None:
    """Attempt held sibling approvals after the origin's approval lock exits."""

    cli_id = changed_cli.get("cli_id")
    identity_hash = changed_cli.get("identity_hash")
    revision = changed_cli.get("revision")
    if (
        changed_cli.get("status") != "allowed"
        or not isinstance(cli_id, str)
        or not isinstance(identity_hash, str)
        or not isinstance(revision, int)
    ):
        return
    try:
        # A newer policy edit, particularly a Block, makes this receipt stale.
        # Never carry its sibling once-allows across that revision boundary.
        if store.read_local_cli_revision() != revision:
            changed_cli["siblings_skipped"] = "local_cli_revision_changed"
            return
        changed_cli["held_allowed_once"] = _allow_held_siblings(
            store,
            cli_id=cli_id,
            identity_hash=identity_hash,
            request_id=request_id,
            approval_gate_input=approval_gate_input,
            now=now,
        )
    except (ApprovalGateError, OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        # A failed sibling approval never rolls back the origin's resolution.
        _LOGGER.warning("Held calls on the changed CLI stay pending (%s)", type(error).__name__)


__all__ = ["finalize_reallow_siblings", "reallow_changed_cli"]
