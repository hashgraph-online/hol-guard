"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .local_cli_grant_decision import GRANT_REFINABLE_ACTIONS, decide_local_cli_grant
from .local_mcp_grant_decision import decide_local_mcp_grant
from .models import GuardAction, GuardArtifact
from .native_local_cli_identity import LocalCliIdentityUnavailableError, track_local_cli_identity_failures
from .runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from .runtime.package_json_scripts import identify_package_json_scripts

LocalCliGrantState = Literal["allowed", "blocked"]


def matching_local_cli_grant(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> tuple[UnlistedCliIdentity, LocalCliGrantState] | None:
    """Return an enrolled grant when the command matches an unlisted CLI identity.

    Raises ``LocalCliIdentityUnavailableError`` when the identity could not be
    derived, so callers can fail closed instead of treating it as no grant.
    """

    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    with track_local_cli_identity_failures() as failures:
        identity = identify_package_json_scripts(command, cwd=cwd, home_dir=home_dir)
        if identity is None:
            identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    # A failed script derivation can fall through to the binary's identity.
    if failures:
        raise LocalCliIdentityUnavailableError(failures[0])
    if identity is None:
        return None
    # The resident reads the grant rows and decides; this raises
    # ``LocalCliIdentityUnavailableError`` when it gives no answer.
    outcome = decide_local_cli_grant(
        store=store,
        identity=identity,
        command=command,
        cwd=cwd,
        home_dir=home_dir,
        current_action=current_action,
    )
    return None if outcome is None else (identity, outcome)


def apply_local_mcp_extension_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    try:
        matched = matching_local_mcp_grant(
            store=store,
            artifact=artifact,
            current_action=current_action,
        )
    except LocalCliIdentityUnavailableError:
        return _hold_unverified_mcp_decision(store, artifact, current_action)
    if matched == "blocked":
        return (
            "block",
            "local-mcp-extension",
            "This MCP tool is blocked by a custom extension on this device.",
        )
    if matched == "allowed":
        return (
            "allow",
            "local-mcp-extension",
            "This MCP tool is allowed by a custom extension on this device.",
        )
    if matched == "review":
        return (
            "review",
            "local-mcp-extension",
            "This tool is not in the reviewed catalog. Review its authority before execution.",
        )
    return _contributed_mcp_decision(store, artifact, current_action)


def _contributed_mcp_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    """Return the resident's contributed decision.

    The resident owns it. With no answer, an allowed or reviewed call is held in
    review rather than guessed at or allowed.
    """

    from .runtime.mcp_server_grants import apply_contributed_mcp_decision

    try:
        contributed = apply_contributed_mcp_decision(store, artifact, current_action)
        if contributed is not None:
            return contributed
        if current_action == "review":
            reasserted = apply_contributed_mcp_decision(store, artifact, "allow")
            if reasserted is not None and reasserted[0] == "review":
                return reasserted
    except LocalCliIdentityUnavailableError:
        return _hold_unverified_contributed_decision(current_action)
    return None


def _hold_unverified_contributed_decision(
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    # A review is held too: with no decisive answer, a time-bounded approval
    # could upgrade it to allow past a catalog block that was not checked.
    # Stricter actions are left alone: replacing them with review would loosen them.
    if current_action not in {"allow", "warn", "review"}:
        return None
    return (
        "review",
        "catalog-mcp-extension",
        "This device's catalog MCP defaults could not be verified. Review this tool call before execution.",
    )


def _hold_unverified_mcp_decision(
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> tuple[GuardAction, str, str] | None:
    """The resident gave no grant answer: hold an allow for review while grants exist.

    Unlike CLI grants, MCP grants also produce review-only outcomes (per-tool
    review, unseen tools under an enrolled server, changed tool authority), and
    each needs a grant row. Any row therefore holds an otherwise allowed call,
    and a call already under review stays decisively in review so a temporary
    approval cannot upgrade it past a stored block.
    """

    contributed = _contributed_mcp_decision(store, artifact, current_action)
    if contributed is not None and contributed[0] in {"block", "review"}:
        return contributed
    effective = contributed[0] if contributed is not None else current_action
    # A review is held too: with no decisive answer, the caller would let a
    # time-bounded approval upgrade it to allow past a stored device block.
    if effective in {"allow", "warn", "review"} and _may_hold_mcp_grants(store):
        return (
            "review",
            "local-mcp-extension",
            "This device's MCP grants could not be verified. Review this tool call before execution.",
        )
    return contributed


def _may_hold_mcp_grants(store: object) -> bool:
    probe = getattr(store, "has_local_cli_grant_rules", None)
    if not callable(probe):
        return True
    try:
        return bool(probe())
    except Exception:
        return True


def matching_local_mcp_grant(
    *,
    store: object,
    artifact: GuardArtifact,
    current_action: GuardAction,
) -> LocalCliGrantState | Literal["review"] | None:
    """Return a this-device MCP extension grant for a live tools/call.

    The resident decides. Raises ``LocalCliIdentityUnavailableError`` when it
    gives no answer, so callers can fail closed instead of treating it as no
    grant.
    """

    if current_action not in GRANT_REFINABLE_ACTIONS:
        return None
    return decide_local_mcp_grant(store=store, artifact=artifact, current_action=current_action)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
