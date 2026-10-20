"""The local CLI grant a contained workspace run is widened by.

The sink never trusts a grant it was handed. It asks this device's store when
it prepares the plan, admits only a plan widened by exactly that grant, and
asks again after the second receipt: a blocked CLI stops the run, and a grant
that changed in between, in any field, stops it too. Without a store, without
a bound resident answer, or when the store cannot be read, no grant is decided
and the run keeps the base sandbox, which is the narrowest one: a grant only
ever widens it. A grant that was decided and then cannot be confirmed again
stops the run.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING

from .contained_denial_note import denial_note, loopback_denied
from .restricted_pytest_model import PYTEST_INVALID_COMMAND_REASON_CODE, RestrictedPytestError
from .restricted_workspace_grants import ExpectedGrant

if TYPE_CHECKING:
    from ..local_cli_hook import ContainedGrant
    from ..store import GuardStore

GRANT_CHANGED = "The local CLI grant changed before launch."
GRANT_BLOCKED = "This device blocked the local CLI this command launches."
_WORKSPACE_REASON = "native_workspace_containment_required"
_STATE_CAPABILITIES = frozenset({"state-dir-read", "state-dir-write"})
# What a store that cannot answer raises: a store failure, a resident that is
# out of reach, or an expired operation deadline.
_STORE_UNANSWERED = (sqlite3.Error, ValueError, RuntimeError, OSError, TimeoutError)
_STORE: ContextVar[GuardStore | None] = ContextVar("restricted_workspace_grant_store", default=None)


@contextmanager
def grant_store(store: GuardStore) -> Iterator[None]:
    """Let contained runs inside this block look grants up in `store`."""
    token = _STORE.set(store)
    try:
        yield
    finally:
        _STORE.reset(token)


def decided_grant(command: str, *, workspace: Path, home: Path) -> ContainedGrant | None:
    """The grant the store decides for a sandbox-required `command` now."""
    store = _STORE.get()
    if store is None:
        return None
    from ..local_cli_hook import ALLOW_CONTAINED_WITH_GRANT, local_cli_contained_grant

    try:
        decision = local_cli_contained_grant(
            store,
            command=command,
            cwd=workspace,
            home_dir=home,
            current_action="sandbox-required",
            reason_code=_WORKSPACE_REASON,
        )
    except _STORE_UNANSWERED:
        return None
    if decision is None:
        return None
    # The route this lookup's caller is already inside; only the grant is read here.
    action, grant, _route = decision
    if action == "block":
        raise RestrictedPytestError("contained_test_authorization_failed", GRANT_BLOCKED)
    return grant if action == ALLOW_CONTAINED_WITH_GRANT else None


def granted_denial_note(grant: ContainedGrant | None) -> Callable[[Iterable[bytes]], str | None]:
    """The denial note, which also remembers a granted run's blocked loopback connection.

    The remembered cause lets Protect suggest local network access. It changes
    no grant and turns nothing on: only an admin preview and apply does that.
    """

    store = _STORE.get()
    if grant is None or store is None or "loopback-network" in grant.capabilities:
        return denial_note

    def note(outputs: Iterable[bytes]) -> str | None:
        outputs = list(outputs)
        chosen = denial_note(outputs)
        if chosen is not None and loopback_denied(outputs):
            # Best effort: the run's own result never depends on this write.
            with suppress(*_STORE_UNANSWERED):
                store.note_local_cli_capability_cause(
                    cli_id=grant.cli_id, identity_hash=grant.identity_hash, cause="connect_loopback"
                )
        return chosen

    return note


def expected_grant(grant: ContainedGrant, home: Path) -> ExpectedGrant:
    """What the plan must carry: the state directory is `<canonical home>/.<name>`."""
    state_dir = None
    if _STATE_CAPABILITIES.intersection(grant.capabilities):
        state_dir = str(home.resolve() / f".{grant.name}")
    return ExpectedGrant(grant.identity_hash, grant.capabilities, state_dir)


def require_unchanged(first: ContainedGrant | None, command: str, *, workspace: Path, home: Path) -> None:
    """Fail unless the store still decides `first` for the command.

    A run that decided no grant has nothing to lose when the store cannot
    answer again. One that decided a grant needs the store to confirm it.
    """
    try:
        now = decided_grant(command, workspace=workspace, home=home)
    except RestrictedPytestError:
        # Blocked since the plan was prepared.
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, GRANT_CHANGED) from None
    if now != first:
        raise RestrictedPytestError(PYTEST_INVALID_COMMAND_REASON_CODE, GRANT_CHANGED)


def link_state_dir(private_home: Path, plan: Mapping[str, object], expected: ExpectedGrant | None) -> None:
    """Make the CLI state directory reachable where the CLI looks for it.

    The run's `HOME` is the private home, so a link there to the one directory
    the grant opened lets the CLI find its saved state while the rest of the
    real home stays out of reach. Nothing is linked without a state capability
    in the plan, or for a directory that does not exist yet or is itself a link.
    """
    capabilities = plan.get("capabilities")
    if (
        expected is None
        or expected.state_dir is None
        or not isinstance(capabilities, list)
        or not _STATE_CAPABILITIES.intersection(capabilities)
    ):
        return
    state = Path(expected.state_dir)
    if state.is_symlink() or not state.is_dir():
        return
    (private_home / state.name).symlink_to(state, target_is_directory=True)
