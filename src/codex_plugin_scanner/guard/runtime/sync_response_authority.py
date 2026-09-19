"""Keep response writes within the connection that authorized their request."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext

from ..native_policy_publication_lock import hold_policy_publication_mutation
from ..oauth_connection_authority import OAuthConnectionSnapshot
from ..store import GuardStore


@contextmanager
def hold_sync_response_authority(
    store: GuardStore, connection: OAuthConnectionSnapshot | None, *, policy: bool = False
) -> Iterator[None]:
    """Validate and commit locally; callers must keep transport and worker waits outside.

    Publication reservation precedes credential authority when policy can change,
    matching the native publisher's existing lock order. Legacy non-OAuth callers
    retain their existing behavior without inventing a connection snapshot.
    """
    with (
        hold_policy_publication_mutation(store.guard_home) if policy else nullcontext(),
        store.hold_oauth_credential_lock(),
    ):
        if connection is not None:
            store._require_oauth_connection_unlocked(connection)
        yield
