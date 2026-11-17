"""Retain the command mutation lease through native review and local reuse."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path

from ..native_command_control_authority_io import (
    NativeCommandControlAuthorityUnavailableError,
    hold_command_control_authority_lock,
)

# The lease only keeps a control mutation from committing while the review
# runs, so it is not worth the review's own budget. Every acquirer takes the
# authority turnstile exclusively and a writer holds it for the whole of its
# wait, so an uncapped wait here spends the hook's entire deadline and leaves
# the native evaluator none: the evaluator then reports an expired deadline and
# the command is held for approval. Wait a short moment for the lease, then
# review without it.
LEASE_WAIT_SECONDS = 0.25

# The only marker phase that describes a control state the rows have settled
# into. A mutation writes the next revision as ``closed`` before it commits its
# rows, so anything else is a state still being written.
COMMITTED_PHASE = "committed"


def _reader(publisher: object, name: str) -> Callable[[], object] | None:
    """Bind one of the publisher's own readers, which this module only duck-types."""

    reader = getattr(publisher, name, None)
    return reader if callable(reader) else None


def published_binding_token(publisher: object) -> tuple[object, ...] | None:
    """Read the *committed* control state, not the cached publisher snapshot.

    Another process can commit a control mutation while this process's
    in-memory generation is unchanged, so the cached snapshot binding alone
    cannot show that the policy under review was replaced. The committed
    control marker moves on every projection the mutation lease protects, and
    the retained business source and the local-CLI revision cover the writers
    that commit without publishing one.

    Each of the three is a small read that takes no lease. Compiling the
    control projection here instead would re-enter the authority lock this
    fence exists to stay out of, and would spend the budget the review still
    needs; an absent marker is a definite state and compares as one. None is
    returned when the committed state could not be read at all, or when the
    marker that was read is mid-mutation, and an unleased review then fails
    closed rather than reading an unknown as unchanged.
    """

    authority = _reader(publisher, "_committed_control_authority")
    business = _reader(publisher, "_compiled_business_source")
    revision = _reader(publisher, "_current_local_cli_revision")
    if authority is None or business is None or revision is None:
        return None
    try:
        marker = authority() or {}
        source = business()
        cli_revision = revision()
        identity = b"" if source is None else getattr(source, "retained_identity_bytes", None)
        if not isinstance(marker, Mapping) or not isinstance(identity, bytes):
            return None
        if marker and marker.get("phase") != COMMITTED_PHASE:
            # A control mutation freezes the marker at the next revision with
            # phase ``closed`` while it still holds the lease, and only commits
            # its control rows afterwards. The unleased review runs precisely
            # because a writer holds that lease, so both of its reads can land
            # inside that one frozen window and match while the rows change
            # between them. A marker mid-mutation is not a state a review can be
            # bound to; refuse it, and the caller fails closed. An absent marker
            # is a home with no control authority at all - a fresh install -
            # which is a definite state and stays comparable, so ordinary work
            # there is not turned into an approval.
            return None
        return (
            marker.get("epoch"),
            marker.get("mutation_revision"),
            marker.get("phase"),
            marker.get("effective_digest"),
            marker.get("authority_key_id"),
            marker.get("pack_program_digest"),
            identity,
            cli_revision,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, IndexError):
        return None


@contextmanager
def native_review_fence(
    *,
    policy_snapshot: Mapping[str, object] | None,
    event_name: str,
    recording_only: bool,
    guard_home: Path,
    deadline: float | None,
) -> Iterator[bool | None]:
    """Yield True while the lease is held, False when it does not apply.

    None means the lease was wanted and was not free within its short wait.
    The review still runs, on the snapshot that was bound before this fence,
    and the caller compares committed control state across it. An external
    mutation can leave the publisher's cached generation unchanged, so the
    comparison must read the durable source. An unavailable reading fails
    closed; the read does not grant permission to an uncertain response.
    """

    bound = policy_snapshot is not None and (
        policy_snapshot.get("command_extensions_bound") is True
        or isinstance(policy_snapshot.get("command_extensions"), Mapping)
    )
    if not bound or event_name not in {"PreToolUse", "UserPromptSubmit"} or recording_only:
        yield False
        return
    # A missing deadline grants no lock wait at all. Normal HTTP callers supply
    # their original absolute deadline; it is never reset here.
    remaining = 0.0 if deadline is None else max(0.0, deadline - time.monotonic())
    with ExitStack() as resources:
        try:
            resources.enter_context(
                hold_command_control_authority_lock(
                    guard_home, timeout_seconds=min(LEASE_WAIT_SECONDS, remaining), shared=True
                )
            )
        except NativeCommandControlAuthorityUnavailableError:
            # Refusing this hook would turn an ordinary command issued during a
            # publication into an approval row, and would add no protection:
            # the review still runs, and still denies. It needs budget to run,
            # so a hook that is already out of time is still refused here. A
            # hook that carries no deadline is not out of time: it took no
            # lease wait, and what makes an unleased review safe is the
            # caller's comparison of committed control state across it, not
            # the clock.
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("native_review_fence_deadline") from None
            yield None
            return
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("native_review_fence_deadline")
        yield True
