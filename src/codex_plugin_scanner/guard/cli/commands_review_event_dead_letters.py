"""CLI wiring for inspecting and replaying Review event dead letters."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from ..store import GuardStore


def _positive_sequence(value: str) -> int:
    sequence = int(value)
    if sequence < 1:
        raise argparse.ArgumentTypeError("dead-letter sequence must be positive")
    return sequence


def add_review_event_dead_letter_arguments(parser: argparse.ArgumentParser) -> None:
    """Add explicit, bounded dead-letter recovery controls."""

    parser.add_argument(
        "--retry-dead-letters",
        action="store_true",
        help="With dead-letters, return stored Review events to the durable outbox.",
    )
    parser.add_argument(
        "--dead-letter-sequence",
        action="append",
        type=_positive_sequence,
        help="With dead-letters and --retry-dead-letters, retry one stream sequence.",
    )


def review_event_dead_letter_usage_error(args: argparse.Namespace, connect_subcommand: object) -> str | None:
    """Reject recovery-only flags before ordinary connect can start OAuth."""

    retry = bool(getattr(args, "retry_dead_letters", False))
    sequences = getattr(args, "dead_letter_sequence", None)
    if connect_subcommand != "dead-letters" and (retry or sequences is not None):
        return "dead-letter options require `hol-guard connect dead-letters`"
    if sequences is not None and not retry:
        return "--dead-letter-sequence requires --retry-dead-letters"
    return None


def run_review_event_dead_letters_command(
    *,
    args: argparse.Namespace,
    store: GuardStore,
    emit: Callable[[str, dict[str, object], bool], None],
) -> int:
    """Inspect or explicitly replay durable permanently rejected events."""

    as_json = bool(getattr(args, "json", False))
    binding = store.get_live_request_oauth_binding()
    if binding is None:
        emit(
            "connect",
            {"status": "dead_letters_unavailable", "error": "A complete current Cloud binding is required."},
            as_json,
        )
        return 2
    delivery_binding = {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }
    if bool(getattr(args, "retry_dead_letters", False)):
        retried = store.retry_live_request_outbox_dead_letters(
            getattr(args, "dead_letter_sequence", None),
            oauth_subject_hash=delivery_binding["oauth_subject_hash"],
            workspace_id=delivery_binding["workspace_id"],
            machine_id=delivery_binding["machine_id"],
            machine_installation_id=delivery_binding["machine_installation_id"],
        )
        emit("connect", {"status": "dead_letters_retried", "retried_count": retried}, as_json)
        return 0
    emit(
        "connect",
        {
            "status": "dead_letters",
            "events": store.list_live_request_outbox_dead_letters(
                oauth_subject_hash=delivery_binding["oauth_subject_hash"],
                workspace_id=delivery_binding["workspace_id"],
                machine_id=delivery_binding["machine_id"],
                machine_installation_id=delivery_binding["machine_installation_id"],
            ),
        },
        as_json,
    )
    return 0


def run_review_event_reassign_command(
    *,
    args: argparse.Namespace,
    store: GuardStore,
    emit: Callable[[str, dict[str, object], bool], None],
) -> int:
    """Apply one explicit quarantined-event binding reassignment."""

    approved_source = getattr(args, "confirm_source", None)
    approved_workspace = getattr(args, "confirm_workspace", None)
    if not isinstance(approved_source, str) or not isinstance(approved_workspace, str):
        print(
            "reassign-quarantined requires --confirm-source and --confirm-workspace",
            file=sys.stderr,
        )
        return 2
    try:
        reassigned = store.reassign_quarantined_live_request_outbox(
            approved_source=approved_source,
            approved_workspace_id=approved_workspace,
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    emit(
        "connect",
        {
            "status": "reassigned",
            "source": store.guard_source,
            "workspace_id": approved_workspace,
            "reassigned_count": reassigned,
        },
        bool(getattr(args, "json", False)),
    )
    return 0
