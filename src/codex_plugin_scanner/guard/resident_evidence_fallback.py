"""Handle evidence records the resident explicitly leaves to the daemon.

A direct answer skips the daemon's post-allow recording. The resident queues
the inputs that recording needs, and this drain pulls them over the resident
channel and records them exactly as the daemon path does. After a
``PreToolUse`` allow that is the decision receipt, the binding capture, and
the command activity, plus the desktop setup notice for a connector-setup
review the resident queued; the resident records the command-line observation
itself. After a reviewed ``PostToolUse`` it is the receipt, the binding
capture, and the post-tool command activity; after a ``UserPromptSubmit`` it is the receipt and the
binding capture alone. A tool call the native MCP relay decided is recorded
by ``mcp_relay_evidence_drain`` as the proxy records it, unless the resident
wrote its receipt itself, and one its package
lane answered by ``mcp_relay_package_evidence_drain``. The publisher advertises the drain in the
direct-lane binding only while it runs, so a resident never answers directly
for a daemon that would leave the evidence behind. A page from a current
resident also carries its diagnostic hook counts, which go to
the resident route counters for the daemon log and nowhere else.

The resident records a page's receipts, and the tool activity the binding let
it record, with its own evidence writer before the page leaves, and marks the
records it recorded, so this drain submits only what the resident left. A
store failure that writer reports rides on the page, and the daemon's writer
client recovers the store from it as it would from its own reply.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Literal, Protocol

from .hook_review.hook_policy_fence_window import record_direct_fence_wait

_DIRECT_HARNESSES = frozenset(
    {
        "codex",
        "claude-code",
        "cursor",
        "copilot",
        "kimi",
        "devin",
        "zcode",
        "openclaw",
        "hermes",
        "cline",
        "opencode",
        "grok",
        "pi",
        "omp",
        "muse",
    }
)
_PRE_TOOL_USE = "PreToolUse"
_POST_TOOL_USE = "PostToolUse"
_USER_PROMPT_SUBMIT = "UserPromptSubmit"
# The desktop notice for a connector-setup review the resident queued.
_CONNECTOR_NOTICE_FIELD = "connector_setup_notice"
_CAPTURE_MARKER = ("diagnostics", "codex-binding-capture.v2.json")
_MCP_RETRY_ATTEMPTS: dict[str, int] = {}


class _DrainHost(Protocol):
    @property
    def store(self) -> object: ...
    @property
    def guard_home(self) -> Path: ...
    @property
    def activity_writer(self) -> object | None: ...
    @property
    def policy_snapshot_publisher(self) -> object: ...
    def _record_post_tool_activity(self, *, harness: str, payload: Mapping[str, object], succeeded: bool) -> None: ...


FallbackResult = Literal["handled", "drop", "retry"]


def record_resident_evidence_fallback(host: _DrainHost, record: object) -> FallbackResult:
    """Record one drained answer the way the daemon records its own."""

    from .cli.commands_support_command_activity import hook_post_succeeded
    from .evidence_drains.mcp_relay_evidence_drain import is_mcp_relay_evidence, record_mcp_relay_evidence
    from .evidence_drains.mcp_relay_package_evidence_drain import (
        is_mcp_relay_package_evidence,
        record_mcp_relay_package_evidence,
    )
    from .hook_review.hook_managed_install_state import _hook_harness_is_unmanaged

    if is_mcp_relay_evidence(record):
        # A relayed MCP tool call, recorded as the proxy records it.
        return _record_mcp_with_one_retry(
            record, lambda: record_mcp_relay_evidence(host.store, host.guard_home, record)
        )
    if is_mcp_relay_package_evidence(record):
        # The package lane's own receipt, against the package request's artifact.
        return _record_mcp_with_one_retry(
            record, lambda: record_mcp_relay_package_evidence(host.store, host.guard_home, record)
        )
    if not isinstance(record, Mapping):
        return "drop"
    harness = record.get("harness")
    payload = record.get("payload")
    workspace = record.get("workspace")
    home_dir = record.get("home_dir")
    response = record.get("harness_response")
    receipt = record.get("receipt")
    # A record without an event predates the post-tool lane, which answered only `PreToolUse`.
    event = record.get("event", _PRE_TOOL_USE)
    if (
        event not in (_PRE_TOOL_USE, _POST_TOOL_USE, _USER_PROMPT_SUBMIT)
        or not isinstance(harness, str)
        or harness not in _DIRECT_HARNESSES
        or not isinstance(payload, dict)
        or not isinstance(workspace, str)
        or not isinstance(home_dir, str)
        or not isinstance(response, dict)
    ):
        return "drop"
    if _hook_harness_is_unmanaged(host, harness):
        # The daemon passes an unmanaged harness through without recording.
        return "handled"
    # A hook the resident held through a policy update's fence reports its wait,
    # unless a current resident recorded it with the receipt.
    if record.get("fence_wait_recorded") is not True:
        record_direct_fence_wait(host.store, record.get("fence_wait_ms"))
    # Activity may cite only a receipt the store will accept, which the resident checks on its page.
    checked = record.get("receipt_valid") is True
    accepted = dict(receipt) if checked and isinstance(receipt, dict) else None
    if accepted is not None:
        submit = getattr(host.activity_writer, "submit_native_decision_receipt", None)
        # A current resident queues the receipt with a running writer itself.
        if callable(submit) and record.get("receipt_recorded") is not True:
            try:
                if submit(receipt=accepted) is False:
                    return "retry"
            except Exception:
                return "retry"
        capture = getattr(getattr(host, "capture_writer", None), "submit_native_capture", None)
        capture_required = host.guard_home.joinpath(*_CAPTURE_MARKER).is_file()
        if harness == "codex" and capture_required and callable(capture) and record.get("capture_recorded") is not True:
            # The daemon hands a Codex receipt to the binding capture as well,
            # unless a current resident sealed it as the page left.
            # Capture is diagnostics-only and intentionally best effort. A
            # dropped capture must not replay a receipt that was already queued.
            with suppress(Exception):
                capture(guard_home=host.guard_home, payload=payload, receipt=accepted)
    if event == _USER_PROMPT_SUBMIT:
        # The daemon records no activity for a prompt it answers.
        return "handled"
    # A current resident queues a tool call's activity behind the receipt itself.
    recorded = record.get("activity_recorded") is True
    if event == _POST_TOOL_USE:
        if not recorded and not _submit_fallback_activity(
            host,
            harness=harness,
            event=_POST_TOOL_USE,
            payload=payload,
            succeeded=hook_post_succeeded(_POST_TOOL_USE, payload),
            discovery=True,
        ):
            return "retry"
        return "handled"
    if not recorded and not _submit_fallback_activity(
        host,
        harness=harness,
        event=_PRE_TOOL_USE,
        payload=payload,
        succeeded=True,
        policy_action=response.get("policy_action"),
        receipt_id=accepted.get("decision_id") if accepted is not None else None,
        prompted=response.get("prompted") is True,
        approval_reuse_status=response.get("approval_reuse_status", "not-applicable"),
    ):
        return "retry"
    if record.get("connector_notice_raised") is not True:
        # A current resident raises the notice as the page leaves.
        with suppress(Exception):
            _raise_fallback_connector_setup_notice(host.store, record.get(_CONNECTOR_NOTICE_FIELD))
    return "handled"


def _submit_fallback_activity(
    host: _DrainHost,
    *,
    harness: str,
    event: str,
    payload: Mapping[str, object],
    succeeded: bool,
    policy_action: object = None,
    receipt_id: object = None,
    prompted: bool = False,
    approval_reuse_status: object = "not-applicable",
    discovery: bool = False,
) -> bool:
    """Submit fallback activity synchronously on the drain thread."""

    submit = getattr(host.activity_writer, "submit_command_activity", None)
    if not callable(submit):
        return True
    try:
        if discovery:
            discover = getattr(host.activity_writer, "submit_composio_discovery", None)
            if callable(discover):
                # A false discovery result means no Composio action was
                # applicable for this ordinary hook. Command activity still
                # has to be submitted independently.
                with suppress(Exception):
                    discover(harness=harness, payload=payload, succeeded=succeeded)
        return (
            submit(
                harness=harness,
                event=event,
                payload=payload,
                succeeded=succeeded,
                policy_action=policy_action if isinstance(policy_action, str) else None,
                receipt_id=receipt_id if isinstance(receipt_id, str) else None,
                prompted=prompted,
                approval_reuse_status=(
                    approval_reuse_status if isinstance(approval_reuse_status, str) else "not-applicable"
                ),
            )
            is not False
        )
    except Exception:
        return False


def _raise_fallback_connector_setup_notice(store: object, notice: object) -> None:
    """The desktop notice for a connector-setup review the resident queued.

    The resident names the stored row and the CLI; the notice is raised from
    the stored row, as ``raise_connector_setup_notice`` raises it.
    """

    if not isinstance(notice, Mapping):
        return
    request_id = notice.get("request_id")
    connector_name = notice.get("connector_name")
    if not isinstance(request_id, str) or not request_id or not isinstance(connector_name, str) or not connector_name:
        return
    lookup = getattr(store, "get_approval_request", None)
    if not callable(lookup):
        return
    queued = lookup(request_id)
    if not isinstance(queued, dict):
        return
    from .approvals import notify_connector_setup

    notify_connector_setup(store, queued, connector_name=connector_name)


def _record_mcp_with_one_retry(record: object, write: Callable[[], object]) -> FallbackResult:
    """Retry one failed MCP write before dropping the bounded record."""

    try:
        key = json.dumps(record, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "drop"
    attempt = _MCP_RETRY_ATTEMPTS.get(key, 0) + 1
    if attempt > 4:
        _MCP_RETRY_ATTEMPTS.pop(key, None)
        return "drop"
    try:
        result = write()
    except Exception:
        result = False
    committed = getattr(result, "committed", False) is True
    if bool(result):
        _MCP_RETRY_ATTEMPTS.pop(key, None)
        return "handled"
    if committed:
        _MCP_RETRY_ATTEMPTS.pop(key, None)
        return "drop"
    if len(_MCP_RETRY_ATTEMPTS) >= 1024:
        _MCP_RETRY_ATTEMPTS.clear()
    _MCP_RETRY_ATTEMPTS[key] = attempt
    return "retry"
