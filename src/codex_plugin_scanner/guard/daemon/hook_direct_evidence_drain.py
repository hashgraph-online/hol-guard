"""Record the evidence of hooks the resident answered without the daemon.

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
``hook_direct_counters`` for the daemon log and nowhere else.

The resident records a page's receipts, and the tool activity the binding let
it record, with its own evidence writer before the page leaves, and marks the
records it recorded, so this drain submits only what the resident left. A
store failure that writer reports rides on the page, and the daemon's writer
client recovers the store from it as it would from its own reply.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import Protocol, cast

from .hook_direct_counters import HookCounterLog
from .hook_policy_fence_window import record_direct_fence_wait

_DRAIN_SCHEMA = "guard-hook-direct-evidence.v1"
_DRAIN_INTERVAL_SECONDS = 0.25
_DRAIN_TIMEOUT_SECONDS = 2.0
# Pages per wake-up, so a backlog drains without starving shutdown.
_MAX_PAGES_PER_WAKE = 8
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


def record_direct_hook_evidence(host: _DrainHost, record: object) -> bool:
    """Record one drained answer the way the daemon records its own."""

    from ..cli.commands_support_command_activity import hook_post_succeeded
    from .hook_managed_install_state import _hook_harness_is_unmanaged
    from .hook_worker_native import _record_native_pre_activity
    from .mcp_relay_evidence_drain import is_mcp_relay_evidence, record_mcp_relay_evidence
    from .mcp_relay_package_evidence_drain import (
        is_mcp_relay_package_evidence,
        record_mcp_relay_package_evidence,
    )

    if is_mcp_relay_evidence(record):
        # A relayed MCP tool call, recorded as the proxy records it.
        return record_mcp_relay_evidence(host.store, host.guard_home, record)
    if is_mcp_relay_package_evidence(record):
        # The package lane's own receipt, against the package request's artifact.
        return record_mcp_relay_package_evidence(host.store, host.guard_home, record)
    if not isinstance(record, Mapping):
        return False
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
        return False
    if _hook_harness_is_unmanaged(host, harness):
        # The daemon passes an unmanaged harness through without recording.
        return True
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
            with suppress(Exception):
                submit(receipt=accepted)
        capture = getattr(getattr(host, "capture_writer", None), "submit_native_capture", None)
        if harness == "codex" and callable(capture) and record.get("capture_recorded") is not True:
            # The daemon hands a Codex receipt to the binding capture as well,
            # unless a current resident sealed it as the page left.
            with suppress(Exception):
                capture(guard_home=host.guard_home, payload=payload, receipt=accepted)
    if event == _USER_PROMPT_SUBMIT:
        # The daemon records no activity for a prompt it answers.
        return True
    # A current resident queues a tool call's activity behind the receipt itself.
    recorded = record.get("activity_recorded") is True
    if event == _POST_TOOL_USE:
        if not recorded:
            host._record_post_tool_activity(  # pyright: ignore[reportPrivateUsage]
                harness=harness,
                payload=payload,
                succeeded=hook_post_succeeded(_POST_TOOL_USE, payload),
            )
        return True
    if not recorded:
        _record_native_pre_activity(host, harness, payload, response, accepted)  # pyright: ignore[reportArgumentType]
    if record.get("connector_notice_raised") is not True:
        # A current resident raises the notice as the page leaves.
        with suppress(Exception):
            _raise_connector_setup_notice(host.store, record.get(_CONNECTOR_NOTICE_FIELD))
    return True


def _raise_connector_setup_notice(store: object, notice: object) -> None:
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
    from ..approvals import notify_connector_setup

    notify_connector_setup(store, queued, connector_name=connector_name)


def _decode_page(
    output: bytes | None,
    counters: HookCounterLog | None = None,
    on_store_fatal: Callable[[], object] | None = None,
) -> tuple[list[object], int, tuple[str, int] | None] | None:
    if not output:
        return None
    try:
        page = json.loads(output)
    except ValueError:
        return None
    if not isinstance(page, dict) or page.get("schema") != _DRAIN_SCHEMA:
        return None
    records = page.get("records")
    remaining = page.get("remaining")
    through = page.get("through")
    epoch = page.get("epoch")
    if not isinstance(records, list) or isinstance(remaining, bool) or not isinstance(remaining, int):
        return None
    if counters is not None and "counters" in page:
        # Diagnostics only; a page from an older resident has none.
        counters.observe_page(epoch, page.get("counters"))
    if on_store_fatal is not None and isinstance(page.get("store_fatal"), dict):
        with suppress(Exception):
            on_store_fatal()
    if through is None:
        return records, remaining, None
    if isinstance(through, bool) or not isinstance(through, int) or through < 1:
        return None
    # The cursor belongs to one resident; a restarted one numbers from one again.
    if not isinstance(epoch, str) or not epoch:
        return None
    return records, remaining, (epoch, through)


class DirectHookEvidenceDrain:
    """Pull direct-answer evidence from the resident on a short interval."""

    def __init__(
        self,
        host: _DrainHost,
        *,
        interval_seconds: float = _DRAIN_INTERVAL_SECONDS,
        transport: Callable[[], tuple[Path, Callable[..., bytes | None]] | None] | None = None,
    ) -> None:
        self._host = host
        self._interval_seconds = interval_seconds
        self._transport = transport or self._publisher_transport
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.recorded = 0
        self.rejected = 0
        self.failures = 0
        self._ack: tuple[str, int] | None = None
        counters = getattr(host, "hook_counters", None)
        self._counters = counters if isinstance(counters, HookCounterLog) else None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="hol-guard-direct-evidence", daemon=True)
        self._thread.start()

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        """Stop polling, then collect whatever the resident still holds."""

        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout_seconds))
        if thread is not None and thread.is_alive():
            return False
        self.drain_once()
        return True

    def drain_once(self) -> bool:
        """Drain up to a few pages; return whether more records remain."""

        try:
            return self._drain_pages()
        finally:
            # Every poll, so daemon receipts are logged even when no drain
            # transport is available.
            if self._counters is not None:
                with suppress(Exception):
                    self._counters.maybe_log()

    def _drain_pages(self) -> bool:
        for _ in range(_MAX_PAGES_PER_WAKE):
            page = self._fetch_page()
            if page is None:
                return False
            records, remaining, through = page
            if records and through is None:
                self.failures += 1
                return False
            for record in records:
                if record_direct_hook_evidence(self._host, record):
                    self.recorded += 1
                else:
                    self.rejected += 1
            if through is not None:
                self._ack = through
            # The resident leaves records it fully recorded off the page, so an
            # empty page whose cursor moved can still have work queued behind it.
            if remaining == 0 or through is None:
                return False
        return True

    def _fetch_page(self) -> tuple[list[object], int, tuple[str, int] | None] | None:
        from ..native_runtime import _isolated_environment

        transport = self._transport()
        if transport is None:
            return None
        executable, client = transport
        request: dict[str, object] = {"guard_home": str(self._host.guard_home)}
        if self._ack is not None:
            request["ack_epoch"], request["ack_through"] = self._ack
        payload = json.dumps(
            {
                "operation": "hook_direct_evidence_drain",
                # Without a budget the resident client falls back to 750 ms,
                # shorter than this request's own deadline.
                "deadline_budget_ms": int(_DRAIN_TIMEOUT_SECONDS * 1_000),
                "request": request,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            output = client(
                executable=executable,
                guard_home=self._host.guard_home,
                environment=_isolated_environment(),
                payload=payload,
                deadline_monotonic=time.monotonic() + _DRAIN_TIMEOUT_SECONDS,
            )
        except Exception:
            output = None
        page = _decode_page(output, self._counters, self._recover_writer_store)
        if page is None:
            self.failures += 1
        return page

    def _recover_writer_store(self) -> None:
        # A writer reply carries the failure, and the client recovers from it.
        stats = getattr(self._host.activity_writer, "stats", None)
        if callable(stats):
            _ = stats()

    def _publisher_transport(self) -> tuple[Path, Callable[..., bytes | None]] | None:
        transport = getattr(self._host.policy_snapshot_publisher, "direct_evidence_transport", None)
        if not callable(transport):
            return None
        return cast("tuple[Path, Callable[..., bytes | None]] | None", transport())

    def _run(self) -> None:
        while not self._stop.is_set():
            more = False
            with suppress(Exception):
                more = self.drain_once()
            if not more:
                self._stop.wait(self._interval_seconds)


__all__ = [
    "DirectHookEvidenceDrain",
    "record_direct_hook_evidence",
]
