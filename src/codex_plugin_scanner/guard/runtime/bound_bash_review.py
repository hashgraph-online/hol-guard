"""Queue exact native consent only from the actual execution sink."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..native_bash_protocol import NativeBashError

if TYPE_CHECKING:
    from ..store import GuardStore


def queue_bound_bash_review(
    prepared: dict[str, object],
    payload: dict[str, object],
    *,
    store: GuardStore,
    harness: str,
    workspace: Path,
    home: Path,
    errors: TextIO,
) -> None:
    from ..daemon.hook_native_review_approval import queue_native_pre_tool_review
    from ..native_decision_receipt import edge_receipt

    review = prepared["review"]
    if not isinstance(review, dict) or not isinstance(review.get("decision"), dict):
        raise NativeBashError("native_bash_review_evidence_invalid")
    decision = review["decision"]
    receipt = edge_receipt(harness, decision, review.get("receipt"), guard_home=Path(store.guard_home))
    if receipt is None:
        raise NativeBashError("native_bash_review_evidence_invalid")
    queued = queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=decision,
        native_receipt=receipt,
        workspace=workspace,
        guard_home=Path(store.guard_home),
        home_dir=home,
        exact_token=str(prepared["artifact_hash"]),
        review_binding=str(prepared["artifact_hash"]),
        bound_bash=prepared,
        silent=True,
    )
    if queued is None:
        raise NativeBashError("native_bash_review_queue_unavailable")
    url = queued.get("approval_url")
    if not isinstance(url, str) or not url:
        raise NativeBashError("native_bash_review_queue_unavailable")
    print(f"HOL Guard requires consent for this exact script invocation: {url}", file=errors)
