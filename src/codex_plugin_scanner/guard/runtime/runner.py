"""Guard wrapper-mode runtime execution."""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_harness, evaluate_detection
from ..models import HarnessDetection
from ..store import GuardStore

_APPROVAL_METADATA_KEYS = ("approval_center_url", "approval_requests", "approval_wait", "review_hint")


def guard_run(
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    dry_run: bool,
    passthrough_args: list[str],
    default_action: str | None = None,
    interactive_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
    blocked_resolver: Callable[[HarnessDetection, dict[str, Any]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate local harness state and optionally launch the harness."""

    detection = detect_harness(harness, context)
    if blocked_resolver is None:
        evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=True)
    else:
        evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=False)
        if not evaluation["blocked"]:
            evaluation = evaluate_detection(detection, store, config, default_action=default_action, persist=True)

    if not dry_run and interactive_resolver is not None and evaluation["blocked"]:
        evaluation = interactive_resolver(detection, evaluation)
    elif not dry_run and blocked_resolver is not None and evaluation["blocked"]:
        pending_evaluation = blocked_resolver(detection, evaluation)
        detection = detect_harness(harness, context)
        reevaluated = evaluate_detection(detection, store, config, default_action=default_action, persist=True)
        for key in _APPROVAL_METADATA_KEYS:
            if key in pending_evaluation:
                reevaluated[key] = pending_evaluation[key]
        evaluation = reevaluated
    if evaluation["blocked"] or dry_run:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        return evaluation

    adapter = get_adapter(harness)
    command = adapter.launch_command(context, passthrough_args)
    evaluation["launch_command"] = command
    environment = os.environ.copy()
    environment["HOME"] = str(context.home_dir)
    if os.name == "nt":
        environment["USERPROFILE"] = str(context.home_dir)
    try:
        result = subprocess.run(command, cwd=context.workspace_dir or Path.cwd(), check=False, env=environment)
    except FileNotFoundError as error:
        evaluation["launched"] = False
        evaluation["return_code"] = 127
        evaluation["launch_error"] = str(error)
        return evaluation
    evaluation["launched"] = True
    evaluation["return_code"] = result.returncode
    return evaluation


def sync_receipts(store: GuardStore) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    credentials = store.get_sync_credentials()
    if credentials is None:
        raise RuntimeError("Guard is not logged in.")
    receipts = store.list_receipts(limit=200)
    inventory = store.list_inventory()
    body = json.dumps({"receipts": receipts, "inventory": inventory}).encode("utf-8")
    request = urllib.request.Request(
        str(credentials["sync_url"]),
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {credentials['token']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    advisories = payload.get("advisories")
    advisories_stored = 0
    if isinstance(advisories, list):
        advisory_items = [item for item in advisories if isinstance(item, dict)]
        advisories_stored = store.cache_advisories(advisory_items, _now())
    return {
        "synced_at": payload.get("syncedAt"),
        "receipts_stored": payload.get("receiptsStored"),
        "advisories_stored": advisories_stored,
        "receipts": len(receipts),
        "inventory": len(inventory),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
