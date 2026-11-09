"""Guard library reads the native daemon composes ``GET`` replies from.

The native daemon owns each route, the caller check and the reply shape. A
call here returns only what still lives in the Guard library: the harness
setup inventory, the managed policy rows, and the Cloud review and Cloud
actions status. Calls that shape a whole reply return
``{"status": int, "body": {...}, "no_store": bool}``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..store import GuardStore


def harness_setup(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """The harness setup items, each with its version compatibility."""

    del args
    from ...version import __version__
    from ..adapters.base import HarnessContext
    from ..cli.install_commands import list_harness_setup_items
    from ..harness_version_api import attach_version_compatibility

    context = HarnessContext(home_dir=Path.home().resolve(), workspace_dir=None, guard_home=store.guard_home)
    items = list_harness_setup_items(context, store)
    return {"items": attach_version_compatibility(items, context), "package_version": __version__}


def managed_policy_rows(store: GuardStore, args: Mapping[str, Any]) -> list[dict[str, object]]:
    """The policy rows ``GET /v1/policy`` lists, annotated from managed state."""

    from ..daemon.managed_controls_api import managed_policy_rows as rows

    harness = args.get("harness")
    return rows(store, harness if isinstance(harness, str) else None)


def cloud_review_status(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    del args
    from ..daemon.cloud_review_settings import cloud_review_settings_status

    return {"status": 200, "body": cloud_review_settings_status(store), "no_store": True}


def cloud_actions_status(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    del args
    from ..daemon.cloud_actions_status import CloudActionsStatusUnavailableError, cloud_actions_local_status

    try:
        status = cloud_actions_local_status(store)
    except CloudActionsStatusUnavailableError:
        return {
            "status": 503,
            "body": {
                "error": "status_unavailable",
                "message": "Guard could not read the Cloud actions status on this computer.",
            },
            "no_store": True,
        }
    return {"status": 200, "body": status, "no_store": True}


READ_CALLS = {
    "read.harness_setup": harness_setup,
    "read.managed_policy_rows": managed_policy_rows,
    "read.cloud_review_status": cloud_review_status,
    "read.cloud_actions_status": cloud_actions_status,
}
