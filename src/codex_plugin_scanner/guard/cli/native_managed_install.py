"""One managed install or uninstall, run by the native runtime under its own installation transaction.

The runtime takes the Guard home's locks (or runs as the owner this thread already holds), installs or removes
each harness, writes its managed-install row, installs or removes the agent safety guidance and journals every
mutation. This module only gathers the facts that live in this process and turns the answer into the rows and
exceptions its callers use.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ..harness.base import HarnessContext
from ..harness.native_harness import ask, describe
from ..harness.native_harness_steps import HookOwnershipError
from ..harness.native_install_facts import install_facts
from ..managed_install_revision import bump_managed_install_revision
from ..native_owned import owner_request
from ..native_runner_authority import NativeRunnerAuthorityError

# The longest one harness's install may run, as the slowest adapter bounds its own probes.
_PER_TARGET_SECONDS = 90.0
_OVERHEAD_SECONDS = 60.0


def _ownership_messages(harnesses: Sequence[str], op: str) -> dict[str, bool]:
    """The hook-ownership messages these harnesses name, each mapped to whether ``op`` is one of their ops."""
    messages: dict[str, bool] = {}
    for adapter in describe()["adapters"]:
        owned = adapter.get("hook_ownership") if isinstance(adapter, dict) else None
        if isinstance(owned, dict) and adapter.get("harness") in harnesses:
            messages[str(owned["message"])] = op in owned["ops"]
    return messages


def native_row(row: dict[str, Any]) -> dict[str, object]:
    """A store row the runtime answered, with its manifest decoded as the store read does."""
    manifest = row.get("manifest")
    if manifest is None:
        manifest = json.loads(str(row["manifest_json"]))
    return {
        "harness": str(row["harness"]),
        "active": bool(row["active"]),
        "workspace": row["workspace"],
        "manifest": manifest,
        "updated_at": str(row["updated_at"]),
    }


def ask_managed(
    op: str,
    context: HarnessContext,
    harnesses: Sequence[str],
    *,
    actor: str,
    **fields: object,
) -> dict[str, Any]:
    """One install op of the native runtime, naming a hook-ownership failure as the harness's spec words it."""
    request: dict[str, Any] = {
        **owner_request(context.guard_home, actor=actor),
        **install_facts(context, harnesses),
        **fields,
    }
    timeout = _PER_TARGET_SECONDS * max(1, len(harnesses)) + _OVERHEAD_SECONDS
    try:
        return ask(op, context, timeout_seconds=timeout, **request)
    except NativeRunnerAuthorityError as error:
        applicable = [message for message, applies in _ownership_messages(harnesses, op).items() if applies]
        if applicable:
            raise HookOwnershipError(applicable[0]) from error
        raise
    except RuntimeError as error:
        if str(error) in _ownership_messages(harnesses, op):
            raise HookOwnershipError(str(error)) from error
        raise
    finally:
        bump_managed_install_revision()


def native_managed_install(
    command: str,
    targets: Sequence[dict[str, object]],
    context: HarnessContext,
    *,
    workspace: str | None,
    now: str,
    source: str,
) -> tuple[list[dict[str, object]], object]:
    """Install or uninstall ``targets``; the recorded rows and the guidance the command changed."""
    harnesses = [str(target["harness"]) for target in targets]
    answer = ask_managed(
        "managed_install",
        context,
        harnesses,
        actor=f"managed.{command}",
        command=command,
        targets=list(targets),
        workspace=workspace,
        now=now,
        source=source,
    )
    rows = [native_row(row) for row in answer["rows"]]
    return rows, answer.get("guidance")
