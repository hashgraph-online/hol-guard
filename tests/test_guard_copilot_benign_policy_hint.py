"""Trust-boundary regressions for Copilot generic hook policy hints."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardAction

_IGNORED_BENIGN_HINT_REASON = "untrusted_hook_payload_hint_ignored_guard_verified_benign"
_BENIGN_COMMAND = (
    f"cd /tmp && {shlex.quote(sys.executable)} - <<'PY'\n"
    "from pathlib import Path\n"
    "text = Path('bounty_submissions.txt').read_text()\n"
    "print('bytes', len(text))\n"
    "print('rows', text.count('data-testid=\"portal-grid-row\"'))\n"
    "PY"
)


def _copilot_payload(
    *,
    command: str = _BENIGN_COMMAND,
    policy_action: GuardAction = "block",
) -> dict[str, object]:
    return {
        "hook_name": "preToolUse",
        "tool_name": "bash",
        "tool_input": {"command": command},
        "policy_action": policy_action,
        "source_scope": "project",
    }


def _receipt_evidence(receipt: dict[str, object], source: str) -> dict[str, object]:
    evidence = receipt["scanner_evidence"]
    assert isinstance(evidence, list)
    for raw_item in cast(list[object], evidence):
        if not isinstance(raw_item, dict):
            continue
        item = cast(dict[str, object], raw_item)
        if item.get("source") == source:
            return item
    raise AssertionError(f"missing {source!r} scanner evidence")


def _guard_config(
    tmp_path: Path,
    workspace: Path,
    *,
    default_action: GuardAction = "warn",
) -> GuardConfig:
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=workspace,
        default_action=default_action,
    )
