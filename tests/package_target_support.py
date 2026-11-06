"""Package intent targets recorded from the former Python target builders.

The resident now owns target derivation; these exact values let tests build a
``PackageIntent`` without a resident round trip.
"""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.package_intent_common import PackageIntentTarget

_RECORDED = json.loads(
    (Path(__file__).parent / "fixtures" / "supply-chain-eval" / "package_targets.v1.json").read_text(encoding="utf-8")
)


def recorded_target(ecosystem: str, spec: str) -> PackageIntentTarget:
    fields = dict(_RECORDED[f"{ecosystem}|{spec}"])
    fields["extras"] = tuple(fields["extras"])
    return PackageIntentTarget(**fields)
