"""Read-only views of Paseo's state for tests: what the native runtime decides, never a second copy of it."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.adapters import get_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.native_harness import describe
from codex_plugin_scanner.guard.native_runner_authority import native_runner_authority

PASEO_NATIVE_HARNESSES = {
    "claude": "claude-code",
    "codex": "codex",
    "copilot": "copilot",
    "opencode": "opencode",
    "pi": "pi",
    "omp": "omp",
}


@dataclass(frozen=True)
class PaseoProvider:
    provider_id: str
    native_harness: str | None
    enabled: bool
    unsupported_reason: str | None


def paseo_config_path(context: HarnessContext) -> Path:
    return get_adapter("paseo").policy_path(context)


def receipt_path(context: HarnessContext) -> Path:
    identity = str(paseo_config_path(context).absolute())
    return context.guard_home / "managed" / "paseo" / f"{hashlib.sha256(identity.encode()).hexdigest()[:20]}.json"


def read_receipt(context: HarnessContext) -> dict[str, object]:
    return cast(dict[str, object], json.loads(receipt_path(context).read_text(encoding="utf-8")))


def paseo_providers(context: HarnessContext) -> tuple[PaseoProvider, ...]:
    prefixes = tuple(describe()["env_prefixes"])
    answer = native_runner_authority(
        "paseo_providers",
        {
            "config_path": str(paseo_config_path(context)),
            "xdg_default": str(context.home_dir / ".config"),
            "environ": {key: value for key, value in os.environ.items() if value and key.upper().startswith(prefixes)},
        },
    )
    error = answer.get("error")
    if isinstance(error, str):
        raise ValueError(error)
    rows = cast(list[dict[str, object]], answer["providers"])
    return tuple(
        PaseoProvider(
            cast(str, row["provider"]),
            cast("str | None", row.get("native_harness")),
            cast(bool, row["enabled"]),
            cast("str | None", row.get("unsupported_reason")),
        )
        for row in rows
    )
