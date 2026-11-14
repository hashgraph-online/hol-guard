"""The Pi-family extension the native ``harness_adapter`` kind renders for Pi and Oh My Pi."""

from __future__ import annotations

import json
from pathlib import Path

from .base import HarnessContext
from .native_harness import NativeHarnessAdapter, _text


def extension_source(
    harness: str, context: HarnessContext, *, variant: str = "active", config_path: Path | None = None
) -> str:
    """The Pi-family extension source this Guard renders for ``harness``."""
    from . import get_adapter

    adapter = get_adapter(harness)
    if not isinstance(adapter, NativeHarnessAdapter):
        raise ValueError(f"Unsupported harness: {harness}")
    answer = adapter._ask(
        "extension_source", context, variant=variant, config_path=None if config_path is None else str(config_path)
    )
    return _text(answer, "source")


def extension_is_current(harness: str, context: HarnessContext) -> bool:
    """Whether the managed Pi-family extension already matches this Guard."""
    from . import get_adapter

    adapter = get_adapter(harness)
    if not isinstance(adapter, NativeHarnessAdapter) or not adapter._spec.get("extension"):
        return False
    return adapter._ask("extension_current", context).get("current") is True


def legacy_omp_extension_is_verified(context: HarnessContext, pi_install: dict[str, object]) -> bool:
    """Whether Oh My Pi holds exactly the extension the former combined Pi install wrote."""
    from . import get_adapter

    adapter = get_adapter("pi")
    if not isinstance(adapter, NativeHarnessAdapter):
        return False
    answer = adapter._ask(
        "legacy_omp_verified", context, managed_install=json.loads(json.dumps(pi_install, default=lambda _: None))
    )
    return answer.get("verified") is True


__all__ = ["extension_is_current", "extension_source", "legacy_omp_extension_is_verified"]
