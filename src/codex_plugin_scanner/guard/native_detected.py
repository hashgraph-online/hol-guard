"""What every harness detects on this host, answered by the native runtime in one op."""

from __future__ import annotations

from typing import Any

from .harness_context import HarnessContext
from .models import HarnessDetection


def _ask_every_harness(op: str, context: HarnessContext) -> dict[str, Any]:
    """One op the runtime answers for every harness; this process supplies the Codex facts only it knows."""
    from .aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
    from .codex_harness_client import codex_native_request, raise_untrusted
    from .native_harness_client import ask, describe
    from .native_runner_authority import NativeRunnerAuthorityError

    count = sum(1 for adapter in describe()["adapters"] if isinstance(adapter, dict))
    fields: dict[str, Any] = codex_native_request(context)
    try:
        answer = ask(op, context, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS * count, **fields)
    except NativeRunnerAuthorityError as error:
        raise NativeAibomError(str(error)) from error
    if "untrusted" in answer:
        raise_untrusted(answer["untrusted"])
    return answer


def detected_harnesses(context: HarnessContext) -> list[str]:
    """The harnesses a detection finds installed, runnable or configured on this host.

    The runtime detects every harness and extends it with the shared workspace AIBOM artifacts.
    """
    return [str(harness) for harness in _ask_every_harness("detected_harnesses", context)["harnesses"]]


def detect_all(context: HarnessContext) -> list[HarnessDetection]:
    """Every harness's detection, in registry order, with the workspace AIBOM merged in by the runtime.

    Each harness is its own resident call with its own deadline and reply, so a slow host or a large
    skill inventory cannot push the whole batch past the resident call's time and size caps.
    """
    from .native_harness_client import describe
    from .native_harness_ops import detect

    return [
        detect(str(adapter["harness"]), context)
        for adapter in describe()["adapters"]
        if isinstance(adapter, dict) and isinstance(adapter.get("harness"), str)
    ]
