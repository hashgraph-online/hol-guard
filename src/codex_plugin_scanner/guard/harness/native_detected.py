"""Which harnesses ``--all`` targets, answered by the native runtime in one op."""

from __future__ import annotations

from typing import Any

from .base import HarnessContext


def detected_harnesses(context: HarnessContext) -> list[str]:
    """The harnesses a detection finds installed, runnable or configured on this host.

    The runtime detects every harness and extends it with the shared workspace AIBOM artifacts; this process
    supplies the Codex facts only it knows.
    """
    from ..aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
    from ..codex_harness_client import codex_native_request, raise_untrusted
    from ..native_runner_authority import NativeRunnerAuthorityError
    from .native_harness import ask, describe

    harnesses = [str(adapter.get("harness")) for adapter in describe()["adapters"] if isinstance(adapter, dict)]
    fields: dict[str, Any] = codex_native_request(context)
    try:
        answer = ask(
            "detected_harnesses",
            context,
            timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS * len(harnesses),
            **fields,
        )
    except NativeRunnerAuthorityError as error:
        raise NativeAibomError(str(error)) from error
    if "untrusted" in answer:
        raise_untrusted(answer["untrusted"])
    return [str(harness) for harness in answer["harnesses"]]
