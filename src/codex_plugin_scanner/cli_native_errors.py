"""Report native-runtime failures as runtime errors instead of usage errors."""

from __future__ import annotations

import argparse
import re
import sys
import sysconfig

# The reason after the colon comes from the native transport and may carry
# brackets, commas and parentheses (for example "[pipe,2 attempt(s),...]").
_NATIVE_UNAVAILABLE_PATTERN = re.compile(r"native_[a-z0-9_]+_unavailable(?::[^\r\n]{1,1024})?")
_REPAIR_HINT_CODES = ("native_resident_runtime_identity_mismatch", "native_resident_update")


def _missing_runtime_hint() -> str | None:
    """Render installation guidance using the updater's existing wheel inventory."""

    from .guard.cli.update_native_wheel import bundled_native_runtime_missing, native_platform_supported

    if not bundled_native_runtime_missing():
        return None
    if native_platform_supported():
        return (
            "The bundled native runtime is missing. Run `hol-guard update` to repair this installation. "
            "If repair cannot recover it, install the matching native wheel for this Guard version "
            "from https://github.com/hashgraph-online/hol-guard/releases into the same Python environment and retry."
        )
    return (
        f"No published HOL Guard native wheel matches this Python platform ({sysconfig.get_platform()}). "
        "The universal Python wheel cannot provide protection on its own. "
        "See https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/get-started.md#platform-support "
        "for the supported installation paths."
    )


def report_native_unavailable(
    parser: argparse.ArgumentParser, exc: ValueError, *, error_prefix: str | None = None
) -> int | None:
    """Print a native-runtime failure and return its exit code, or None for other errors.

    Argparse's ``parser.error`` prints the usage banner and reads like a bad
    command line, which hid a stale update marker behind every command.
    Callers with an existing error-line contract can retain its prefix.
    """

    message = str(exc)
    if _NATIVE_UNAVAILABLE_PATTERN.fullmatch(message) is None:
        return None
    prefix = error_prefix if error_prefix is not None else f"{parser.prog}: error"
    print(f"{prefix}: {message}", file=sys.stderr)
    if message == "native_guard_config_unavailable" and (hint := _missing_runtime_hint()) is not None:
        print(f"{parser.prog}: hint: {hint}", file=sys.stderr)
    if any(code in message for code in _REPAIR_HINT_CODES):
        print(
            f"{parser.prog}: hint: run `hol-guard daemon repair` to recover an interrupted runtime update.",
            file=sys.stderr,
        )
    return 1


def report_review_contract_rejection(parser: argparse.ArgumentParser, exc: ValueError) -> int | None:
    """Print a refused Guard Cloud signature as a runtime error, or None for other errors.

    A key Guard cannot anchor stops `connect` and `sync` after sign-in. The
    usage banner made that look like a mistyped command.
    """

    from .guard.review_oauth_binding import GuardReviewContractError

    if not isinstance(exc, GuardReviewContractError):
        return None
    print(f"{parser.prog}: error: {exc}", file=sys.stderr)
    print(
        f"{parser.prog}: hint: Guard Cloud sent signed data this install could not verify, so Guard did not "
        "trust it and stopped the sync. Run `hol-guard update`, then `hol-guard sync`.",
        file=sys.stderr,
    )
    return 1


def guard_value_error_exit(parser: argparse.ArgumentParser, exc: ValueError) -> int:
    """Return the runtime-failure exit code, or fall back to the usage error."""

    runtime_exit = report_native_unavailable(parser, exc)
    if runtime_exit is None:
        runtime_exit = report_review_contract_rejection(parser, exc)
    if runtime_exit is None:
        parser.error(str(exc))
    return runtime_exit
