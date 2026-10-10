"""Report native-runtime failures as runtime errors instead of usage errors."""

from __future__ import annotations

import argparse
import re
import sys

# The reason after the colon comes from the native transport and may carry
# brackets, commas and parentheses (for example "[pipe,2 attempt(s),...]").
_NATIVE_UNAVAILABLE_PATTERN = re.compile(r"native_[a-z0-9_]+_unavailable(?::[^\r\n]{1,1024})?")
_REPAIR_HINT_CODES = ("native_resident_runtime_identity_mismatch", "native_resident_update")


def report_native_unavailable(parser: argparse.ArgumentParser, exc: ValueError) -> int | None:
    """Print a native-runtime failure and return its exit code, or None for other errors.

    Argparse's ``parser.error`` prints the usage banner and reads like a bad
    command line, which hid a stale update marker behind every command.
    """

    message = str(exc)
    if _NATIVE_UNAVAILABLE_PATTERN.fullmatch(message) is None:
        return None
    print(f"{parser.prog}: error: {message}", file=sys.stderr)
    if any(code in message for code in _REPAIR_HINT_CODES):
        print(
            f"{parser.prog}: hint: run `hol-guard daemon repair` to recover an interrupted runtime update.",
            file=sys.stderr,
        )
    return 1


def guard_value_error_exit(parser: argparse.ArgumentParser, exc: ValueError) -> int:
    """Return the native-failure exit code, or fall back to the usage error."""

    native_exit = report_native_unavailable(parser, exc)
    if native_exit is None:
        parser.error(str(exc))
    return native_exit
