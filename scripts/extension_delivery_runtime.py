"""Bind a delivery script to the native runtime its workflow built from this checkout.

A source checkout has no packaged runtime to verify. The delivery workflow
builds `hol-guard-runtime` from the exact commit it publishes and names it in
`HOL_GUARD_NATIVE_BINARY`; the runtime then judges distribution roots and
provenance statements. Without that variable nothing is pinned, so a script
that needs the runtime fails closed instead of falling back to Python.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from codex_plugin_scanner.guard.catalog_delivery import lifecycle


@contextmanager
def pinned_runtime() -> Iterator[None]:
    named = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not named:
        yield
        return
    executable = Path(named).resolve(strict=True)
    if not executable.is_file():
        raise SystemExit("HOL_GUARD_NATIVE_BINARY must name the built hol-guard-runtime file")
    with lifecycle.pinned_session(executable):
        yield
