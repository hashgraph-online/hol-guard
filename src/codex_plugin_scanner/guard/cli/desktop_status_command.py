"""Read-only Desktop status entrypoint, before normal store initialization."""

from __future__ import annotations

import sqlite3
import sys
from typing import TYPE_CHECKING

from ..config import GuardConfig
from .commands_dispatch_desktop import _run_guard_desktop_command
from .desktop_status_store import DesktopStatusStore

if TYPE_CHECKING:
    import argparse
    from pathlib import Path
    from typing import TextIO

    from ..adapters.base import HarnessContext


def run_desktop_status_command(
    args: argparse.Namespace,
    *,
    guard_home: Path,
    context: HarnessContext,
    output_stream: TextIO | None = None,
) -> int:
    store = None
    try:
        store = DesktopStatusStore(guard_home, source=getattr(args, "source", "default"))
        # Desktop's projection consumes runtime/harness/Cloud observations only;
        # product config fields are not included in this contract.
        config = GuardConfig(guard_home=guard_home, workspace=context.workspace_dir)
        return _run_guard_desktop_command(
            args,
            guard_home=guard_home,
            context=context,
            store=store,
            config=config,
            output_stream=output_stream,
        )
    except (OSError, sqlite3.DatabaseError, ValueError):
        print("Guard status could not be read. Open Guard to check local setup or repair it.", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()
