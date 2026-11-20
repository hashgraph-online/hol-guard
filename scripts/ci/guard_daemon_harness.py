"""Re-exports the repository's ``ci/guard_daemon_harness.py``.

A script run from ``scripts/`` resolves ``ci`` to this package, which shadows
the repository's own ``ci`` package; this loads the harness by its path.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HARNESS = Path(__file__).resolve().parents[2] / "ci" / "guard_daemon_harness.py"
_spec = importlib.util.spec_from_file_location("_repo_ci_guard_daemon_harness", _HARNESS)
if _spec is None or _spec.loader is None:
    raise ImportError("The Guard daemon harness is missing.")
_module = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _module
_spec.loader.exec_module(_module)

GuardDaemonServer = _module.GuardDaemonServer

__all__ = ["GuardDaemonServer"]
