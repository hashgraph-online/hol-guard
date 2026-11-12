"""Import build-time delivery helpers from scripts/ without leaving it on sys.path."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")


def script(name: str) -> ModuleType:
    sys.path.insert(0, SCRIPTS)
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(SCRIPTS)
