from __future__ import annotations

import os
import sys
from pathlib import Path

SRC_PATH = Path(__file__).resolve().parents[1] / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

existing_pythonpath = os.environ.get("PYTHONPATH", "")
pythonpath_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry]
if str(SRC_PATH) not in pythonpath_entries:
    os.environ["PYTHONPATH"] = os.pathsep.join([str(SRC_PATH), *pythonpath_entries])
