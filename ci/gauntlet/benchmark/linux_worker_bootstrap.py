"""Inert container bootstrap: receive authenticated inputs on dedicated FDs.

This asset has no signing key and executes no candidate before verification.
"""
from __future__ import annotations

import os
import runpy
import sys

if sys.platform != "linux" or os.geteuid() != 0:
    raise RuntimeError("isolated worker bootstrap requires Linux root supervisor")
sys.argv = ["/trusted/probes/developer_worker_probe.py", "--plan-fd", "3",
            "--isolation-fd", "4", "--verification-key-fd", "5"]
runpy.run_path(sys.argv[0], run_name="__main__")
