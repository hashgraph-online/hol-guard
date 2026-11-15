"""Write the Oh My Pi arms: ompbase (no extension) and ompcigar (Guard's managed omp extension).

Run with the rig venv's python after cigar_setup.py:
    HOME=$W/ghome $W/gvenv/bin/python -I make_omp_arms.py <work dir>
Guard installs its omp extension into the rig Guard home the way `hol-guard install omp` does for a
user; the CIGAR arm loads that file explicitly, the base arm loads none. No login is copied: omp
reads its own agent dir for the model login (see omp_exec.py).
"""

import shutil
import sys
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi import OmpHarnessAdapter

work = Path(sys.argv[1]).resolve()
home = work / "ghome"
guard = home / ".hol-guard"
arms = work / "arms"
adapter = OmpHarnessAdapter()
ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard, home_override_explicit=True)
adapter.install(ctx)
extension = adapter._managed_extension_path(ctx)
assert extension.is_file(), f"Guard wrote no omp extension at {extension}"
for arm in ("ompbase", "ompcigar"):
    where = arms / arm
    where.mkdir(parents=True, exist_ok=True)
    (where / "home").mkdir(exist_ok=True)
    (where / "harness").write_text("omp\n")
    if arm == "ompcigar":
        shutil.copy2(extension, where / "hol-guard.ts")
print("omp arms written; extension from", extension)
