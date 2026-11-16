"""Write each seed's task plan as JSON, so another runner replays the exact same tasks without this RNG.

Usage: export_plans.py [first last]   (default 68 99) writes references/plans/s<seed>.json
A plan holds the repo, each step's kind and prompt, and the pool entries its setup and checks use.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import REFS
from run import plan

first, last = (int(x) for x in sys.argv[1:3]) if len(sys.argv) > 2 else (68, 99)
out = REFS / "plans"
out.mkdir(exist_ok=True)
for seed in range(first, last + 1):
    repo, pool, tasks = plan(seed, 6, frozen=False)
    doc = {"seed": seed, "repo": repo, "steps": tasks}
    (out / f"s{seed}.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
print(f"wrote plans for seeds {first}-{last} to {out}")
