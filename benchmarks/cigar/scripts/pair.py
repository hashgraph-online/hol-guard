"""Savings of a CIGAR arm over a base arm run in the same batch, on any seeds (no stored reference needed).

Usage: pair.py <tag> [--base base] [--cigar cigar] [--base-tag TAG]
--base-tag takes the base rows from another batch (one run with CIGAR off serves many CIGAR-only batches).
Prints per seed cost and passes, the cost and token totals, and cost and requests per step kind.
"""

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RUNS
from steps import row_steps

ap = argparse.ArgumentParser()
ap.add_argument("tag")
ap.add_argument("--base", default="base")
ap.add_argument("--cigar", default="cigar")
ap.add_argument("--base-tag")
a = ap.parse_args()
rows, where = {}, {}
for tag, arm in ((a.base_tag or a.tag, a.base), (a.tag, a.cigar)):
    for line in (RUNS / tag / "results.jsonl").read_text().splitlines():
        r = json.loads(line)
        if r["arm"] == arm:
            rows[(arm, r["seed"])] = r
            where[(arm, r["seed"])] = RUNS / tag
seeds = sorted(s for (arm, s) in rows if arm == a.cigar and (a.base, s) in rows)
if not seeds:
    sys.exit(f"no seed has both {a.base} and {a.cigar} rows")


def pct(base, other, digits=0):
    # A session that failed before its first response has no cost to compare against.
    return f"{100 * (base - other) / base:.{digits}f}%" if base else "n/a"


def failed(row):
    return ",".join(f"{x['step']}:{x['kind']}" for x in row["steps"] if not x["passed"]) + (
        f" {row['error']}" if row.get("error") else ""
    )


print(f"{'seed':>4} {'repo':8} {'base':>8} {'cigar':>8} {'saved':>6}  pass base/cigar")
tb = tc = 0.0
pb = pc = 0
kinds = collections.defaultdict(lambda: [0, 0.0, 0.0, 0, 0])
for s in seeds:
    b, c = rows[(a.base, s)], rows[(a.cigar, s)]
    tb, tc = tb + b["cost"]["usd"], tc + c["cost"]["usd"]
    pb, pc = pb + b["passed"], pc + c["passed"]
    note = "".join(f"  {arm} FAIL {failed(r)}" for arm, r in ((a.base, b), (a.cigar, c)) if not r["passed"])
    saved = pct(b["cost"]["usd"], c["cost"]["usd"])
    print(
        f"{s:>4} {c['repo']:8} {b['cost']['usd']:8.4f} {c['cost']['usd']:8.4f} {saved:>6}  {int(b['passed'])}/{int(c['passed'])}{note}"
    )
    for x, y in zip(row_steps(b, where[(a.base, s)]), row_steps(c, where[(a.cigar, s)])):
        k = kinds[x["kind"]]
        k[0] += 1
        k[1] += x["usd"]
        k[2] += y["usd"]
        k[3] += x["requests"] or 0
        k[4] += y["requests"] or 0
print(
    f"TOTAL {len(seeds)} seeds  base {tb:.4f}  cigar {tc:.4f}  cost saved {pct(tb, tc, 1)}  passes {pb}/{pc}"
)


def total(arm, key):
    return sum(rows[(arm, s)]["tokens"].get(key, 0) for s in seeds)


print(f"\n{'tokens':16} {'base':>12} {'cigar':>12} {'saved':>7}")
for label, keys in (
    ("all (in + out)", ("input_tokens", "output_tokens")),
    ("input", ("input_tokens",)),
    ("  cached", ("cached_input_tokens",)),
    ("  uncached", ("uncached_input_tokens",)),
    ("output", ("output_tokens",)),
    ("requests", ("requests",)),
):
    b = sum(total(a.base, k) for k in keys)
    c = sum(total(a.cigar, k) for k in keys)
    print(f"{label:16} {b:12,} {c:12,} {100 * (b - c) / b if b else 0.0:6.1f}%")
print(f"\n{'kind':9} {'steps':>5} {'usd base':>9} {'usd cigar':>9} {'saved':>6} {'req/step base':>13} {'cigar':>5}")
for k, (n, ub, uc, rb, rc) in sorted(kinds.items()):
    print(f"{k:9} {n:5} {ub:9.4f} {uc:9.4f} {100 * (ub - uc) / ub if ub else 0:5.0f}% {rb / n:13.1f} {rc / n:5.1f}")
