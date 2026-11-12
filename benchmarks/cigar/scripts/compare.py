"""Compare a gauntlet run with the stored baseline and say whether CIGAR got worse.

Usage: compare.py <tag> [--threshold 0.10] [--json out.json]
Reads $CIGAR_GAUNTLET_WORK/runs/<tag>/results.jsonl. For each harness in the run, the CIGAR arm is
checked against the stored CIGAR reference on the same seeds; a base arm in the same run replaces the
stored base for the savings figure. Exit 0 = no regression, 1 = regression, 2 = incomplete run.
"""

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import REFS, RUNS
from steps import codex_steps

ap = argparse.ArgumentParser()
ap.add_argument("tag")
ap.add_argument("--threshold", type=float, default=0.10)
ap.add_argument("--json")
a = ap.parse_args()
ref = json.loads((REFS / "baseline.json").read_text())
runs = RUNS / a.tag
rows = {}
for line in (runs / "results.jsonl").read_text().splitlines():
    r = json.loads(line)
    rows[(r["arm"], r["seed"])] = r
verdicts, report = [], {}
for harness, h in ref["harnesses"].items():
    cig_arm, base_arm = h["arms"]["cigar"], h["arms"]["base"]
    seeds = sorted(s for (arm, s) in rows if arm == cig_arm)
    if not seeds:
        continue
    missing = [s for s in seeds if str(s) not in h["cigar"]]
    if missing:
        print(f"{harness}: seeds {missing} have no stored reference; use seeds {ref['seeds']}")
        sys.exit(2)
    fresh_base = all((base_arm, s) in rows for s in seeds)
    print(f"\n## {harness} ({len(seeds)} seeds; base {'rerun now' if fresh_base else 'stored'})")
    print(f"{'seed':>4} {'repo':8} {'base':>9} {'cigar ref':>9} {'cigar now':>9} {'vs ref':>7}  pass ref/now")
    tb = tr = tn = 0.0
    pr = pn = 0
    kinds = collections.defaultdict(lambda: [0.0, 0.0, 0, 0, 0])
    for s in seeds:
        now, cref = rows[(cig_arm, s)], h["cigar"][str(s)]
        base = rows[(base_arm, s)]["cost"]["usd"] if fresh_base else h["base"][str(s)]["usd"]
        tb, tr, tn = tb + base, tr + cref["usd"], tn + now["cost"]["usd"]
        pr, pn = pr + cref["passed"], pn + now["passed"]
        delta = 100 * (now["cost"]["usd"] - cref["usd"]) / cref["usd"]
        flag = (
            ""
            if now["passed"]
            else "  FAIL "
            + ",".join(f"{x['step']}:{x['kind']}" for x in now["steps"] if not x["passed"])
            + (f" {now['error']}" if now.get("error") else "")
        )
        print(
            f"{s:>4} {now['repo']:8} {base:9.4f} {cref['usd']:9.4f} {now['cost']['usd']:9.4f} {delta:+6.0f}%  {int(cref['passed'])}/{int(now['passed'])}{flag}"
        )
        if "steps" in cref and harness == "codex":
            for x, y in zip(cref["steps"], codex_steps(now, runs)):
                k = kinds[x["kind"]]
                k[0] += x["usd"]
                k[1] += y["usd"]
                k[2] += 1
                k[3] += x["requests"] or 0
                k[4] += y["requests"] or 0
    save_ref = (
        100 * (h["totals"]["base_usd"] - h["totals"]["cigar_usd"]) / h["totals"]["base_usd"]
        if len(seeds) == len(ref["seeds"])
        else None
    )
    save_now = 100 * (tb - tn) / tb
    print(
        f"TOTAL base {tb:.4f}  cigar ref {tr:.4f}  cigar now {tn:.4f} ({100 * (tn - tr) / tr:+.1f}% vs ref)  passes {pr}/{pn}"
    )
    print(f"savings now {save_now:.1f}% of cost" + (f"  (reference {save_ref:.1f}%)" if save_ref is not None else ""))
    tokens_saved = None
    if fresh_base:
        # Tokens as counted, unweighted by price, beside the cost figure: cost weighs output 50x a cache read.
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
            b = sum(total(base_arm, k) for k in keys)
            c = sum(total(cig_arm, k) for k in keys)
            saved = 100 * (b - c) / b if b else 0.0
            if label.startswith("all"):
                tokens_saved = saved
            print(f"{label:16} {b:12,} {c:12,} {saved:6.1f}%")
    if kinds:
        print(f"\n{'kind':9} {'steps':>5} {'usd ref':>9} {'usd now':>9} {'req/step ref':>12} {'now':>5}")
        for k, (ur, un, n, rr, rn) in sorted(kinds.items()):
            print(f"{k:9} {n:5} {ur:9.4f} {un:9.4f} {rr / n:12.1f} {rn / n:5.1f}")
    bad = []
    if tn > tr * (1 + a.threshold):
        bad.append(f"CIGAR cost {100 * (tn - tr) / tr:+.1f}% over reference (limit +{100 * a.threshold:.0f}%)")
    if pn < pr - 1:
        bad.append(f"CIGAR passed {pn} sessions, reference {pr}")
    if fresh_base and save_ref is not None and save_now < save_ref - 5:
        bad.append(f"savings {save_now:.1f}% vs reference {save_ref:.1f}%")
    partial = sorted(set(ref["seeds"]) - set(seeds))
    verdicts.append((harness, bad, partial))
    report[harness] = {
        "seeds": seeds,
        "base_usd": tb,
        "cigar_ref_usd": tr,
        "cigar_now_usd": tn,
        "passes_ref": pr,
        "passes_now": pn,
        "savings_now_pct": save_now,
        "tokens_saved_pct": tokens_saved,
        "savings_ref_pct": save_ref,
        "regressions": bad,
    }
if not verdicts:
    print("no CIGAR arm rows in this run")
    sys.exit(2)
print()
for harness, bad, partial in verdicts:
    # A seed with no row (a crashed or skipped session) must not let the rest pass for the whole run.
    note = f" (PARTIAL: no result for seeds {partial})" if partial else ""
    print(f"{harness}: {'REGRESSION: ' + '; '.join(bad) if bad else 'OK'}{note}")
if a.json:
    Path(a.json).write_text(json.dumps(report, indent=1) + "\n")
sys.exit(1 if any(bad for _, bad, _ in verdicts) else 2 if any(partial for _, _, partial in verdicts) else 0)
