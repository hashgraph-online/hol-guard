"""Where the requests go, and what Guard's holds cost, for any arms of a batch.

Usage:
  report.py <tag> --arm gfull [--arm cigar ...]
  report.py <tag> --arm gfull --base base [--base-tag TAG ...]

Per arm and step kind it prints: requests per step, tool calls per step and by
type (test, read, search, edit, git, other), holds, holds per 100 calls,
calls made later in the same step after a hold, dollar cost per hold, and retries: later calls in
the step that repeat a held call (the same command, or the same tool on the
same file; Oh My Pi patches name no file, so there the same patch). A rewritten
command is a later call but not a retry. Oh My Pi commands that ran through
Guard's runner leave no command text, so they are counted as not checked and
retries there is a lower bound. With --base it also prints cost
and tokens saved against the base arm, cost saved per step kind, and the
do-no-harm rate (share of paired steps where the arm cost 20% more than the
base). Steps a harness never reached are left out of every count. Give
--base-tag more than once to pair against several no-Guard runs of the same
seeds; savings are then printed as low-high over those runs.

Holds are tool results that carry a Guard stop message. Text Guard adds as a
CIGAR note is not a hold.
"""

import argparse
import bisect
import collections
import json
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RUNS
from steps import row_steps

HOLD = re.compile(
    r"HOL Guard (?:could not match|requires|blocked|held|is holding|stopped|needs)"
    r"|HOL Guard withheld|stays blocked|hol-guard approvals wait|Waiting for (?:a )?(?:Guard )?approval",
    re.I,
)
TEST = re.compile(r"\b(pytest|unittest|doctest|tox|nox|cargo test|go test|vitest|jest|npm (?:run )?test|pnpm test)\b")
SEARCH = re.compile(r"^\s*(rg|grep|find|fd|ls|tree)\b|\|\s*(rg|grep)\b")
READ = re.compile(r"\b(sed -n|cat|head|tail|nl|wc|less|bat)\b")
EDIT = re.compile(r"apply_patch|<<\s*'?PY|python3? -c|perl -p?i|sed -i|\btee\b|>\s*[\w./-]+\.\w+\s*$")
GIT = re.compile(r"\bgit\b")
TEST_OUTPUT = re.compile(r"(?<!\d)\d+ (?:passed|failed|errors?)\b|no tests ran|\[\s*\d+%\]|test result: (?:ok|FAILED)")
TOOL_KIND = {
    "read": "read", "Read": "read", "NotebookRead": "read",
    "grep": "search", "Grep": "search", "Glob": "search", "find": "search", "glob": "search", "ls": "search", "LS": "search",
    "edit": "edit", "Edit": "edit", "MultiEdit": "edit", "Write": "edit", "write": "edit", "NotebookEdit": "edit",
    "apply_patch": "edit",
}
KINDS = ("test", "read", "search", "edit", "git", "other")


def shell_kind(cmd):
    c = cmd.strip()
    if TEST.search(c):
        return "test"
    if EDIT.search(c):
        return "edit"
    if SEARCH.search(c):
        return "search"
    if READ.search(c):
        return "read"
    if GIT.search(c):
        return "git"
    return "other"


def call_kind(name, text):
    if name in TOOL_KIND:
        return TOOL_KIND[name]
    return shell_kind(text or "")


PATCH_FILE = re.compile(r"\*\*\* (?:Update|Add|Delete) File: ([^\s\\\"]+)")


def call_keys(tool, cmd, paths=()):
    """What a retry repeats: the command text, or the same tool on any of the same files.

    Commands keep their inner whitespace, which can change what they do. The
    tool is part of a file key so that reading a file after a held edit to it
    is not counted as retrying the edit. A multi-file patch gets one key per
    file, so a later patch to any one of them matches.
    """
    cmd = (cmd or "").strip()
    if cmd:
        return frozenset([cmd])
    return frozenset(f"{tool}:{path}" for path in paths if path)


def text_of(value):
    if isinstance(value, str):
        return value
    return json.dumps(value)


def codex_calls(row):
    """Per step: [kind, held, key] from the Codex rollout. One custom/function call is one request."""
    n = len(row["kinds"])
    out = [[] for _ in range(n)]
    for path in row.get("ledger") or []:
        step, pending = -1, {}
        try:
            lines = Path(path).read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            e = json.loads(line)
            p = e.get("payload") or {}
            t = p.get("type")
            if e.get("type") == "event_msg" and t == "task_started":
                step += 1
                continue
            if not 0 <= step < n:
                continue
            if t in ("custom_tool_call", "function_call"):
                raw = p.get("input") or p.get("arguments") or ""
                cmds = re.findall(r'cmd:\s*"((?:[^"\\]|\\.)*)"', raw)
                if "apply_patch" in raw and not cmds:
                    kind = "edit"
                elif cmds:
                    kinds = [shell_kind(c.encode().decode("unicode_escape", "ignore")) for c in cmds]
                    if "test" in kinds:
                        kind = "test"
                    elif "apply_patch" in raw:
                        kind = "edit"
                    else:
                        kind = kinds[0]
                else:
                    kind = call_kind(p.get("name", ""), raw)
                pending[p.get("call_id")] = len(out[step])
                patched = PATCH_FILE.findall(raw)
                cmd = cmds[0].encode().decode("unicode_escape", "ignore") if cmds else ""
                out[step].append([kind, False, call_keys("apply_patch", cmd, patched)])
            elif t in ("custom_tool_call_output", "function_call_output"):
                i = pending.get(p.get("call_id"))
                text = text_of(p.get("output"))
                if i is not None and HOLD.search(text) and "CIGAR" not in text[:200]:
                    out[step][i][1] = True
    return out


def claude_calls(row):
    """Per step: [kind, held, key] from the Claude Code transcripts.

    In the main transcript a step starts at each typed prompt. A subagent's
    transcript has prompts of its own, so its calls go to the step that was
    running when they were made, by timestamp.
    """
    n = len(row["kinds"])
    out = [[] for _ in range(n)]
    starts, pending = [], {}
    for index, path in enumerate(row.get("ledger") or []):
        try:
            lines = Path(path).read_text().splitlines()
        except OSError:
            continue
        step = -1
        for line in lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            msg = e.get("message") or {}
            content = msg.get("content")
            if index == 0 and e.get("type") == "user" and isinstance(content, str) and not e.get("isMeta"):
                step += 1
                starts.append(e.get("timestamp") or "")
                continue
            if index > 0:
                stamp = e.get("timestamp") or ""
                step = bisect.bisect_right(starts, stamp) - 1
            if not 0 <= step < n or not isinstance(content, list):
                continue
            for b in content:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "tool_use":
                    # Claude Code writes a tool call twice when a hook answers it; count it once.
                    if b.get("id") in pending:
                        continue
                    inp = b.get("input") or {}
                    pending[b.get("id")] = (step, len(out[step]))
                    keys = call_keys(b.get("name", ""), inp.get("command", ""), [inp.get("file_path") or inp.get("path")])
                    kind = call_kind(b.get("name", ""), inp.get("command", ""))
                    out[step].append([kind, False, keys, e.get("timestamp") or ""])
                elif b.get("type") == "tool_result":
                    where = pending.get(b.get("tool_use_id"))
                    if where and HOLD.search(text_of(b.get("content"))):
                        out[where[0]][where[1]][1] = True
    # Subagent transcripts come after the main one; put each step's calls back in time order.
    return [[call[:3] for call in sorted(step, key=lambda call: call[3])] for step in out]


def omp_calls(row, runs_dir):
    """Per step: [kind, held, key] from the Oh My Pi step logs."""
    out = []
    for n in range(1, len(row["kinds"]) + 1):
        calls, pending = [], {}
        path = Path(runs_dir) / f"{row['arm']}-s{row['seed']}-{n}.jsonl"
        for line in path.read_text().splitlines() if path.exists() else []:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("type") == "tool_execution_start":
                args = e.get("args") or {}
                pending[e.get("toolCallId")] = len(calls)
                cmd = args.get("command", "")
                kind = "wrapped" if "contained-workspace-sink" in cmd else call_kind(e.get("toolName", ""), cmd)
                # Guard's runner replaces a wrapped command with a one-off request file, so the
                # model's command is not recorded and the call cannot be matched (keys None).
                keys = None if kind == "wrapped" else call_keys(
                    e.get("toolName", ""), cmd, [args.get("path") or str(args.get("input") or "")]
                )
                calls.append([kind, False, keys])
            elif e.get("type") == "tool_execution_end":
                i = pending.get(e.get("toolCallId"))
                text = text_of(e.get("result"))
                if i is not None and HOLD.search(text):
                    calls[i][1] = True
                # Guard's omp extension runs bash through its own runner and the model's command is
                # no longer in the log; a test runner's summary in the output marks a test run.
                if i is not None and calls[i][0] == "wrapped":
                    calls[i][0] = "test" if TEST_OUTPUT.search(text) else "other"
        # A step that ended mid-call leaves no output to sort the call by.
        for call in calls:
            if call[0] == "wrapped":
                call[0] = "other"
        out.append(calls)
    return out


def row_calls(row, runs_dir):
    h = row.get("harness")
    if h == "claude-code":
        return claude_calls(row)
    if h == "omp":
        return omp_calls(row, runs_dir)
    return codex_calls(row)


def load(tag, arm):
    path = RUNS / tag / "results.jsonl"
    rows = {}
    for line in path.read_text().splitlines():
        r = json.loads(line)
        if r["arm"] == arm:
            rows[r["seed"]] = r
    return rows


def anatomy(tag, arm, rows):
    per = collections.defaultdict(collections.Counter)
    step_usd = collections.defaultdict(lambda: ([], []))
    for r in rows.values():
        steps = row_steps(r, RUNS / tag)
        calls = row_calls(r, RUNS / tag)
        for i, kind in enumerate(r["kinds"]):
            step_calls = calls[i] if i < len(calls) else []
            requests = steps[i]["requests"] if i < len(steps) else None
            # A step the harness never reached (it stopped early) has neither
            # requests nor calls. One that timed out or failed has calls but
            # no result line, so its request count is unknown and counts 0.
            if not requests and not step_calls:
                continue
            k = per[kind]
            k["steps"] += 1
            k["requests"] += requests or 0
            held_keys, held_seen, step_holds = set(), False, 0
            for c_kind, held, keys in step_calls:
                k["calls"] += 1
                k[c_kind] += 1
                if held_seen:
                    k["after_hold"] += 1
                    if keys is None:
                        k["unmatched"] += 1
                    elif keys & held_keys:
                        k["retries"] += 1
                if held:
                    k["holds"] += 1
                    held_seen = True
                    step_holds += 1
                    held_keys |= keys or frozenset()
            if requests:
                step_usd[kind][held_seen].append((steps[i]["usd"], step_holds))
    print(f"\n== {tag} {arm}: {len(rows)} sessions, {sum(r['passed'] for r in rows.values())} passed")
    cols = ("steps", "requests", "calls") + KINDS + ("holds", "after_hold", "retries")
    print(f"{'kind':9}" + "".join(f"{c:>11}" for c in cols) + f"{'req/step':>10}{'holds/100':>10}")
    tot = collections.Counter()
    for kind, k in sorted(per.items()):
        tot.update(k)
        print(f"{kind:9}" + "".join(f"{k[c]:>11}" for c in cols) + f"{k['requests'] / k['steps']:>10.2f}{100 * k['holds'] / max(k['calls'], 1):>10.1f}")
    print(f"{'TOTAL':9}" + "".join(f"{tot[c]:>11}" for c in cols) + f"{tot['requests'] / max(tot['steps'], 1):>10.2f}{100 * tot['holds'] / max(tot['calls'], 1):>10.1f}")
    if tot["holds"]:
        print(f"calls after a hold, per hold: {tot['after_hold'] / tot['holds']:.2f}")
        print(f"retries per hold (same command or same file again): {tot['retries'] / tot['holds']:.2f}")
        if tot["unmatched"]:
            print(f"  not checked: {tot['unmatched']} later call(s) ran through Guard's runner with no recorded command")
        extra, measured = hold_cost(step_usd)
        if measured:
            print(
                f"cost per hold: ${extra / measured:.4f} "
                f"(held steps cost ${extra:.4f} more than the median same-kind step with no hold)"
            )
        if measured < tot["holds"]:
            unpriced = tot["holds"] - measured
            print(f"  not priced: {unpriced} hold(s) in steps with no usage or no unheld step of that kind")
    return per


def hold_cost(step_usd):
    """Extra dollars in steps with a hold, and how many holds they cover: each held
    step's cost minus the median cost of the same kind's steps without one. Kinds
    with no unheld step are skipped, and so are their holds. Different tasks share
    a kind, so this is an estimate of the hold's cost, not a paired measurement."""
    extra, measured = 0.0, 0
    for clean, held in step_usd.values():
        if not clean or not held:
            continue
        mid = statistics.median(usd for usd, _ in clean)
        extra += sum(usd - mid for usd, _ in held)
        measured += sum(n for _, n in held)
    return extra, measured


TOKEN_KEYS = ("input_tokens", "output_tokens")


def session_tokens(row):
    return sum(row["tokens"].get(k, 0) for k in TOKEN_KEYS)


def share(paired_usd, row):
    usd = row["cost"]["usd"]
    return min(paired_usd / usd, 1.0) if usd else 0.0


def paired(tag, arm, rows, base_arm, base_tags):
    bases = [(t, load(t, base_arm)) for t in base_tags]
    seeds = sorted(s for s in rows if all(s in b for _, b in bases))
    if not seeds:
        print(f"\nno seed has both {arm} and {base_arm} rows")
        return
    cost, toks, kinds, harm = [], [], collections.defaultdict(list), [0, 0]
    for btag, brows in bases:
        # Totals count only steps both arms reached, the same steps the per-kind
        # figures use: a session that stopped early must not be credited with the
        # other arm's cost for steps it never ran. Tokens are not split per step,
        # so each session's tokens are scaled by the share of its cost in those steps.
        bc = ac = bt = at = 0.0
        pairs = 0
        per = collections.defaultdict(lambda: [0.0, 0.0])
        for s in seeds:
            sb = sa = 0.0
            for x, y in zip(row_steps(brows[s], RUNS / btag), row_steps(rows[s], RUNS / tag)):
                # Cost comes from the same result line as requests: a step
                # without one has no cost to compare.
                if not x["requests"] or not y["requests"]:
                    continue
                per[x["kind"]][0] += x["usd"]
                per[x["kind"]][1] += y["usd"]
                sb += x["usd"]
                sa += y["usd"]
                pairs += 1
                harm[1] += 1
                harm[0] += y["usd"] > 1.2 * x["usd"]
            bc += sb
            ac += sa
            bt += session_tokens(brows[s]) * share(sb, brows[s])
            at += session_tokens(rows[s]) * share(sa, rows[s])
        if not pairs:
            print(f"\n{arm} vs {base_arm} ({btag}): no step has a result line on both sides; savings unavailable")
            continue
        cost.append(100 * (bc - ac) / bc if bc else 0.0)
        toks.append(100 * (bt - at) / bt if bt else 0.0)
        for k, (b, a) in per.items():
            kinds[k].append(100 * (b - a) / b if b else 0.0)
    if not cost:
        return
    passes = (sum(rows[s]["passed"] for s in seeds), [sum(b[s]["passed"] for s in seeds) for _, b in bases])

    def rng(v):
        return f"{min(v):.1f}%" if len(v) == 1 else f"{min(v):.1f}-{max(v):.1f}%"

    print(f"\n== {arm} vs {base_arm} over {len(seeds)} seeds, {len(bases)} base run(s)")
    print(f"cost saved {rng(cost)}  tokens saved (estimate, by cost share) {rng(toks)}  passed {arm} {passes[0]} / base {passes[1]}")
    print(f"do-no-harm: {harm[0]} of {harm[1]} paired steps cost 20% more ({100 * harm[0] / max(harm[1], 1):.1f}%)")
    for k, v in sorted(kinds.items()):
        print(f"  {k:9} cost saved {rng(v)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tag")
    ap.add_argument("--arm", action="append", required=True)
    ap.add_argument("--base")
    ap.add_argument("--base-tag", action="append")
    a = ap.parse_args()
    for arm in a.arm:
        rows = load(a.tag, arm)
        if not rows:
            print(f"no {arm} rows in {a.tag}")
            continue
        anatomy(a.tag, arm, rows)
        if a.base:
            paired(a.tag, arm, rows, a.base, a.base_tag or [a.tag])


if __name__ == "__main__":
    main()
