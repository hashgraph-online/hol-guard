"""Where a session's requests go, step by step (workflow anatomy).

Usage: anatomy.py <tag> [<tag> ...]

Reads the transcripts of finished runs (Codex rollouts, Claude Code transcripts, Oh My Pi session
logs) and prints, per harness, arm and step kind, the mean per session of: model requests, tool
calls by type (read, search, edit, test, build, git, other), Guard holds, failed calls and the
CIGAR note size. Reading only; nothing is run.
"""

import bisect
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import WORK

TYPES = ("read", "search", "edit", "test", "build", "git", "other")
RULES = [
    ("edit", r"apply_patch|\*\*\* Begin Patch|^(Edit|Write|MultiEdit|edit|write)$"),
    ("test", r"\bpytest\b|\btox\b|unittest|\bnox\b|\bcargo test\b|\bgo test\b|\bnpm test\b|\bvitest\b|\bjest\b"),
    ("build", r"\bpip\b|\buv\b|python3? -m build|\bwheel\b|\bhatch\b|setup\.py|\btwine\b|\bflit\b"),
    ("git", r"^\s*git\b|[;&|]\s*git\b"),
    ("search", r"^(Grep|Glob|grep|find|ls)$|\brg\b|\bgrep\b|\bfind\b|\bfd\b|^\s*ls\b"),
    ("read", r"^(Read|read)$|\bcat\b|\bsed -n\b|\bhead\b|\btail\b|\bnl\b|\bwc\b"),
]
NOTE = "HOL Guard CIGAR"
# A Guard hold, block or refusal as the agent sees it in a tool result.
HOLD = re.compile(r"HOL Guard (held|blocked|stopped|paused|requires review|could not match)|"
                  r"Guard's workspace sandbox cannot run|needs your approval|waiting for approval", re.I)
FAILED_CODEX = re.compile(r"Exit code: [1-9]|Process exited with code [1-9]|Script failed|Script error")


def kind_of(text):
    for kind, pattern in RULES:
        if re.search(pattern, text, re.M):
            return kind
    return "other"


def blank():
    return {"requests": 0, "holds": 0, "failed": 0, "note": 0, **{t: 0 for t in TYPES},
            "notes": [], "calls": []}


def flat(content):
    if isinstance(content, str):
        return content
    out = []
    for part in content or []:
        if isinstance(part, dict):
            out.append(part.get("text") or flat(part.get("content")) or "")
    return "\n".join(out)


def codex(path, n):
    steps, at = [blank() for _ in range(n)], -1
    for line in Path(path).read_text().splitlines():
        e = json.loads(line)
        p = e.get("payload") or {}
        step = steps[at] if 0 <= at < n else None
        if e.get("type") == "response_item" and p.get("type") == "message":
            text = flat(p.get("content"))
            if p.get("role") == "user" and not text.startswith("<"):
                at += 1
            elif p.get("role") == "developer" and text.startswith(NOTE) and step:
                step["note"] += len(text)
                step["notes"].append(text)
        elif step is None:
            continue
        elif e.get("type") == "event_msg" and p.get("type") == "token_count":
            step["requests"] += 1
        elif p.get("type") in ("custom_tool_call", "function_call"):
            call = p.get("input") or p.get("arguments") or ""
            step[kind_of(call)] += 1
            step["calls"].append(call)
        elif p.get("type") in ("custom_tool_call_output", "function_call_output"):
            text = flat(p.get("output")) if not isinstance(p.get("output"), str) else p["output"]
            step["holds"] += bool(HOLD.search(text))
            step["failed"] += bool(FAILED_CODEX.search(text))
    return steps


def claude_note(e):
    """The decoded CIGAR note text of a Claude Code hook attachment, or None."""
    content = (e.get("attachment") or {}).get("content")
    text = "\n".join(c for c in content if isinstance(c, str)) if isinstance(content, list) else content
    return text if isinstance(text, str) and NOTE in text else None


def claude_event(e, step, seen):
    """Add one Claude Code transcript event to a step. A request is a distinct message id with usage."""
    m = e.get("message") if isinstance(e.get("message"), dict) else {}
    if e.get("type") == "attachment":
        text = claude_note(e)
        if text:
            step["note"] += len(text)
            step["notes"].append(text)
    elif e.get("type") == "assistant":
        if m.get("usage") and m.get("id") and m["id"] not in seen:
            seen.add(m["id"])
            step["requests"] += 1
        for part in m.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "tool_use":
                args = part.get("input") or {}
                step[kind_of(args.get("command") or part.get("name", ""))] += 1
                step["calls"].append(json.dumps(args))
    elif e.get("type") == "user":
        for part in m.get("content") or []:
            if isinstance(part, dict) and part.get("type") == "tool_result":
                step["holds"] += bool(HOLD.search(flat(part.get("content"))))
                step["failed"] += bool(part.get("is_error"))


def claude(paths, n):
    """The main transcript sets the steps; child-agent transcripts join the step running at their time."""
    steps, at, starts, seen = [blank() for _ in range(n)], -1, [], set()
    for line in Path(paths[0]).read_text().splitlines():
        e = json.loads(line)
        m = e.get("message") if isinstance(e.get("message"), dict) else {}
        if e.get("type") == "user" and isinstance(m.get("content"), str):
            at += 1
            starts.append(e.get("timestamp") or "")
        elif 0 <= at < n:
            claude_event(e, steps[at], seen)
    for path in paths[1:]:
        for line in Path(path).read_text().splitlines():
            e = json.loads(line)
            i = bisect.bisect_right(starts, e.get("timestamp") or "") - 1
            if 0 <= i < n:
                claude_event(e, steps[i], seen)
    return steps


def omp(paths, n):
    steps = [blank() for _ in range(n)]
    for at, path in enumerate(paths[:n]):
        step = steps[at]
        for line in Path(path).read_text().splitlines():
            e = json.loads(line)
            m = e.get("message") if isinstance(e.get("message"), dict) else {}
            if e.get("type") != "message_end":
                continue
            text = flat(m.get("content"))
            if m.get("role") == "assistant":
                step["requests"] += 1
                for part in m.get("content") or []:
                    if isinstance(part, dict) and part.get("type") == "toolCall":
                        args = part.get("arguments") or {}
                        step[kind_of(args.get("command") or part.get("name", ""))] += 1
                        step["calls"].append(json.dumps(args))
            elif m.get("role") == "toolResult":
                step["holds"] += bool(HOLD.search(text))
                step["failed"] += bool(m.get("isError"))
            elif NOTE in text:
                step["note"] += len(text)
                step["notes"].append(text)
    return steps


def sessions(tags):
    """Yield (row, [(step kind, step)]) for every session of the given runs.

    A row with no transcript (the first step failed before the harness wrote one) is reported on
    stderr and left out, not counted as a session that did nothing.
    """
    for tag in tags:
        for line in (WORK / "runs" / tag / "results.jsonl").read_text().splitlines():
            row = json.loads(line)
            kinds, ledger = row["kinds"], row["ledger"]
            if not ledger:
                print(f"skipped {tag} {row.get('arm')} seed {row.get('seed')}: no transcript", file=sys.stderr)
                continue
            if row["harness"] == "codex":
                steps = codex(ledger[0], len(kinds))
            elif row["harness"] == "claude-code":
                steps = claude(ledger, len(kinds))
            else:
                steps = omp(ledger, len(kinds))
            yield row, list(zip(kinds, steps))


def main():
    table = defaultdict(list)
    for row, steps in sessions(sys.argv[1:]):
        for kind, step in steps:
            table[(row["harness"], kind, row["arm"])].append(step)
    cols = ("requests", *TYPES, "holds", "failed", "note")
    print(f"{'harness':<12} {'step':<11} {'arm':<9} {'n':>2} " + " ".join(f"{c[:6]:>6}" for c in cols))
    for (harness, kind, arm), rows in sorted(table.items()):
        means = [sum(r[c] for r in rows) / len(rows) for c in cols]
        print(f"{harness:<12} {kind:<11} {arm:<9} {len(rows):>2} " + " ".join(f"{v:>6.1f}" for v in means))


if __name__ == "__main__":
    main()
