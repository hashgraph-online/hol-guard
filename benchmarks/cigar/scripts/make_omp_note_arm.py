"""Write the Oh My Pi CIGAR-only arm (ompnote) from the full Guard arm (ompcigar).

    python3 -I make_omp_note_arm.py <work dir>

Guard ships one Oh My Pi extension that both adds CIGAR's prompt note and checks
tool calls. To compare full Guard with the note alone, as the Claude Code and
Codex CIGAR-only arms do with the prompt hook only, this copies that extension
and skips the handlers that check or rewrite tool calls and their results
("tool_call", "tool_result", "context", "message_end"). The prompt handlers
("input", "before_agent_start") and session bookkeeping stay as Guard wrote them.
Run make_omp_arms.py first; rerun this after any rebuild of ompcigar.
"""

import sys
from pathlib import Path

SKIPPED = ("tool_call", "tool_result", "context", "message_end")
ENTRY = "export default function (pi: ExtensionAPI) {\n"


def note_only(source: str) -> str:
    if source.count(ENTRY) != 1:
        raise SystemExit("ompcigar extension has no single entry point; was it rebuilt in a new shape?")
    skipped = ", ".join(f'"{name}"' for name in SKIPPED)
    shim = (
        "  // Rig CIGAR-only arm: skip Guard's tool checks, keep its prompt note.\n"
        f"  const __skipped = new Set([{skipped}]);\n"
        "  pi = new Proxy(pi, { get(target, key) {\n"
        "    if (key === \"on\") return (event, handler) => __skipped.has(event) ? undefined : target.on(event, handler);\n"
        "    const value = target[key];\n"
        "    return typeof value === \"function\" ? value.bind(target) : value;\n"
        "  } });\n"
    )
    return source.replace(ENTRY, ENTRY + shim)


def main() -> None:
    arms = Path(sys.argv[1]).resolve() / "arms"
    source = arms / "ompcigar" / "hol-guard.ts"
    if not source.is_file():
        raise SystemExit(f"no full Guard omp arm at {source}; run make_omp_arms.py first")
    where = arms / "ompnote"
    (where / "home").mkdir(parents=True, exist_ok=True)
    # Write the extension first: a batch takes the harness marker to mean the arm is ready.
    (where / "hol-guard.ts").write_text(note_only(source.read_text()))
    (where / "harness").write_text("omp\n")
    print("ompnote written from", source)


if __name__ == "__main__":
    main()
