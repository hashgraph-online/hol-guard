# CIGAR preview 3.60.0a121 (2026-11-18)

Results for the 3.60.0a121 preview build and two hold fixes measured on it. The setup, seeds and arms are described in [cigar-long-task.md](cigar-long-task.md).

Full Guard against no Guard, each no-Guard run made in the same batch. The 32 seeds are the benchmark seeds 116–131 and the held-out seeds 200–215; the random set is a newer 16 seeds (581 to 9298), compared with two separate no-Guard runs.

| harness | set | cost saved | tokens saved | passed (Guard / no Guard) | holds |
|---|---|---|---|---|---|
| Codex | 32 seeds | 59.3% | 66.5% | 30 / 32 | 8 |
| Codex | 16 random seeds | 63.2–63.6% | 70.4–70.6% | 15 / 15 | |
| Claude Code | 32 seeds | 41.5% | 49.8% | 29 / 31 | 14 |
| Claude Code | 16 random seeds | 59.7–60.1% | 68.5–68.8% | 15 / 14 and 13 | |
| Oh My Pi (CIGAR) | 32 seeds | 55.3% | 62.2% | 26 / 32 | 25 |
| Oh My Pi (CIGAR) | 16 random seeds | 58.8–69.0% | 65.1–72.5% | 13 / 14 | |

## Short replies

Codex, 16 random seeds, full Guard with an instruction to answer briefly against full Guard without it. The Codex developer-instruction rows give the saving over full Guard without the instruction. The CIGAR note row gives each arm's saving over no Guard, since the difference was too small to report on its own.

| where the instruction went | baseline | cost saved | tokens saved | passed (with / without) |
|---|---|---|---|---|
| Codex developer instructions, run 1 | full Guard, no instruction | 5.5% | -0.2% | 15 / 15 |
| Codex developer instructions, run 2 | full Guard, no instruction | 13.9% | 9.2% | 15 / 15 |
| one sentence in the CIGAR note | no Guard | 67.8% with it, 66.2–68.2% without | 74.1% with it, 72.7–74.0% without | 14 / 15 |

The instruction helps only where the harness reads it as a system instruction. CIGAR's note is not that, so the note keeps its current wording.

## Commit messages read as data

Most Claude Code holds on the 32 seeds were `git commit -m "$(cat <<'EOF' ... EOF)"` messages holding a backtick, `a[key]`, `"\n"` or an em dash. After the fix in #8026 that reads such a message as data (only directly after `git commit` with value-less flags and a final `-m` or `--message`), on the same seeds and no-Guard run:

| | before | after |
|---|---|---|
| cost saved | 41.5% | 50.7% |
| tokens saved | 49.8% | 58.5% |
| passed (no Guard 31) | 29 | 30 |
| holds | 14 | 11 |
| requests | 1,221 | 1,108 |

On the 16 random seeds the same build saved 61.3–61.7% cost and 69.6–69.9% tokens (was 59.7–60.1% / 68.5–68.8%), passed 15 (no Guard 14 and 13), and held nothing.

## Oh My Pi edits that name a missing file

Most Oh My Pi holds were `edit` calls whose header line held leaked reasoning, such as `[tool/analysis code] ... "[src/app.py#D5E8]`. Guard could not prove which file the header named, so the edit went to review, and the agent then waited on an edit that could never apply. After the fix in #8018 that blocks such an edit at once with a reason showing how to write the header, on the same seeds and no-Guard runs:

| set | | before | after |
|---|---|---|---|
| 32 seeds | cost saved | 55.3% | 59.2% |
| | tokens saved | 62.2% | 71.9% |
| | passed (no Guard 32) | 26 | 29 |
| | holds | 25 | 12 |
| 16 random seeds | cost saved | 58.8–69.0% | 64.2–73.0% |
| | tokens saved | 65.1–72.5% | 73.6–79.1% |
| | passed (no Guard 14) | 13 | 15 |
| | holds | 13 | 0 |

Two of the three 32-seed failures are rename steps that also failed before the fix.

