# CIGAR long-task rig

Runs real Codex, Claude Code and Oh My Pi sessions on seeded multi-step tasks in
pinned open-source Python repos, with and without Guard, and records cost,
tokens and whether every task was done right. Results are in
[`docs/benchmarks/cigar-long-task.md`](../../docs/benchmarks/cigar-long-task.md).

This is not a CI job. Sessions call paid models; run it by hand before merging a
change that could move CIGAR's savings or Guard's hold rate.

## What a session is

One resumed agent thread of six steps on one repo. The seed fixes the repo, the
tasks and their targets, so every run of a seed asks the same things:

- fix bugs from a teammate's bad commit, or a commit with two bugs;
- write stubbed functions again;
- rename a name across files;
- add a doctest;
- answer "which function does this" without touching the tree;
- review the session's changes.

Every step is checked: the suite passes, tests are untouched, the rename is
complete, the doctest runs, the answer names the right function. A session
passes only if every step does.

Seeds below 200 use the benchmark prompts on the main repos (click, boltons,
toolz, more-itertools, jinja, pluggy). Seeds 200 and up are held out: they run
only on the repos marked `heldout` in `references/repos.json` (cachetools,
tomli, sortedcontainers) and phrase every task in loose wording, so a result
there cannot come from tuning to the prompts. Any seed works, so a random-seed
run is just a list of seeds nobody picked; the published runs use 16 seeds
mixed across both ranges.

## Arms

| arm | harness | Guard |
|---|---|---|
| `base` | Codex | none |
| `cigar` | Codex | CIGAR note only |
| `gfull` | Codex | every Guard hook: tool checks, approvals and CIGAR |
| `clbase` | Claude Code | none |
| `clcigar` | Claude Code | CIGAR note only |
| `clgfull` | Claude Code | every Guard hook |
| `ompbase` | Oh My Pi | none |
| `ompcigar` | Oh My Pi | Guard's managed omp extension (enforcement and CIGAR) |

Models: Codex and Oh My Pi run `gpt-6-luna` at medium effort; Claude Code runs
the bench default (haiku).

## Setup

Needs `codex` logged in, `claude` logged in for the Claude Code arms, `omp`
logged in for the Oh My Pi arms, Python 3.12+, and network for pip, git clones
and the signed CIGAR catalog.

1. Get a native macOS wheel for the Guard build under test (an alpha release
   asset or the PR's `native-guard-wheel-*` artifact). A plain `uv build` wheel
   has no native runtime and will not do.
2. `scripts/setup.sh <wheel>`. It builds everything in `$CIGAR_GAUNTLET_WORK`
   (default `/tmp/cigar-gauntlet`): a venv with the wheel, a Guard home, CIGAR
   set up the one-click way, all arms, and the repos cloned at pinned tags with
   a green suite each. It never touches the real `~/.hol-guard`, `~/.codex` or
   `~/.claude`. Rerun it with another wheel to move the rig to that build.

`HOL_GUARD_SRC` names the hol-guard checkout whose `scripts/` holds the bench
helpers; it defaults to the checkout these files are in.

## Running

```bash
scripts/batch.sh <tag> "base cigar gfull" 116 117 118      # Codex and Claude Code arms
scripts/batch_omp.sh <tag> "ompbase ompcigar" 116 117 118  # Oh My Pi arms
python3 scripts/compare.py <tag>                            # base vs CIGAR against the reference
python3 scripts/pair.py <tag> --base clbase --cigar clgfull  # paired savings for any two arms
```

Results land in `$CIGAR_GAUNTLET_WORK/runs/<tag>/results.jsonl`, one row per
session: arm, seed, repo, `passed`, `cost.usd`, `tokens` (input, cached,
uncached, output, requests) and each step's checks. `CIGAR_GAUNTLET_JOBS` caps
how many sessions run at once (default 4).

Report savings as paired totals over the same seeds, in both cost and tokens.
Cost saved is lower than tokens saved because most saved tokens are cached
input, which is billed far below output. Sessions are noisy: one seed can swing
30% either way, so judge totals over at least 16 seeds, never a single seed.

`scripts/notes.py` is a free check (about 2 minutes, no model calls): it replays
CIGAR's prompt hook on 48 seeded steps and diffs each note against
`references/notes/`. Use it to see whether a change alters what agents see
before paying for a live run.

## Keep the arms fair

Each of these once made the Guard arms look worse than Guard is. Check them
after changing the rig:

- The Claude Code hooks must name the daemon's own `HOME`. Another home is
  rejected as an unexpected root and every call is reviewed without a working
  directory.
- Do not export `GIT_CONFIG_GLOBAL` to the agent. The hook does not carry it,
  so every git read waits on an approval. Each arm's identity goes in its own
  `~/.gitconfig`.
- Claude Code's sandbox must exclude Guard's runtime (`make_full_arms.py` sets
  `excludedCommands`); nested, the runtime can neither start its own sandbox
  nor reach the daemon.
- Do not set `core.hooksPath=/dev/null` in the agent's repos. Guard treats a
  hooks folder outside the project or home as uncontained and holds writes.
- Regenerate the Oh My Pi extension (`make_omp_arms.py`) for each wheel. An old
  extension may skip headless prompts, so CIGAR never runs under `omp --print`.

If every hook call is denied with `native_pre_tool_unavailable`, the rig's
daemon has stopped answering. Stop it (`hol-guard daemon stop --home
$CIGAR_GAUNTLET_WORK/ghome --guard-home $CIGAR_GAUNTLET_WORK/ghome/.hol-guard`);
the next hook call starts a fresh one. Discard the sessions that ran meanwhile.

## Cleanup

`scripts/cleanup.sh` stops the rig daemon and deletes the Codex login copies
and session copies. `--all` deletes the whole rig.

## Files

- `scripts/run.py`: one seeded session (plan, teammate changes, agent steps,
  checks). Keep prompts and checks as they are; stored results depend on them.
- `scripts/setup.sh`, `cigar_setup.py`, `make_arms.py`, `make_full_arms.py`,
  `make_omp_arms.py`, `setup_repos.py`: rig setup.
- `scripts/omp_exec.py`: the Oh My Pi command and environment.
- `scripts/compare.py`, `pair.py`, `steps.py`, `notes.py`: reports and checks.
- `scripts/prep.py`: rebuilds a task pool from verified mutations; only needed
  to add a repo.
- `references/repos.json`: repo URLs, tags and test folders.
- `references/pools/`: verified tasks per repo.
- `references/plans/`: frozen plans for seeds 68–99 (`export_plans.py`
  regenerates them).
- `references/baseline.json`, `references/notes/`: the stored reference for
  `compare.py` and `notes.py`.
