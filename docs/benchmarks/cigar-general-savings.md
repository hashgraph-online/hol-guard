# CIGAR general savings (2026-11-16)

Follow-on measurements to [cigar-long-task.md](cigar-long-task.md), which has the long-task, random-seed,
workflow, language and mixed-prompt sets these sections read.

Rig 3.59.0 wheel (main after #7853) unless a section says otherwise; cheapest models (Codex and Oh My
Pi on gpt-6-luna medium, Claude Code on claude-haiku-4-5).

## Workflow set, step by step (anatomy)

From the 2026-11-15 workflow runs (`wfcx`, `wfcl`, `wfomp`; four sessions per arm, rig 3.59.0 wheel,
cheapest models), read with `benchmarks/cigar/scripts/anatomy.py`. Mean per session for each step:
model requests, Guard holds or refusals the agent saw, failed tool calls, and note size.

| harness | step | requests no Guard → full Guard | holds (full) | failed calls no → full | note chars |
|---|---|---|---|---|---|
| Codex | bug fix | 7.5 → 4.2 | 0.0 | 0.2 → 0.2 | 2,040 |
| Codex | changelog | 5.5 → 3.8 | 0.0 | 0.2 → 0.0 | 1,028 |
| Codex | dependency | 4.0 → 4.5 | 0.0 | 0.0 → 0.2 | 1,947 |
| Codex | wheel build | 5.0 → 13.5 | 0.8 | 0.0 → 0.8 | 84 |
| Claude Code | bug fix | 18.2 → 6.2 | 0.0 | 4.0 → 0.5 | 1,998 |
| Claude Code | changelog | 5.5 → 3.0 | 0.0 | 0.0 → 0.0 | 1,019 |
| Claude Code | dependency | 3.8 → 4.5 | 0.0 | 0.0 → 0.2 | 1,986 |
| Claude Code | wheel build | 7.5 → 12.2 | 1.8 | 2.0 → 6.0 | 84 |
| Oh My Pi | bug fix | 8.2 → 5.5 | 0.0 | 0.8 → 1.0 | 1,986 |
| Oh My Pi | changelog | 5.8 → 3.2 | 0.0 | 0.2 → 0.0 | 1,238 |
| Oh My Pi | dependency | 5.5 → 5.2 | 0.0 | 0.0 → 1.0 | 2,096 |
| Oh My Pi | wheel build | 6.8 → 13.2 | 3.8 | 1.8 → 7.8 | 158 |

Where the extra requests go: the wheel-build step. With full Guard it takes about twice the
requests on every harness, and the note there is nearly empty, so CIGAR neither causes nor saves
those. The agent does not know the project's build command (`python -m build` and `pip wheel` are
missing or hang without network; the working one is `python -m flit_core.wheel`), and each
attempt that Guard holds costs a further turn: package installs held for review, a
`python - <<'PY'` script Guard could not match to its controls (once in every Codex session), a
two-step chain whose first step (`ls`) Guard did not treat as read-only, and a program the
workspace sandbox would not start. The other three steps save requests on every harness.

Follow-ups: the chore note (hol-guard #7899) now names the project's own build command. The holds are Guard decisions, which this work does
not change; they are listed for the owner.

## Stall on 2026-11-16 (finding, not reproduced)

Read from this Mac's Guard daemon log; no CIGAR activity appears in it. At 08:05 EST the daemon
restarted right after Guard's core files went missing beneath the running process (the delivery
container became unreadable), which looks like a Desktop core update under a live daemon. On
start it spent 30.5 s migrating installed authority before answering hooks (12.6 s at the next
start, 17.3 s at 20:36 EST the night before). Hooks fail closed while the daemon is not
answering, which is the "could not complete the native hook decision safely" every tool call
saw. Unrelated noise in the same log: catalog publication refresh fails about every three
minutes, and Claude Code hooks miss the resident runtime 50 to 240 times per five minutes. The
busy load run below hit the same refusal on this Mac's own hooks and recovered on retry.

## Which apps get the note (harness coverage)

From `context_assistance_prompt.rs` at this build: the note goes out only on the prompt hook's
answer. No app gets it through an MCP tool.

| App | Gets the note | How |
|---|---|---|
| Claude Code, Codex, Devin, Muse, Z Code | yes | prompt hook, `additionalContext` |
| Kimi Code | yes | prompt hook, `message` |
| Cline | yes | hook worker passes it on as `contextModification` |
| Pi, Oh My Pi | yes, with a current Guard extension | prompt hook, only when the extension sets `guard_prompt_context` |
| Antigravity, Copilot, Cursor, Gemini, Grok, Hermes, OpenClaw, OpenCode, Paseo | no | Guard checks their tool calls; nothing carries a note |

Nine of the eighteen apps Guard protects get no savings from CIGAR today.

## Used and wrong notes in real sessions

`benchmarks/cigar/scripts/used_notes.py` reads the enforcement + CIGAR sessions from the long-task page. A note that
named project files was used when a later tool call in the same step names one of them, wrong when
the agent worked on other project files and none of the note's, and neither when the agent named no
file at all (mostly code questions answered from the note). A call names a file when one of its
path tokens is that path, or that path with a leading folder; a different file that shares part of
the name (`test_a.py` for `a.py`) does not count. "Used" is still generous: a note that lists eight
files counts if the agent touched any one.

| set | harness | notes with files | used | wrong | neither |
|---|---|---|---|---|---|
| Python, picked seeds (`l24b`) | Codex | 77 | 94.8% | 0.0% | 5.2% |
| | Claude Code | 64 | 92.2% | 0.0% | 7.8% |
| | Oh My Pi | 82 | 90.2% | 4.9% | 4.9% |
| Python, fresh draw (`fresh8`) | Codex | 39 | 84.6% | 0.0% | 15.4% |
| | Claude Code | 30 | 86.7% | 0.0% | 13.3% |
| | Oh My Pi | 39 | 82.1% | 5.1% | 12.8% |
| Go, Rust, TypeScript | Codex | 36 | 91.7% | 8.3% | 0.0% |
| | Claude Code | 33 | 93.9% | 6.1% | 0.0% |
| | Oh My Pi | 38 | 84.2% | 15.8% | 0.0% |

On task prompts CIGAR's notes are nearly always on the right files; the wrong notes are on everyday
prompts (the mixed set: 48 of 86, 55.8%), which these task sets do not contain. Tuned versus fresh:
the random-seed rows in [cigar-long-task.md](cigar-long-task.md) save as much as the picked seeds or more (Codex CIGAR only
50.4% against 44.9%; Claude Code 47.9% against 51.5%), so the picked seeds are not over-tuned; the
fresh draw here uses fewer notes per step, not wrong ones.

## Note build time and dropped notes under load

`benchmarks/cigar/scripts/load.py` replays the mixed set's prompts through the cigar arm's prompt
hook, no model calls, and compares each note with the one-at-a-time baseline. "Dropped" means the
baseline had a note and this run got none.

| where | prompts at once | busy cores | dropped | p50 | p95 |
|---|---|---|---|---|---|
| macOS arm64, this Mac | 1 | 0 | 0 of 88 | | 0.58 s |
| macOS arm64, this Mac | 4 | 4 | 39 of 88 (44.3%) | 0.17 s | 0.52 s |
| Linux arm64, container (4 CPUs) | 1 | 0 | 10 of 88 (11.4%) | 0.46 s | 0.50 s |
| Windows x64 on Arm (VM) | 1 | 0 | not measured | | |

Windows was not measured: on the VM (x64 Guard under Arm emulation) CIGAR's install job did not finish
within 15 minutes on two fresh rig homes, so no prompt hook ran. That install time is itself a
finding for the owner.

The busy-run drops were silent: the hook exited 0 with an empty answer. Cause: the prompt hook
asked whether project context was on with a 40 ms try-lock and read a busy lock as "off". Fixed
by keeping a lock-free copy of that choice (hol-guard #7898, with a test that fails on the parent
commit). Not rerun: there was no native wheel with the fix to install in the rig.

The Linux row compares against the Mac baseline, which was a different build (77 of 88 notes
changed), so most of its "drops" are not drops: 9 of the 10 are everyday prompts ("keep going",
"nice work", "go ahead", "write a design doc...") where the Mac build pasted a 0.7–5.7k-character
excerpt that the mixed-set labels mark wrong, and the Linux build stayed silent in 0.01–0.08 s. One
(a cachetools "explain" prompt, 0.19 s) lost a right note.

## Probe: notes that point at files the agent already opened

`benchmarks/cigar/scripts/reopened.py` over the picked-seed, fresh and workflow sessions
(`l24b*`, `fresh8*`, `wf*`). For each step after the first: the note's mapped ranges and pasted
excerpts whose file a tool call named in an earlier step, and the note text those lines take.
File-level, so it is an upper bound on what leaving them out could save. A pasted excerpt counts
with its whole code block. The last column weighs those characters (about four to a token) by every
later request that carries them, against the sessions' total input tokens.

| harness | ranges in later notes | file opened before | share of all note text | share of session input |
|---|---|---|---|---|
| Claude Code | 1,155 | 560 (48.5%) | 18.2% | 0.5% |
| Codex | 834 | 458 (54.9%) | 24.2% | 1.1% |
| Oh My Pi | 938 | 433 (46.2%) | 18.3% | 1.3% |

Half the ranges are in files the agent has opened. Leaving all of them out would remove 18–24% of
note text, but notes are a small part of what a session sends, so the saving is at most 0.5–1.3% of
input. CIGAR already sends each pasted excerpt once per session (`context_assistance_prompt_seen.rs`),
but it only remembers what it showed, not what the agent opened itself. Not built: the ceiling is
below the noise of a batch, and the per-session record of opened files it needs would serve little
else.

## Launch brief: what a launched agent already gets

`guard-swarm` starts Codex as `codex exec --json -` and Claude Code as `claude -p --output-format
stream-json` with the user's own profile (`rust/crates/guard-swarm/src/adapter.rs`: no profile
replacement). Guard's prompt hook runs for those children like any other session, so a Swarm agent's
first prompt already carries the same CIGAR note a brief would hold. A separate brief would add the
note twice. The first part of the swarm check is therefore measured as a cold launched agent without Guard against
one with it (swarm set, `cold` mode, `base` against `gfull` arms), and a separate brief is not built. It would only
help harnesses with no prompt hook, which Swarm does not launch today.

## Probe: do agents lose turns finding the test command?

`anatomy.py` on the Go, Rust and TypeScript sessions (`lgo*`, `lrust*`, `lts*`; Codex and Claude
Code), mean per step. Test runs count `go test`, `cargo test`, `npm test`, `vitest` and `jest`.
Claude Code rows include child-agent transcripts, joined to the step that was running.

| harness | step | test runs no Guard → full Guard | failed calls no Guard → full Guard |
|---|---|---|---|
| Codex | bug | 2.0 → 0.5 | 0.0 → 0.1 |
| Codex | second bug | 1.9 → 0.0 | 0.0 → 0.0 |
| Codex | review | 1.2 → 1.2 | 0.0 → 0.1 |
| Claude Code | bug | 3.1 → 2.1 | 1.1 → 1.5 |
| Claude Code | second bug | 4.2 → 0.9 | 1.1 → 0.2 |
| Claude Code | review | 1.6 → 1.2 | 0.6 → 0.8 |

Agents run the tests one to four times a step without Guard and less with it, and seldom fail
to: failed calls of any kind stay under two a step. The Python fix note already names the `pytest`
command for test files the prompt names. A per-language narrowest-test note has little to save
here, so it is not built. The chore note (#7899) lists each project's own
test commands for build and CI prompts, which is where the workflow set lost turns.

## Probe: compaction on the long set

None of the 72 long and workflow sessions (`l24*`, `l24b*`, `wf*`, three harnesses) compacted: no
compaction record in any Codex rollout, Claude Code transcript or Oh My Pi session. The largest
request context was 160k tokens on Claude Code (`l24bcl`) and 153k on Codex (`l24bcx`), under each
harness's compaction point. With nothing to measure before and after, the re-add-after-compaction
change is not built; it needs a set that runs past compaction, which costs several times the long set.

## Swarm set

Six tasks that split into two or three parts (`benchmarks/cigar/scripts/swarm_run.py`), cheapest
models, 2026-11-16. "One" is a single agent doing every part; "cold" is one fresh agent per part,
run in turn on the same folder. Cost is the paid-token price for all sessions of the task.

| harness | arm | one agent: passes, cost | N cold agents: passes, cost |
|---|---|---|---|
| Codex | no Guard | 6/6, $0.033 | 6/6, $0.072 |
| Codex | full Guard (CIGAR) | 6/6, $0.030 (−9%) | 4/6, $0.042 (−42%) |
| Claude Code | no Guard | 6/6, $1.339 | 6/6, $2.068 |
| Claude Code | full Guard (CIGAR) | 6/6, $1.121 (−16%) | 6/6, $1.703 (−18%) |
| Oh My Pi | no Guard | 6/6, $0.039 | 6/6, $0.070 |
| Oh My Pi | CIGAR only | 6/6, $0.029 (−26%) | 6/6, $0.039 (−44%) |

Splitting a task across cold agents costs 1.5 to 2.2 times one agent without Guard; with CIGAR's
note the extra cost of splitting falls to 1.3 to 1.5 times. The two Codex cold misses (toolz and
jinja seeds) had no Guard hold or refusal in any session: each part's agent ran only its own
focused test and stopped while another part's test still failed. No conflicting edits were seen.

The third arm (N agents with shared context) is built in the runner, not in Guard:
`swarm_run.py --mode warm` is `cold` plus a hand-off at the top of each later agent's prompt. For
every earlier agent it lists the piece it was given, the files it changed and the test suite's
last line after it finished. The prompt hook still sends its note. Alpha 3.60.0a110, seeds 1-6,
full Guard; Claude Code and Codex cold and warm were run back to back:

| harness | cold | warm | change |
|---|---|---|---|
| Oh My Pi (CIGAR) | 5/6, agents 2-3 $0.0183 | 6/6, agents 2-3 $0.0172 | −6% |
| Codex | 5/6, $0.031 on the 5 both passed | 6/6, $0.031 | +0.6% |
| Claude Code | 6/6, $1.452 | 6/6, $1.545 | +6.4% |

The bar for building hand-offs in Guard was 30% under cold, so they were not built. Later agents
already do one read, one edit and one test; the extra cost of splitting is each agent's fixed
start (system prompt, tools, note), which a hand-off cannot remove. The suite line did win one
pass: on seed 4 it showed the last agent tests an earlier part left failing.

## Commit-replay set

33 merged public pull requests from 12 repos (Python, Go, Rust, TypeScript), pinned in
`benchmarks/cigar/references/replay.json` by `benchmarks/cigar/scripts/replay_prep.py`. Each task
starts at the parent commit with the PR's title and description as the prompt; it passes when the
PR's own tests pass. Every test file passes at the merge commit and fails at the parent. One
session per task, `benchmarks/cigar/scripts/replay_run.py`, rig 3.59.0, cheapest models. This set
was never used for tuning, so it is also the fresh-task check. Saving counts tasks both arms passed.

| harness | arms | passed (no Guard) | cost saved, both passed | per task low / median / high |
|---|---|---|---|---|
| Codex | full Guard vs no Guard | 23 (31) | 3.9% (23 tasks) | −111% / 17% / 53% |
| Oh My Pi | CIGAR only vs no Guard | 18 (26) | 16.8% (16 tasks) | −73% / 47% / 73% |
| Claude Code | full Guard vs no Guard, alpha 3.60.0a110 | 14 (17) | 42.2% (13 tasks) | |

Oh My Pi leaves out one TypeScript task (ufo #313) whose CIGAR session cost $0.093 against $0.006; a
rerun cost $0.0048 against $0.0052, so it was a one-off. With it the total is −23%.

Why the pass counts fall:

- 4 tasks on both harnesses (three more-itertools PRs and one cachetools PR): Guard's prompt
  protection refused to send the PR text ("uses wording Guard holds for review, such as a delete,
  transfer, download or elevated command"). The texts are ordinary bug reports (for example a
  `chunked_even` boundary fix). This is a Guard decision false positive, outside CIGAR, and is
  reported to the owner; this work does not change Guard decisions.
- Codex's other 4 losses were task noise: rerun on both arms, the same tasks failed on both or
  passed on both.
- Oh My Pi: of the 5 other losses, 2 (tomli) failed on both arms when rerun. 3 failed with CIGAR
  twice and passed without it twice: tomli #286 (key-part limit), semver #296 (empty-string error)
  and ufo #287 (`filterQuery`). None had a Guard hold. The PR tests check exact names and messages
  the description does not give; the cause was not traced further. One first-run CIGAR session
  (tomli) hung for an hour mid-stream in a model tool call, with no Guard call pending.

Claude Code ran later on alpha 3.60.0a110 (all 33 tasks on each arm, no session errors). Its prompt starts with one
instruction line (`CLAUDE_LEAD` in `replay_run.py`, both arms): without it Haiku read the bare PR
text as a question and stopped after one request with no edits (7 of 20 no-Guard and 2 of 21
full-Guard sessions in a first try). Over all 33 tasks it saved 38.3% ($12.879 against $7.948);
on the 13 both passed, 42.2% ($4.203 against $2.428). Three fewer passes with Guard is inside
Haiku's spread on this set and needs a second run to call.

The 40% target is missed by more than ten points on Codex and Oh My Pi (3.9% and 16.8%) and met on Claude Code (42.2%), which reads whole files and so has more for the note to replace. The reason:
one-PR tasks on small libraries are already direct (median 15–17 requests a task, 93% of input
from cache), so the note has few searches to replace. The large savings on the seeded sets come
from multi-step sessions where the note replaces repeated searches; one-step work has less of that.
