# Long coding task: what an agent pays for

This benchmark measures what a long coding session costs with and without a change to how Guard handles tool output. It runs the same six-step task on a pinned project, with each harness's real CLI and its cheapest supported model, and reads usage from the harness's own usage record.

## The task

The fixture is pallets/click at a pinned commit. Each run starts from a clean copy and resumes one session six times, one prompt per step. After every step the bench runs the project's suite and four acceptance checks inside the same sandbox the agent used. A run passes when every check passes after step six.

Run it with `scripts/bench_guard_cigar_long_task.py`:

```bash
python scripts/bench_guard_cigar_long_task.py --work DIR fixture
python scripts/bench_guard_cigar_long_task.py --work DIR arm-init base          # Codex control
python scripts/bench_guard_cigar_long_task.py --work DIR arm-init claude-base   # Claude Code control
python scripts/bench_guard_cigar_long_task.py --work DIR run --arm base --first-rep 1 --reps 5
python scripts/bench_guard_cigar_long_task.py --work DIR report --base base ARM
```

An arm is a folder under `DIR/arms/` holding either a Codex home or a Claude Code settings file. Reps of one arm run one after another; run separate processes to run arms side by side.

## What counts

Providers bill input they have already seen, a cached prefix, at a fraction of the input price. A change that shrinks the chat can still raise the bill if it breaks that cache and makes the model read files again at full price. So the bench reports **paid**: the list-price cost of full-price input, cache reads, cache writes and output, summed per run. Raw input, every input token cached or not, is shown for reference only and never used to judge a change.

Paid tokens are the cost divided by the model's full input price, so harnesses with different prices can share one table.

Usage comes from:

- **Codex:** the session rollout file, summed over every model request.
- **Claude Code:** the session transcript, one entry per model request, with cache reads and both cache-write lifetimes counted separately.

A harness with no usage record is reported as "no usage ledger" rather than estimated.

## Results

All runs below were made on 2026-11-05, five per arm, base and treatment on the same day and model. Prices are list prices read that day. "read chars" counts output from commands the bench recognises as file reads; in the Codex treatment every command goes through the shaping wrapper, so it shows 0 there.

The treatment arms used a throwaway hook, not shipped code, that did what the shaping plan describes:

- test runs (`pytest`) kept to the failures and the summary line;
- `git diff`/`git show` collapsed hunks already shown earlier in the session;
- `rg`/`grep` results grouped per file and capped;
- any output over the cap kept its head, tail and error lines, with the rest saved to a file the model could read back;
- a read of the same file range with the same contents as earlier in the session replaced by a one-line note.

On Claude Code it ran as a `PostToolUse` hook on `Bash` and `Read` that returned `updatedToolOutput`. On Codex it ran as a `PreToolUse` hook on `Bash` that wrapped the command in the shaper through `updatedInput`.

### Codex (gpt-6-luna, medium reasoning)

Input $0.10, cached input $0.01 and output $0.50 per million tokens.

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base | 5 | 0 | yes | 0.0518 | +0.0% | 0.0438 | 3,262,454 | +0.0% | 123,664 | 3,138,790 | 0 | 16,191 | 67.2 | 0.0 | 107,772 |
| codexhook | 5 | 0 | yes | 0.0559 | +7.9% | 0.0469 | 3,462,724 | +6.1% | 136,542 | 3,326,182 | 0 | 17,899 | 68.8 | 0.0 | 0 |

All ten runs passed. The shaper cut 13% of the tool output it saw (396,580 to 345,996 characters over 82 commands); most Codex reads here are already narrow `sed -n` ranges and the suite runs quietly. The +7.9% is inside the run-to-run spread: a second copy of the base arm, with the hook configured but never trusted by Codex so it never ran, came out at +8.5% over four runs.

### Claude Code (claude-haiku-4-5)

Input $1, cache read $0.10, five-minute cache write $1.25, one-hour cache write $2 and output $5 per million tokens.

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| claude-base | 5 | 0 | NO | 2.7878 | +0.0% | 2.4773 | 20,908,303 | +0.0% | 1,573 | 20,704,091 | 202,639 | 62,105 | 195.0 | 0.4 | 172,292 |
| claude-shape | 5 | 0 | NO | 2.7399 | -1.7% | 2.4188 | 21,186,408 | +1.3% | 1,569 | 21,027,611 | 157,229 | 64,227 | 194.6 | 0.0 | 164,142 |

One run in five passed in each arm; in the other eight runs at least one check failed after step six. Haiku does not finish this task reliably, so these rows are not a clean comparison, and the bench report marks them as such. The shaper cut 30% of the tool output it saw (1,304,310 to 914,807 characters over 632 calls), mostly test output. Paid cost per run moved by -1.7%, against a spread of $2.32 to $3.35 between base runs. Almost all of the bill is cache reads of the chat, roughly 106,000 tokens re-read on each of about 195 requests; the tool output Guard can reach is a small part of that and did not shrink the per-request context.

### Hook cost

| Harness | hook calls | p50 | p95 | max | resident process added |
|---|---|---|---|---|---|
| Claude Code | 632 | 0 ms | 3 ms | 18 ms | none |
| Codex | 82 | 26 ms | 715 ms | 912 ms | none |

The Codex times include running the wrapped command itself, so they are an upper bound on the shaper's own cost.

### Gate G1

G1 asks for paid -25% on both Codex and Claude Code with every check passing. Measured: Codex +7.9%, Claude Code -1.7%. Both miss by more than ten points with the shaping and re-read levers in place, so this track stops here, as the plan requires. Compaction was not added. Raising the cut on tool output further would not change this: on both harnesses the bill is driven by how many requests a session makes and how much fixed context each one re-reads, and a tool hook can change neither.
