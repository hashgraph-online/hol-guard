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

## Prompt context

Runs made on 2026-11-06 with a pre-release build of #7341 (3.60.0a22), same fixture, task, models and prices as above. This round changes what the agent is told, not what tools return. Guard's prompt hook adds a short note to each prompt:

- where the code the prompt is about lives, as `path:line` pointers labeled with the enclosing definition;
- for prompts about changes ("a teammate pushed", "review", "what broke"), the uncommitted diff and each commit since the session's first prompt, newest first, before the pointers. Git runs offline with no user config, and changed files pass Guard's secret screen first.

The model, its reasoning level and every harness setting are the same as the control. Only the hooks differ:

- **Codex (`map`):** Guard's prompt hook and its after-tool hook on `Bash`, `Read` and MCP tools.
- **Claude Code (`claude-ctx`):** the control's settings plus Guard's `UserPromptSubmit` hook only. Each of the 30 prompts in the five runs got the note; no control prompt did.

`arm-init` only makes the controls. The arms with the note were set up by hand:

1. Install the Guard build under test in its own virtualenv. With `HOME` set to a scratch folder, set up context assistance there (`hol-guard context setup-python`, then `hol-guard context install`) and turn it on with workspace documents and agent context. Project scope is automatic, so the bench projects need no grant.
2. Codex: run Guard's Codex install against the scratch home. In the scratch home's `.codex/config.toml`, keep only the hooks the arm uses and add the control's approval and sandbox settings. Make the arm's `codex_home` a symlink to that `.codex` folder and its `home` a symlink to the scratch home. Codex trusts a hook by a key that includes the resolved path of `config.toml`, so a copied file carries keys for the wrong path and Codex skips the hooks without saying so.
3. Claude Code: copy the `claude-base` arm and add the `UserPromptSubmit` entry that Guard's Claude Code install writes for the scratch home to its `claude_settings.json`. The hook command must name the scratch Guard home, because Claude Code runs hooks with the real `HOME`.
4. Before measuring, check one session's transcript for the note on every prompt.

### Codex (gpt-6-luna, medium reasoning)

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base | 5 | 0 | yes | 0.0533 | +0.0% | 0.0449 | 3,456,946 | +0.0% | 115,147 | 3,341,798 | 0 | 16,755 | 66.0 | 0.0 | 112,911 |
| map | 5 | 4 | NO | 0.0553 | +3.8% | 0.0462 | 3,312,160 | -4.2% | 145,261 | 3,166,899 | 0 | 18,203 | 59.6 | 0.0 | 119,069 |

The four errored rows are earlier builds and are not counted: two ran with hooks Codex had not trusted, so Guard never ran, and two ran before #7341, when the change note came back empty in blobless clones like this fixture. They are also why "all pass" reads NO; the five counted runs all passed every check.

Requests fell 10%, and in the two runs checked the step after a teammate's commit took three commands, but paid cost rose 3.8%. Per-run paid was $0.042, $0.085, $0.047, $0.050 and $0.052. The $0.085 run made 90 requests in all. Its final review step ran 302 seconds, against 32 to 136 for its other steps, while the agent ran its own full diff and five experiments. The other four runs averaged 52.0 requests. Full-price input also rose, from 115k to 145k tokens. That comes from provider cache misses of 4k to 27k tokens at random requests, which show up in every arm: full-price input ranges from 75k to 186k between runs of the same arm. At five runs that noise is as large as the effect.

### Claude Code (claude-haiku-4-5)

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| claude-base | 5 | 0 | NO | 3.1286 | +0.0% | 2.7938 | 23,745,231 | +0.0% | 1,768 | 23,523,619 | 219,844 | 66,963 | 219.2 | 1.0 | 181,451 |
| claude-ctx | 5 | 0 | NO | 2.4102 | -23.0% | 2.1320 | 18,037,774 | -24.0% | 1,436 | 17,864,255 | 172,082 | 55,638 | 178.0 | 0.2 | 118,872 |

Paid cost fell 23%, with 19% fewer requests and 34% fewer characters of file reads. Per-run paid was $2.80 to $3.40 for the control and $1.93 to $2.87 with the note; four of the five runs with the note cost less than the cheapest control run.

Every run in both arms passed the full suite and two of the three acceptance checks. The third, `t2`, failed two of its four cases in three control runs and in four runs with the note. That is Haiku's limit on this task, as in the shaping round. It also means one run with the note passed every check against two control runs, so read the 23% as cost per attempted task, not savings for the same finished work.

One control run is not in the table: in its first attempt the agent's edits made the suite hang, steps two to four each hit the bench's ten-minute limit and no usage row was written. It was run again from a clean copy.

### Codex, second round (gpt-6-luna, medium reasoning)

The first Codex round differed from the Claude Code one in two ways: the `map` arm also ran Guard's after-tool hook, and five runs were too few against the cache-miss noise. The second round, also on 2026-11-06 with the same build, ran eight runs per arm. The `ctx` arm has Guard's `UserPromptSubmit` hook only, like `claude-ctx`, and four sessions ran at a time.

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| base | 8 | 0 | yes | 0.0587 | +0.0% | 0.0501 | 3,785,213 | +0.0% | 136,269 | 3,648,944 | 0 | 17,177 | 71.5 | 0.0 | 116,684 |
| ctx | 8 | 0 | yes | 0.0505 | -14.0% | 0.0424 | 3,113,904 | -17.7% | 125,536 | 2,988,368 | 0 | 16,115 | 64.5 | 0.0 | 109,658 |

All 16 runs passed every check. Per-run paid was $0.049 to $0.077 for the control and $0.037 to $0.067 with the note. An exact permutation test on the means gives p ≈ 0.04 one-sided and ≈ 0.08 two-sided, and a bootstrap 90% interval for the change runs from -24% to -3%. Requests that re-sent more than 3,000 tokens at full price, the cache misses that swamped the first round, averaged 12.4 per control run and 11.0 per run with the note. The saving comes from fewer requests, not from cache luck.

The first round's +3.8% did not hold up. This round does not say whether the after-tool hook or the small sample caused it.

### Oh My Pi (gpt-6-luna, medium thinking)

Oh My Pi 18.12.3 through its `openai-codex` provider, same fixture, task, checks and prices, eight runs per arm, four sessions at a time. The bench script does not drive Oh My Pi, so these runs used a separate local driver:

- Each step starts `omp --mode rpc`, sends the step's prompt and waits for the session to settle; steps two to six add `-c` to resume. Print mode (`omp -p`) does not fire the extension's `input` event, so Guard adds no note there.
- Both arms load Guard's extension once by path, with discovery off (`--no-extensions -e <path>`). The control's copy of the extension asks Guard for no prompt context; nothing else differs.
- Usage comes from the session file: one assistant entry per model request, with input, cache reads and output.

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| omp-base | 8 | 1 | NO | 0.1347 | +0.0% | 0.1241 | 10,770,036 | +0.0% | 182,036 | 10,588,000 | 0 | 21,237 | 149.8 | 0.0 | 195,790 |
| omp-ctx | 8 | 0 | yes | 0.1297 | -3.7% | 0.1182 | 9,830,882 | -8.7% | 220,658 | 9,610,224 | 0 | 23,121 | 136.6 | 0.0 | 209,184 |

The errored control row is a run where the model looped on step one, streaming the same text until the driver was stopped. It is not counted, and it is why "all pass" reads NO; it was run again from a clean copy. All 16 counted runs passed every check.

Paid cost fell 3.7%, which is well inside the noise: per-run paid was $0.100 to $0.196 for the control and $0.102 to $0.176 with the note, the one-sided permutation p is 0.38, and the bootstrap 90% interval runs from -19% to +16%. Requests fell 9%, but read output rose 7%. With the note the agent opened the lines it pointed to and still explored on its own, making 55 file reads per run against 52. Full-price input rose 21%, from more provider cache misses in the middle of steps (21.5 per run against 16). On the first request of each step, where the note goes, misses were the same in both arms. Prompts got the note 47 times out of 48. The one miss came when Guard took about three seconds under load and the extension went ahead without it.

An Oh My Pi session cost about 2.3 times a Codex session on the same model: about 150 requests, each re-reading about 70,000 tokens.

### What this shows

On Claude Code, telling the agent where the code is and what changed cut the bill by about a quarter, because sessions made fewer requests and each request re-read less. On Codex the same note cut the bill by 14% over eight runs a side, again through fewer requests. The first five-run Codex round was too small to show it, because Codex sessions are short and cache misses swing the cost by about as much as the saved requests do. On Oh My Pi the note cut requests a little and did not cut the bill: the agent read more, not less.
