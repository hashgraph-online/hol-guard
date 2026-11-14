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

All 16 runs passed every check. Per-run paid, sorted, was $0.0491, $0.0524, $0.0544, $0.0581, $0.0588, $0.0590, $0.0615 and $0.0765 for the control, and $0.0365, $0.0433, $0.0465, $0.0503, $0.0507, $0.0533, $0.0565 and $0.0668 with the note. An exact permutation test on the means (see [How the tests were run](#how-the-tests-were-run)) gives p ≈ 0.04 one-sided and ≈ 0.08 two-sided, and a bootstrap 90% interval for the change runs from -24% to -3%. Requests that re-sent more than 3,000 tokens at full price, the cache misses that swamped the first round, averaged 12.4 per control run and 11.0 per run with the note. The saving comes from fewer requests, not from cache luck.

The first round's +3.8% did not hold up. This round does not say whether the after-tool hook or the small sample caused it.

### Oh My Pi (gpt-6-luna, medium thinking)

Oh My Pi 18.12.3 through its `openai-codex` provider, same fixture, task, checks and prices, eight runs per arm, four sessions at a time. The bench script does not drive Oh My Pi, so these runs used a separate local driver:

- Each step starts `omp --mode rpc --model openai-codex/gpt-6-luna --thinking medium --session-dir <per-run folder> --no-lsp --no-extensions -e <extension>`, writes `{"type": "prompt", "message": <step prompt>}` as one line on stdin, and reads events until one has type `session_settled`; steps two to six add `-c` to resume. Print mode (`omp -p`) does not fire the extension's `input` event, so Guard adds no note there.
- Both arms load Guard's extension once by path, with discovery off (`--no-extensions -e <path>`). The control's copy of the installed extension differs in one setting: both places that send `guard_prompt_context: true` to Guard send `false` instead. Nothing else differs.
- Usage comes from the session file: one assistant entry per model request, with input, cache reads and output.
- The driver uses the bench script's fixture copy, teammate commit and per-step checks, so only the harness differs.

| Arm | n | errored | all pass | paid $/run | paid vs base | input $ | raw input | raw vs base | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| omp-base | 8 | 1 | NO | 0.1347 | +0.0% | 0.1241 | 10,770,036 | +0.0% | 182,036 | 10,588,000 | 0 | 21,237 | 149.8 | 0.0 | 195,790 |
| omp-ctx | 8 | 0 | yes | 0.1297 | -3.7% | 0.1182 | 9,830,882 | -8.7% | 220,658 | 9,610,224 | 0 | 23,121 | 136.6 | 0.0 | 209,184 |

The errored control row is a run where the model looped on step one, streaming the same text until the driver was stopped. It is not counted, and it is why "all pass" reads NO; it was run again from a clean copy. All 16 counted runs passed every check.

Paid cost fell 3.7%, which is well inside the noise. Per-run paid, sorted, was $0.1001, $0.1001, $0.1021, $0.1076, $0.1312, $0.1611, $0.1796 and $0.1958 for the control, and $0.1017, $0.1203, $0.1209, $0.1222, $0.1264, $0.1339, $0.1369 and $0.1756 with the note. The one-sided permutation p is 0.38 (0.75 two-sided), and the bootstrap 90% interval runs from -19% to +16%. Requests fell 9%, but read output rose 7%. With the note the agent opened the lines it pointed to and still explored on its own, making 55 file reads per run against 52. Full-price input rose 21%, from more provider cache misses in the middle of steps (21.5 per run against 16). On the first request of each step, where the note goes, misses were the same in both arms. Prompts got the note 47 times out of 48. The one miss came when Guard took about three seconds under load and the extension went ahead without it.

An Oh My Pi session cost about 2.3 times a Codex session on the same model: about 150 requests, each re-reading about 70,000 tokens.

### How the tests were run

Both eight-run rounds use the per-run paid costs listed above.

- **Permutation test:** take all 12,870 ways to split the 16 costs into two groups of eight. For each split, compute the mean of one group minus the mean of the other. The one-sided p is the share of splits whose difference is at most the observed one (note minus control). The two-sided p is the share whose absolute difference is at least the observed one.
- **Bootstrap interval:** resample each arm's eight costs with replacement 20,000 times. Each time, take the ratio of the means minus one. The 5th and 95th percentiles give the 90% interval.

### What this shows

On Claude Code, telling the agent where the code is and what changed cut the bill by about a quarter, because sessions made fewer requests and each request re-read less. On Codex the same note cut the bill by 14% over eight runs a side, again through fewer requests. The first five-run Codex round did not show it. That round also ran the after-tool hook, and Codex cache misses swing the cost of these short sessions by about as much as the saved requests do; these runs do not say which of the two hid the saving. On Oh My Pi the note cut requests a little and did not cut the bill: the agent read more, not less.

## Line-range map

Runs made on 2026-11-07 with native wheels built from this change. Same fixture, task, checks and prices as above. The note now lists `path:start-end` ranges with each definition's first line and its members' lines, and pastes no code. The changes note names the definitions each changed hunk falls in. Each arm ran at the same time as its own control, because the control's cost moved by up to 25% between runs started a few hours apart.

### Codex (gpt-6-luna, medium reasoning)

Arms run the prompt hook only, as in the second round above.

| Arm | n | errored | all pass | paid $/run | paid vs base | raw input | full-price in | cache read | output | requests | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base5 | 8 | 0 | yes | 0.0457 | +0.0% | 3,032,449 | 93,601 | 2,938,848 | 13,913 | 65.4 | 101,804 |
| map (early build) | 8 | 0 | yes | 0.0393 | -14.0% | 2,432,534 | 89,110 | 2,343,424 | 13,963 | 58.8 | 76,970 |
| base6 | 8 | 0 | yes | 0.0562 | +0.0% | 3,532,735 | 131,839 | 3,400,896 | 18,030 | 74.2 | 115,389 |
| map | 7 | 1 | NO | 0.0347 | -38.3% | 1,996,650 | 89,030 | 1,907,621 | 13,534 | 50.3 | 73,362 |
| base7 | 8 | 0 | yes | 0.0618 | +0.0% | 3,994,179 | 136,995 | 3,857,184 | 18,987 | 78.8 | 127,396 |
| map | 8 | 0 | yes | 0.0377 | -39.0% | 2,140,254 | 104,686 | 2,035,568 | 13,670 | 53.5 | 74,857 |

The early build is the map before it pointed at related docs and tests. The errored row is one Luna `max_output_tokens` error in step one, not counted; the other seven passed every check. The last pair has a bootstrap 90% interval of -49% to -27% and a one-sided permutation p of 0.001. Pooling the last two pairs with the batching-sentence arm described below (23 runs, each divided by its own control's mean) gives -38%, with a 90% interval of -43% to -33%.

Per step (m$, base6 / map): s1 6.2 / 5.2, s2 17.2 / 9.0, s3 6.4 / 5.0, s4 6.5 / 2.7, s5 8.3 / 4.1, s6 11.6 / 8.8. Every step makes fewer requests. Steps four (find a teammate's breaking change) and five (docs) halve.

A sentence asking the agent to batch reads and edits changed nothing on Codex: with the map, -37.9% against -38.3% without it. Without the map, the sentence alone gave -17.6%. Codex already sends several `sed -n` ranges in one shell call, so this change adds the sentence on Claude Code only.

### Claude Code (claude-haiku-4-5)

The `map` arm runs Guard's prompt hook through the native runtime built from this change, against a scratch Guard home with CIGAR set up. The control has no hook. Runs of the two arms alternated through the day, and the note reached every prompt (checked in the session transcripts). This arm includes the batching sentence.

| Arm | n | all pass | paid $/run | raw input | full-price in | cache read | cache write | output | requests | compactions | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base | 9 | 6/9 | 3.0116 | 23,096,361 | 1,685 | 22,894,635 | 200,041 | 64,080 | 208.9 | 0.8 | 173,546 |
| map | 8 | 4/8 | 2.0240 | 14,688,551 | 1,218 | 14,537,651 | 149,682 | 53,930 | 150.8 | 0.0 | 100,241 |

Paid cost fell 32.8%. Per-run paid, sorted, was $2.45, $2.70, $2.94, $2.96, $2.97, $3.08, $3.11, $3.30 and $3.61 for the control, and $1.62, $1.87, $1.94, $2.01, $2.05, $2.14, $2.26 and $2.30 with the map: every run with the map cost less than the cheapest control. The bootstrap 90% interval runs from -38% to -27%, and the one-sided permutation p is below 0.001. Against all 22 control runs made on this rig that day, including those paired with the earlier arms, the change is -29.9%.

Requests fell 28%, from 209 to 151, and file-read output fell 42%. The calls that went away are searches (25 to 9 per run), `git` commands (15 to 2, since the changes note already names what a teammate touched) and `python -c` probes (25 to 16). Test runs and edits stayed the same. The control compacted its chat in most runs; the map arm never did.

Every failed run in both arms fails the same way: two of the four `t2` cases. The prompt asks for `(DEPRECATED)` in `--help`, and Haiku instead adds `deprecated` to Click's bracketed extras (`[deprecated: use --new]`), the style the surrounding option-help code uses. The suite and the other checks pass in every run. Over the whole day, 12 of 22 control runs and 12 of 23 runs with any form of the note passed every check, so the note does not change how often Haiku finishes the task correctly.

### Oh My Pi (gpt-6-luna, medium reasoning)

Same driver as the Oh My Pi rows above: RPC mode with only the Guard extension loaded, and a control copy of the extension with prompt context turned off. The first map runs cut the bill by about 19% (nine runs) and the step that asks about a teammate's push barely moved. The cause was in the extension: it sent no session id with its prompt-context request, so Guard could not tell when the session began and the changes note never saw the teammate's commit. The prompt fell back to pasted excerpts. This change sends the session id; the `fix` arm is the extension built from it.

| Arm | n | errored | all pass | paid $/run | paid vs base | raw input | full-price in | cache read | output | requests | read chars |
|---|---|---|---|---|---|---|---|---|---|---|---|
| base | 8 | 0 | yes | 0.1441 | +0.0% | 11,623,325 | 179,245 | 11,444,080 | 23,507 | 155.4 | 189,468 |
| fix | 8 | 0 | yes | 0.0924 | -35.9% | 6,821,939 | 162,147 | 6,659,792 | 19,092 | 121.1 | 134,814 |

Per-run paid, sorted, was $0.086, $0.094, $0.132, $0.132, $0.143, $0.162, $0.192 and $0.211 for the control, and $0.074, $0.086, $0.087, $0.089, $0.089, $0.096, $0.102 and $0.116 with the fix. The bootstrap 90% interval runs from -46% to -22%, and the one-sided permutation p is 0.002. All 16 runs passed every check.

Per step (m$, base / fix): s1 10.4 / 7.1, s2 33.9 / 19.9, s3 14.6 / 11.0, s4 17.7 / 9.5, s5 23.5 / 16.2, s6 44.0 / 28.7. Step four, the teammate's push, now halves as it does on Codex. Searches fell from 13 to 5 per run and edits from 53 to 39. The batching sentence made no difference here either (-19% with it over four runs, against -19% without it).

Runs that hit a login error partway through were dropped from both arms, as was one control run that failed a check. Both arms still lose about 13,000 characters per run to Guard's sandbox refusing `/bin/sh` when the agent first runs the tests; that is the same on both sides and is a separate Guard issue.

### Why the harnesses differ

The bill is the number of requests times the context each request re-sends. The map cuts the first and keeps the second from growing.

- Codex sends several `sed -n` ranges in one shell call, so a list of line ranges turns into few, large reads: requests fell from 79 to 54.
- Haiku sends one tool call per request. A session makes about 150 to 210 requests, each re-reading 24,000 tokens of fixed prompt plus the growing chat, so cost is almost all cache reads. Here the map helps by removing whole search and `git` loops rather than by merging reads. The batching sentence asks Claude Code to send calls it already knows together in one response; Haiku did so on about one turn in twenty.
- Oh My Pi also makes one call per request and edits one hunk at a time, so it pays for many small edits (about 18 in the final review step). Its saving comes the same way as Haiku's, from fewer searches and a smaller step four, once the extension sends its session id. Before that fix the changes note was empty on Oh My Pi and Pi, which is why their numbers trailed the other two.

## Seeded runs across repos

The single click task above can be tuned to. These runs use the rig in [`benchmarks/cigar/`](../../benchmarks/cigar/README.md): each seed picks a repo and six tasks from verified pools (bug fixes, a two-bug commit, stubs to write again, a rename, a doctest, a code question, a review), and every step is checked. Seeds 116–131 use the benchmark prompts on six repos; seeds 200–215 are held out, on three other repos with loosely worded prompts; the random set is 16 seeds nobody picked (153, 171, 183, 185, 190, 191, 195, 199, 384, 1309, 1940, 2628, 3924, 6419, 6712, 8003).

Three setups per harness: no Guard, CIGAR only (the prompt note, no tool checks), and enforcement plus CIGAR (every Guard hook, as a user who installed Guard runs). Totals are paired over the same seeds. Cost is list price; tokens are input plus output. Cost saved trails tokens saved because most saved tokens are cached input. Codex and Oh My Pi run gpt-6-luna at medium effort, Claude Code runs claude-haiku-4-5. Guard 3.60.0a75, 2026-11-12.

| harness | seeds | setup | cost | tokens | passed | cost saved | tokens saved |
|---|---|---|---|---|---|---|---|
| Codex | random 16 | no Guard | $0.29 | 16.6M | 16/16 | — | — |
| Codex | random 16 | CIGAR only | $0.14 | 6.8M | 16/16 | 50.4% | 58.8% |
| Codex | random 16 | enforcement + CIGAR | $0.20 | 11.2M | 16/16 | 29.8% | 32.5% |
| Codex | 116–131, 200–215 | no Guard | $0.58 | 34.2M | 31/32 | — | — |
| Codex | 116–131, 200–215 | CIGAR only | $0.32 | 17.0M | 31/32 | 44.9% | 50.3% |
| Codex | 116–131, 200–215 | enforcement + CIGAR | $0.49 | 28.3M | 28/32 | 15.3% | 17.4% |
| Claude Code | random 16 | no Guard | $7.50 | 49.1M | 16/16 | — | — |
| Claude Code | random 16 | CIGAR only | $3.90 | 22.5M | 16/16 | 47.9% | 54.2% |
| Claude Code | random 16 | enforcement + CIGAR | $4.84 | 28.6M | 14/16 | 35.4% | 41.8% |
| Claude Code | 116–131, 200–215 | no Guard | $16.91 | 113.7M | 30/32 | — | — |
| Claude Code | 116–131, 200–215 | CIGAR only | $8.20 | 46.8M | 32/32 | 51.5% | 58.8% |
| Claude Code | 116–131, 200–215 | enforcement + CIGAR | $9.94 | 58.9M | 30/32 | 41.2% | 48.2% |
| Oh My Pi | random 16 | no Guard | $0.32 | 18.3M | 16/16 | — | — |
| Oh My Pi | random 16 | enforcement + CIGAR | $0.18 | 8.9M | 16/16 | 43.8% | 51.4% |
| Oh My Pi | 116–131, 200–215 | no Guard | $0.77 | 46.5M | 32/32 | — | — |
| Oh My Pi | 116–131, 200–215 | enforcement + CIGAR | $0.38 | 18.9M | 30/32 | 50.6% | 59.4% |

Oh My Pi has no CIGAR-only setup: its Guard extension carries both.

CIGAR alone halves the tokens on every harness and seed set without costing tasks; Claude Code with CIGAR passed two held-out tasks the run without Guard missed. With enforcement on, the gap to CIGAR only is commands Guard held for review and the turns the agent spent working around them: inline Python (`python -c`, heredocs), `perl -pi`, `find … -exec sed -i`, shell `for` loops and `git add … && git commit`. Not every enforcement failure is a hold: three Codex held-out misses (204, 207, 212) show no Guard message, and the two Claude Code random misses left a rename or a test unfinished. The Oh My Pi misses do trace to Guard: reads of its own `xd://` and `proc://` resources held for review, and a malformed edit sent for approval instead of back to the model.

### Enforcement + CIGAR after the review-hold fixes

The table above was run while Guard still held many of the agents' routine edit and probe commands for review. These runs repeat the enforcement + CIGAR setup, every Guard hook on, on later 3.59.0 builds. Codex, Oh My Pi and the random Claude Code seeds ran on the morning of 2026-11-13. Claude Code on seeds 116–131 and 200–215 still saved only 47.3% of tokens on that build, so it was run again on 2026-11-14 on main at `0ba8d232`. By then Guard no longer held inline Python that only reads or reshapes data (#7685, #7709), `find … -exec sed -i` edits (#7679) or Git probes that ran past the hook's time budget (#7672, #7711).

Each row is paired with a no-Guard run of the same seeds made on 2026-11-13, so the no-Guard totals differ a little from the table above. Same models, prices and token count (input plus output).

| harness | seeds | no Guard cost | no Guard tokens | no Guard passed | enforcement + CIGAR cost | enforcement + CIGAR tokens | enforcement + CIGAR passed | cost saved | tokens saved |
|---|---|---|---|---|---|---|---|---|---|
| Codex | random 16 | $0.29 | 17.8M | 16/16 | $0.16 | 8.4M | 16/16 | 45.7% | 52.9% |
| Codex | 116–131, 200–215 | $0.58 | 34.2M | 31/32 | $0.27 | 14.1M | 32/32 | 52.7% | 58.8% |
| Claude Code | random 16 | $9.10 | 60.9M | 14/16 | $3.96 | 22.4M | 16/16 | 56.4% | 63.3% |
| Claude Code | 116–131, 200–215 | $16.91 | 113.7M | 30/32 | $7.85 | 43.8M | 30/32 | 53.6% | 61.5% |
| Oh My Pi | random 16 | $0.40 | 22.0M | 16/16 | $0.21 | 10.0M | 16/16 | 48.1% | 54.5% |
| Oh My Pi | 116–131, 200–215 | $0.77 | 46.5M | 32/32 | $0.40 | 19.3M | 31/32 | 48.0% | 58.6% |

With every Guard hook on, all three harnesses now use less than half the tokens they use without Guard, on the benchmark seeds, the held-out seeds and the random ones. Each run with Guard passed as many tasks as its paired run without Guard, or more, except one Oh My Pi seed. On Claude Code's benchmark and held-out seeds, the same setup saved 48.2% of tokens in the table above and 47.3% on the 2026-11-13 build. With those holds gone it saved 61.5%, with the same tasks passed.
