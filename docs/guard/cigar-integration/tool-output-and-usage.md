# Tool output and usage

This page answers three questions: does Guard change what your AI app sees from its tools, how do you get the raw output, and how much did each app actually use.

## What Guard does to tool output

Guard never shortens, summarizes or rewrites tool output to save tokens. After a tool runs, Guard's hook scans the output for secrets, such as an API key or a private key, and decides one of these:

- **Pass it on unchanged.** This is what happens to almost all output.
- **Block it** when it contains a secret, or when the scan cannot finish in time.
- **Keep only the first part** when the output is too big to scan in full (over 5 MB of text, or nested too deeply). Guard scans the first 1 MB and blocks the output if that part holds a secret.

How much of a block or a cut the model sees depends on the app. Pi, Oh My Pi and the Cline plugin let Guard replace the result, so the model gets Guard's message, or the scanned first 1 MB, in place of the output. In Claude Code, Codex, Cline's native hooks and the other apps, Guard's hook runs after the tool has already returned. Guard adds its message, for example "HOL Guard blocked this output because it contains sensitive content.", but the app can still pass the output itself to the model. [Harness support](../harness-support.md) and the [Cline protection contract](../cline-local-protection-contract.md) cover each app's limits.

CIGAR adds to a prompt and takes nothing away: when it is on, each prompt you send gets the few parts of your project that match it, with the file and lines each part came from. CIGAR itself leaves your prompt, the chat and tool output as they are.

Never trimmed to save tokens, in any version:

- command, test and build output;
- file reads;
- search results;
- diffs;
- anything an MCP server returns.

## Getting the raw output

Guard does not keep a copy of output it blocks or cuts. The tool has already run by then, so running the command again repeats whatever it did. Rerun it yourself, in a terminal outside the AI app, only when it is safe to repeat, such as a read, a search or a test run. For a long output, send it to a file and open the file.

## Why Guard does not trim output to save money

Guard tested it. On 2026-11-05 a long six-step coding task was run five times per arm with and without a trial hook that trimmed test output, collapsed repeated diffs, capped search results and dropped repeated file reads. The trial hook was never shipped.

| Harness | Model | Paid per run, without | Paid per run, with trial hook | Change |
|---|---|---|---|---|
| Codex | gpt-6-luna, medium reasoning | $0.0518 | $0.0559 | +7.9% |
| Claude Code | claude-haiku-4-5 | $2.7878 | $2.7399 | -1.7% |

The hook cut the tool output the model saw (13% on Codex, 30% on Claude Code), but the bill hardly moved. Providers bill input they have already seen, a cached prefix, at a fraction of the full input price. Most of a long session's cost comes from how many model requests it makes and the fixed context each request re-reads, and a tool hook changes neither. On Claude Code only one run in five passed in each arm, so that row is not a clean comparison. The full table, prices and method are in the [long-task benchmark](../../benchmarks/cigar-long-task.md).

## What `hol-guard context lean` does to the bill

`hol-guard context lean` changes when Codex sums up the older turns of a long chat. It does not lower the bill and can raise it: after each summary Codex reads again, at full price, the files it had already read, and the summary itself is a paid model request. Use it when you want a shorter chat, not to save money. [Runtime controls](runtime-controls.md) describes the command.

## Seeing what each app used

`hol-guard context usage` prints, for today and the last 7 days, what Codex and Claude Code used on this computer. The dashboard's CIGAR **Usage** tab shows the same numbers. Add `--json` for the full data.

```text
$ hol-guard context usage
Model usage from each tool's own records on this computer, today and over the last 7 days.

Codex: 1 session
                                       Today         Last 7 days
  Input at full price                 54,600              54,600
  Input read from cache            2,164,800           2,164,800
  Input written to cache                   0                   0
  Output                              16,800              16,800
  Model requests                          12                  12
  Chat summaries                           1                   1

Claude Code: no sessions in the last 7 days.

Guard does not read usage records from Copilot, Cursor, Gemini, OpenCode or Pi, so they are not counted here.
```

Each row comes from the app's own usage record, not from an estimate:

- **Codex:** the `token_usage_record` entries in each session file under `~/.codex/sessions` (or `$CODEX_HOME/sessions`).
- **Claude Code:** the usage on each reply in each session transcript under `~/.claude/projects` (or `$CLAUDE_CONFIG_DIR/projects`). A reply Claude Code writes twice is counted once.

| Row | Meaning |
|---|---|
| Input at full price | Input the app reported as not read from the cache. This includes input sent again after the cache expired. |
| Input read from cache | Input the app reported as read from the provider's cache, billed at a fraction of the full price. |
| Input written to cache | Input stored for later reuse. Claude Code bills it above the full price; Codex reports none. |
| Output | Tokens the model wrote. |
| Model requests | Calls to the model. One prompt can make many. |
| Chat summaries | Times the app shortened the chat so it could keep going. |

The numbers count with CIGAR on or off, and Guard sends them nowhere. Guard keeps a local cache, `context-usage-meter.json` in the Guard home, holding for each session file of the last 7 days: its full path, how far Guard has read it, its per-day totals, its model and folder name, and, for Claude Code, the last 16 characters of up to 1024 reply ids so a reply written twice is counted once. Later counts then read only what was added. The first count reads every session from the last week and can take a minute on a long history.

Guard does not read usage records from Copilot, Cursor, Gemini, OpenCode or Pi. Their usage is left out rather than guessed.
