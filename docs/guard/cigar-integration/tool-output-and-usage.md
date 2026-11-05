# Tool output and usage

This page answers three questions: does Guard change what your AI app sees from its tools, how do you get the raw output, and how much did each app actually use.

## What Guard does to tool output

Guard does not shorten, summarize or rewrite tool output. After a tool runs, Guard's hook either passes the output to the AI app exactly as the tool returned it, or blocks all of it. It blocks output only when the output contains a secret, such as an API key or a private key. The app then sees "HOL Guard blocked this output because it contains sensitive content." in place of the output. Guard never hands the app a cut-down version.

CIGAR adds to a prompt and takes nothing away: when it is on, each prompt you send gets the few parts of your project that match it, with the file and lines each part came from. Your prompt, the chat and the tool output reach the app unchanged.

Never shaped, in any version:

- command, test and build output;
- file reads;
- search results;
- diffs;
- anything an MCP server returns.

## Getting the raw output

Because Guard does not trim output, what the app saw is what the tool returned. When Guard blocks output for a secret, it does not keep a copy. To see the output, run the same command yourself in a terminal outside the AI app.

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
| Input at full price | Input the provider had not seen before in this chat. |
| Input read from cache | Input the provider had already seen, billed at a fraction of the full price. |
| Input written to cache | Input stored for later reuse. Claude Code bills it above the full price; Codex reports none. |
| Output | Tokens the model wrote. |
| Model requests | Calls to the model. One prompt can make many. |
| Chat summaries | Times the app shortened the chat so it could keep going. |

The numbers count with CIGAR on or off, and Guard sends them nowhere. Guard keeps how far it has read each file, the per-day totals, and each session's model and folder name in `context-usage-meter.json` in the Guard home, so later counts read only what was added. The first count reads every session from the last week and can take a minute on a long history.

Guard does not read usage records from Copilot, Cursor, Gemini, OpenCode or Pi. Their usage is left out rather than guessed.
