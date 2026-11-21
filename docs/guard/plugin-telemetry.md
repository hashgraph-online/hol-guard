# Plugin install counts

Plugin authors listed on HOL can see how many Guard users have their plugin installed. Guard sends these counts only after you turn them on, and it sends nothing about you or your machine.

```bash
hol-guard telemetry plugins on                  # start weekly counts
hol-guard telemetry plugins send --dry-run      # print what would be sent, without sending
hol-guard telemetry plugins status
hol-guard telemetry plugins off                 # stop and delete the device key
```

## What is sent

Once a week, the Guard daemon downloads the public HOL listing index and the native runtime matches the plugins installed under `~/.claude` (or `$CLAUDE_CONFIG_DIR`), `~/.codex` (or `$CODEX_HOME`), `~/.gemini` and `~/.cursor` against it on your machine. A plugin is matched only by the repository in its manifest, never by its homepage or name alone. Guard first keeps only the index entries for repositories its installed plugins declare; that list stays on your machine. The report lists, for each matched plugin:

| Field | Example |
|---|---|
| `slug` | the public HOL listing |
| `runtime` | `claude-code`, `codex`, `gemini` or `cursor` |
| `version` | the installed plugin version |
| `key` | `HMAC-SHA256(device key, "<week>:<slug>:<runtime>")` |

The report also carries the ISO week and the Guard version. Nothing else is sent: no user, machine, path, hostname or workspace identifier. Plugins that are not public HOL listings are never included.

The device key is 32 random bytes stored in the Guard home with owner-only permissions, and it never leaves the machine. Because the key is mixed with the week, listing and runtime, the counting keys differ for every week, listing and runtime, so a key alone cannot be matched to another week or another listing. The keys do not hide everything: one report carries all of a machine's matched listings in a single request, so those listings arrive together, and an unusual set of listings and versions could be recognized again in a later week. HOL stores each listing as its own row and uses the keys only to count distinct installs. `off` deletes the key, so turning counts on again starts an unrelated series.

HOL does not store the sender's IP address with a report, keeps reports for 13 weeks, and never shows a count below 10 installs.

## When reports are sent

The daemon checks every six hours and sends at most one report per ISO week, only while counts are on. `send` sends this week's report immediately; `send --dry-run` builds the report, with a throwaway key if counts are off, and prints it.

## Update prompts

`hol-guard plugin updates` lists installed plugins that have a newer release checked on HOL, the releases plugin authors record with the HOL Plugin Release workflow. It is separate from install counts and works whether counts are on or off.

```bash
hol-guard plugin updates                                   # list newer checked releases
hol-guard plugin updates --json
hol-guard plugin updates dismiss <slug> --version <latest> # hide one prompt until a newer release
hol-guard plugin updates reset                             # show dismissed prompts again
```

Guard downloads the public listing index and the public release index, and the native runtime compares the installed versions with them on your machine. Nothing about your installed plugins is sent. A prompt is marked urgent when a newer release fixes a high or critical scanner finding, or when the installed release had one. Dismissals are stored in `plugin-updates.json` in the Guard home and apply only to the version you dismissed.
