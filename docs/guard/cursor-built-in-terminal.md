# Cursor built-in terminal: design review

Status: proposed for review. Nothing on this page is implemented. The Cursor
`terminal` row in the [harness protection claims](harness-claims.md#cursor)
stays `unsupported` until a design is reviewed, its uninstall path is tested
and a live Cursor session shows Guard answering terminal commands.

## The gap

Cursor runs Guard's hooks for actions an agent takes: `beforeShellExecution`
for agent shell commands, `beforeMCPExecution`, `beforeReadFile` and
`preToolUse` for file writes. A command typed into Cursor's built-in terminal
is not an agent action. Cursor raises no hook for it, so Guard never sees it.

The gap matters in two cases:

- a person pastes a command an agent suggested in chat, instead of letting the
  agent run it through its hooked shell tool;
- a long-running process the agent started keeps running in a terminal tab
  after the agent turn ends, and later input to that tab reaches no hook.

Commands an agent runs through its own shell tool are not part of this gap.
They reach `beforeShellExecution` whichever terminal Cursor displays them in.

## Upstream boundary

Cursor's terminal follows the editor's integrated-terminal settings:

| Setting | What it changes | Can it stop a command? |
| --- | --- | --- |
| `terminal.integrated.profiles.<os>` and `defaultProfile.<os>` | Which shell starts and with what arguments | No. It runs once, when the tab opens. |
| `terminal.integrated.env.<os>` | Environment for new terminals | No. |
| Shell integration (OSC 633 marks) | Lets the editor see command start, end and exit code | No. It reports a command after the shell accepts it. |

None of these is a pre-execution event. Stopping a typed command therefore
needs code inside the shell itself, and each shell offers a different hook:

| Shell | Pre-execution hook | Can it refuse the command? |
| --- | --- | --- |
| zsh | a replacement for every widget that runs the line: `accept-line`, `accept-and-hold`, `accept-line-and-down-history` (Ctrl+O in the emacs keymap) and `accept-and-infer-next-history` | Yes, by not accepting the line; a widget left unreplaced runs the line unchecked |
| bash | `DEBUG` trap with `shopt -s extdebug` | Yes, a nonzero return skips the command |
| fish | `fish_preexec` event | No |
| PowerShell | PSReadLine `CommandValidationHandler` | Yes, by throwing |
| cmd.exe | none | No |

## Options

1. **Keep the row unsupported (recommended).** Guard installs nothing in the
   terminal. The dashboard and generated claims keep saying that commands typed
   into Cursor's built-in terminal bypass Guard. No shell profile bytes change.
2. **Observe only through shell integration.** Guard reads OSC 633 marks to
   record what ran. This records a command after it ran and cannot stop it, so
   the row could become `observe_only` at most. It needs an editor extension
   to read the marks, which Guard does not ship.
3. **A Guard-owned terminal profile.** Guard adds a `HOL Guard (zsh)` profile
   whose launch script loads the user's own rc files and then installs a
   pre-execution check that calls the native runtime. This is the only option
   that can stop a command.

## What option 3 would need before review

- **Profile ownership.** Guard adds one named profile and never edits an
  existing one. It sets `defaultProfile.<os>` only when the user asks, and
  records the previous value so uninstall can put it back.
- **No shell profile rewrites.** The launch script lives under Guard's home.
  Guard does not write to `~/.zshrc`, `~/.bashrc`, PowerShell profiles or any
  other user file. Acceptance is that Guard changes only what it owns: the
  Guard profile entry in `settings.json`, the launch script under Guard's home
  and, only when the user asked for it, `defaultProfile.<os>`, whose previous
  value Guard records. No other setting and no shell file changes.
- **Environment handoff.** The script passes the session's workspace and a
  `CURSOR_TERMINAL` surface marker to the runtime, so receipts name the
  terminal surface and do not count as editor or CLI evidence.
- **Conflict detection.** If the user's rc files already replace any of the
  zsh widgets that run a line, bind another widget that runs one, set a `DEBUG` trap or define a validation handler, the check
  stays out and `hol-guard doctor cursor` reports the terminal as unprotected
  rather than chaining or overriding the user's hook.
- **Failure behavior.** If the runtime cannot answer, the check must say so on
  the terminal and refuse the line, matching the editor hooks' fail-closed
  answer, with a documented way to open an unguarded shell.
- **Repair and uninstall.** Repair rewrites only the Guard profile entry.
  Uninstall removes it, restores `defaultProfile.<os>` if Guard changed it and
  leaves `settings.json` byte for byte as it was when nothing else changed.
- **Unsupported shells.** fish and cmd.exe cannot refuse a command. A profile
  for them would be observe-only and must be labelled that way, or not offered.

## Limits that remain under option 3

- The user can open any other terminal profile, or run `exec zsh`, and leave
  the check behind. A terminal profile protects the default path only, so the
  row could not claim more than `partial`.
- The check sees the line as typed. Aliases, functions and scripts the shell
  expands later are reviewed only as far as the native command parser reads the
  typed line.
- Remote and container terminals start their shells elsewhere and would not
  load the profile.
- Input to a program that is reading from the terminal goes to that program,
  not to the shell's line editor. A long-running process an agent started, or
  any interactive tool such as a REPL, receives later input unchecked, so the
  second case in [the gap](#the-gap) stays open under option 3.

## Recommendation

Keep option 1 and the `unsupported` row. The terminal is a person typing.
Agent shell commands, MCP calls, file reads and `preToolUse` file writes go
through Cursor's agent hooks; inline edits that bypass `preToolUse` and
cloud-agent actions are not covered (see
[harness claims](harness-claims.md#cursor) and the
[local and cloud contract](cursor-local-cloud-contract.md)). Option 3
adds shell code to a user-facing terminal for a path the user can step around,
so it should start only on a concrete request, after this page is reviewed, and
with its no-rewrite and uninstall tests written first.
