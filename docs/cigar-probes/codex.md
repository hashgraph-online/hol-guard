# Probe: Codex PreToolUse can wrap a shell command

Date: 2026-11-05. codex-cli 0.166.0, `codex exec`, model `gpt-6-luna`, medium reasoning.

Question: can a PreToolUse hook on the shell tool run the model's command
through a filter, so the model reads the filtered output?

Setup: a Codex home whose `config.toml` sets `features.hooks = true` and one
`PreToolUse` command hook (matcher `Bash`). The hook prints
`hookSpecificOutput.permissionDecision = "allow"` with `updatedInput.command`
set to a wrapper that runs the original command and prints its shaped output.
The wrapper writes a log line per command, so the log proves the hook ran.

| Check | Result |
|---|---|
| Hook trust entry keyed by the home path as written (`/tmp/...`) | hook never ran, no error |
| Hook trust entry keyed by the resolved path (`/private/tmp/...` on macOS) | hook ran for every shell command |
| `updatedInput.command` replaced | the rollout records the wrapper command, and the model reads the wrapper's output |

Findings:

- Codex keys `[hooks.state."<config path>:pre_tool_use:<i>:<j>"]` by the
  config file's resolved path. On macOS `/tmp` resolves to `/private/tmp`, so
  a trust entry written with the unresolved path is silently ignored. Guard
  must resolve the path before it writes the trust hash.
- The rewritten command is what Codex runs and records. This probe wrapped the command base64-encoded, so the bench's rollout
  classifier saw every call as `python`. A production wrapper should pass the
  command in clear text.
- PostToolUse was not probed; the plan shapes Codex output at PreToolUse only.
