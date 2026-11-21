# Probe: Claude Code PostToolUse can replace what the model sees

Date: 2026-11-05. Claude Code 2.1.292, `claude -p`, model `claude-haiku-4-5-20251001`.

Question: can a PostToolUse hook change the tool result the model reads, for
the built-in Bash and Read tools?

Setup: a settings file passed with `--settings` holding one PostToolUse
command hook (matcher `Bash|Read`). The hook logs the event it receives and
prints `hookSpecificOutput.updatedToolOutput` carrying a marker string. The
model is asked to run a command (or read a file) and quote what the tool
returned.

| Tool | `updatedToolOutput` value | Model quoted |
|---|---|---|
| Bash | a plain string | the real output (string ignored) |
| Bash | the `tool_response` object with `stdout` replaced | the marker |
| Read | the `tool_response` object with `file.content` replaced | the marker, numbered from `file.startLine` |

Findings:

- The replacement must keep the tool's own result shape. For Bash that is
  `{stdout, stderr, interrupted, isImage, noOutputExpected}`; for Read it is
  `{type: "text", file: {filePath, content, numLines, startLine, totalLines}}`.
  A bare string is dropped without an error.
- The hook gets the full raw result in `tool_response`, so the raw text can be
  kept for recovery before the model sees the shorter one.
- Read output is shown to the model with line numbers added after the hook,
  so a replacement for Read should be plain file text or a one-line note.
