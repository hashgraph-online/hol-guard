# Claude Code tool results after they run

Claude Code calls Guard's `PostToolUse` hook after a tool has finished. For
Claude Code's built-in tools (Bash, Read, Grep, Write, Edit and the rest), the
result has already reached the model by the time Guard sees it. This page says
what Guard can and cannot do at that point, so no message, receipt or claim
promises more than happened.

## States

Guard records each Claude Code `PostToolUse` answer in exactly one of these
states. The receipt fields are `decision` and `model_output_action`.

| State | When | What Claude Code and the model see | Receipt |
| --- | --- | --- | --- |
| Observed | Guard reviewed the result and found nothing to act on. | The original result. Guard adds nothing. | `decision: allow`, `model_output_action: allow_original` |
| Flagged after delivery | Guard found sensitive content, such as a credential, in a result the model already has. | The original result, then Guard's note: Guard flagged the output after Claude Code had received it, could not withhold it, and the model should not repeat, quote, summarize or store the sensitive parts. Claude Code labels this note a hook "blocking error"; the turn continues. | `decision: deny`, `model_output_action: not_applicable` |
| Replaced | Not available for Claude Code. Guard does not rewrite a Claude Code tool result, so a reviewed excerpt is never shown in place of the original. | — | never recorded for `claude-code` |
| Withheld | Not available for Claude Code. A `PostToolUse` hook cannot take back a built-in tool result Claude Code already delivered. | — | never recorded for `claude-code` |
| Unavailable | Guard could not finish the review (the native runtime or the Guard service was down, timed out, or the input was malformed). | The original result. The turn continues, as [ADR 0009](adr/0009-native-and-daemon-critical-failure.md) requires: the tool already ran, so stopping the turn would not undo it. | no decision receipt; the hook reports the failure instead |

Guard still masks a flagged result in its own records. The output is not
copied into receipts, activity or evidence; only its digest, the rule ID and
the reason code are kept.

## Why there is no withholding state

A `PostToolUse` reply with `decision: "block"` gives Claude Code a reason to
show the model. Claude Code does not remove the tool result it has already
added to the conversation. A live check on Claude Code 2.1.325 confirmed this:
the model received the complete Bash output and Guard's note after it.

Before this page, Guard told Claude Code that it had "blocked this output" and
recorded `model_output_action: block`. Both described a withholding that never
happened. Guard now records `not_applicable` for a flagged Claude Code result
and words the note as a flag on content already delivered. Other harnesses keep
their own semantics; a harness whose hook runs before the model reads the
result can still withhold it.

## What protects secrets in Claude Code

`PostToolUse` cannot stop a secret from reaching the model, so prevention
happens before the tool runs. `PreToolUse` review stops reads of known
credential files and commands that print secrets, and that is where Guard's
Claude Code protection claim for secrets rests. The generated harness claims
list Claude Code `PostToolUse` as observe-only for the same reason.

## Scope

This page covers Claude Code's built-in tools. Claude Code lets a hook replace
an MCP tool's output; Guard does not use that capability, so MCP tool results
follow the same states above until a replacement path is built and
qualified.
