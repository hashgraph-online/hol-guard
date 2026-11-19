# Codex file edits and tool results

This page records what Codex's hooks let Guard see and change for file edits
and tool results, the Codex version each statement was checked on, and what
Guard records as a result. The generated harness claims in
[harness-claims.md](harness-claims.md) remain the source of support status;
nothing here promotes a claim.

## File edits

Codex applies the model's file changes through its `apply_patch` tool. Guard's
Codex hook matcher sends `apply_patch` to `PreToolUse`, and Guard reads the
target paths from the patch headers before the change is written.

Checked on Codex CLI 0.169.0 (macOS, `codex exec` with approvals and sandbox
bypassed, a disposable Codex home and a probe hook in place of Guard):

| Question | Result |
| --- | --- |
| Do model file changes arrive as hook events? | Yes. Adding, updating, moving and deleting a file each arrived as a `PreToolUse` and a `PostToolUse` event for `apply_patch`, with the patch in `tool_input.command`. No file changed without an event. |
| Does a `PreToolUse` deny stop the write? | Yes. The file was not created, and the model reported the refusal. |

Guard therefore treats Codex file edits as an upstream tool event, not as a
direct edit that needs detection after the fact. Two limits remain:

- An edit that a future Codex version applies without an `apply_patch` call
  would not reach Guard. The contract keeps this as a known blind spot.
- Guard installs its Codex `PostToolUse` hook for `Bash`, `Read` and MCP tools
  only, so the written result of an `apply_patch` call is not observed.

With Guard itself in place of the probe, a targeted Gauntlet run on Codex CLI
0.169.0 drove three pinned write cases (a client secret, a hidden instruction
for the next session, a `postinstall` script) through `apply_patch`. Guard
denied each patch before it ran and no target file was written. That run used
a lane change still under review; release qualification does not drive Codex
write cases yet, so the `apply_patch` row stays `configured`, not qualified.

## Tool results

Codex runs `PostToolUse` after a tool finishes and before the model reads its
result. A reply with `decision: "block"` replaces the result with Guard's
reason. Checked on Codex CLI 0.169.0 with the same probe setup: a shell
command printed a marker, the hook blocked the result, and the model received
only the hook's reason, never the marker.

| State | When | What the model sees | Receipt `model_output_action` |
| --- | --- | --- | --- |
| Observed | Guard found nothing to act on. | The original result. | `allow_original` |
| Withheld | Guard found a credential or instructions aimed at the agent. | Guard's reason in place of the result. | `block` |
| Withheld, too large to scan | The output was too large to scan in full within local limits. | Guard's reason, which says the output was withheld. | `block` |
| Replaced with a reviewed excerpt | Not available for Codex. The block reply carries only the reason, so an excerpt cannot be shown in place of the result. | — | never recorded for `codex` |
| Unavailable | Guard could not finish the review. | The original result; the tool already ran. | no decision receipt; the hook reports the failure |

Before this page, Guard recorded `replace_with_reviewed_excerpt` for oversized
Codex output and told the model it had "returned a reviewed excerpt", while
Codex showed the model only that sentence. Guard now records `block` and says
the output was withheld.

The contract still lists Codex `PostToolUse` as observe-only: the probe used a
stand-in hook, and no Guard qualification lane checks what the model receives
after a Codex `PostToolUse` block.
