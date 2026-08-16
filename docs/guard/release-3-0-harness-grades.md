# `release/3.0` harness ownership grades

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

Every supported harness classified by execution-ownership grade: `guard_owned_local`, `host_decision_only`, `observe_only_degraded`, or `unsupported`. `delegable_remote` is a post-MVP capability and no harness is graded for it in this baseline. Grade is derived from the adapter's `approval_tier` and the presence of an enforceable local hook surface.

## Grade definitions

- `guard_owned_local` — Guard intercepts the action and can enforce (block/require approval) before the harness executes it.
- `host_decision_only` — the harness makes the enforcement decision; Guard supplies the decision payload but cannot itself block execution.
- `observe_only_degraded` — Guard records evidence/receipts but cannot influence execution; cannot satisfy mandatory assurance.
- `unsupported` — no enforceable surface exists for mandatory assurance.

## Harness matrix

| Harness | Adapter | `approval_tier` | Hook surface | Grade | Returns provider results? | Mandatory assurance? |
| --- | --- | --- | --- | --- | --- | --- |
| Codex | `adapters/codex.py:947` | `native-or-center` | pre/post-tool hooks, shims, daemon (extensive) | `guard_owned_local` | No (local decision) | Yes |
| Claude Code | `adapters/claude_code.py:157` | `native-or-center` | preToolUse permission + prompt notification hooks | `guard_owned_local` | No (local decision) | Yes |
| Copilot CLI | `adapters/copilot.py:329` | `native-or-center` | preToolUse + permissionRequest repo hooks | `guard_owned_local` | No (local decision) | Yes |
| Cursor | `adapters/cursor.py:39` | `native-harness` | hook config + native approval bridge | `guard_owned_local` | No (local decision) | Yes |
| Pi | base default (`adapters/base.py:119`) | `approval-center` | no enforceable hook surface in adapter | `observe_only_degraded` | No | No |
| OpenCode | `adapters/opencode.py:71` | `mixed` | no post-execution surface; pre-hook only | `observe_only_degraded` | No | No |
| Antigravity | `adapters/antigravity.py:23` | `approval-center` | no enforceable hook surface in adapter | `observe_only_degraded` | No | No |
| Gemini | `adapters/gemini.py:23` | `approval-center` | minimal hook surface | `host_decision_only` | No | Conditional |
| Grok | `adapters/grok.py:70` | `approval-center` | hook config present | `host_decision_only` | No | Conditional |
| Kimi | `adapters/kimi.py:51` | `approval-center` | hook config present | `host_decision_only` | No | Conditional |
| ZCode | `adapters/zcode.py:68` | `approval-center` | hook config present | `host_decision_only` | No | Conditional |
| Hermes | `adapters/hermes.py:167` (managed tier `:341` = `native-or-center`) | `approval-center` (managed: `native-or-center`) | file inspection + managed hooks | `host_decision_only` (managed path: `guard_owned_local`) | No | Conditional |
| OpenClaw | `adapters/openclaw.py:41` (managed tier `:212` = `native-or-center`) | `approval-center` (managed: `native-or-center`) | managed hooks | `host_decision_only` (managed path: `guard_owned_local`) | No | Conditional |

## Failure modes

- Hook daemon failure is fail-closed only in `strict` fail mode: `commands_hook_generic.py:558-563` tightens the action to `block` when `daemon_status` is a failure status and `fail_mode == "strict"`. Non-strict fail modes preserve the current composed policy action rather than silently approving, and unknown action spellings remain fail-closed through the normalizer (`commands_hook_generic.py:147`).
- Harnesses graded `observe_only_degraded` or `host_decision_only` cannot satisfy mandatory assurance: Guard cannot unilaterally block execution there. This is an accepted alpha limitation consistent with the compatibility matrix.
- Fail-open adapters (those that would approve on hook error/timeout) cannot satisfy mandatory assurance. In the current tree the generic hook path tightens to `block` under `strict` fail mode and otherwise preserves the composed action instead of defaulting to `allow`.

## Notes

- Grades reflect the current `approval_tier` field and hook surface, not marketing claims. `approval-center` means approvals route through the Guard approval center; it does not by itself imply local execution ownership.
- No harness is graded `delegable_remote` in this baseline; remote delegation is a separately gated post-MVP capability.
