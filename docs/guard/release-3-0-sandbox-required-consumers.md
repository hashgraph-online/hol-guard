# `release/3.0` `sandbox-required` consumer matrix

Status: wave-zero baseline. Audience: execution-assurance gate reviewers. Source evidence snapshot: `origin/release/3.1` at `10348fd40fa53ef60d9363bb6c37591b8bb60a61`; release identity migrated to 3.0 and revalidated in PR #1901.

The canonical `sandbox-required` directive semantics and every consumer that reads it, with how each preserves directive semantics. The directive is terminal in the action lattice and is never lowered to `allow`.

## Canonical semantics

`action_lattice.py:5` defines the total order `allow < warn < review < require-reapproval < sandbox-required < block` (severity `"sandbox-required": 4` at `:37`). `:8-9` states `sandbox-required` additionally requires an enforceable sandbox and "must never collapse to `review`". `runtime/composition_rules.py:10` states `require-reapproval` and `sandbox-required` requirements are never lowered; the only composition downgrades are strong false-positive paths that lower `block → review` or `review → warn`, never `sandbox-required` (`composition_rules.py:108-121`).

## Consumer matrix

| Consumer | Area | File | Reads directive | Lowers to allow? |
| --- | --- | --- | --- | --- |
| Action lattice | core semantics | `action_lattice.py` | defines order + terminal guarantee | No |
| Composition rules | decision composition | `runtime/composition_rules.py` | never lowered | No |
| Effect decision | decision engine | `runtime/effect_decision.py` | enforces in effect plan | No |
| Decisions | decision engine | `runtime/decisions.py` | enforces | No |
| Runner | execution | `runtime/runner.py` | routes to containment | No |
| Hook handlers | pre/post-tool | `cli/commands_hook_{claude,copilot,generic,runtime_eval,runtime_finish,runtime_review,github_workflow}.py` | enforce before tool runs | No |
| Approvals | approval queue | `approvals.py`, `approval_resolution.py`, `runtime/approval_reuse.py` | sandbox-required not auto-approvable | No |
| MCP | tool calls | `mcp_tool_calls.py`, `proxy/runtime_mcp.py`, `proxy/stdio.py` | enforce on MCP path | No |
| Receipts | evidence | `store_receipts.py`, `incident.py` | record verbatim, never rewrite | No |
| Adapters | harness payloads | `adapters/{cursor_hook_payload,cursor_hook_script_template_head,grok_hooks,pi_hooks,zcode_hooks}.py` | pass through to harness | No |
| Persistence | schema | `store_command_shadow_schema.py`, `models.py`, `types.py` | store verbatim | No |
| CLI support | payload/policy | `cli/commands_support_{hook_payload,interaction,prompts,runtime_policy}.py`, `cli/render.py` | render/pass through | No |
| Supply chain | package eval | `local_supply_chain.py`, `runtime/supply_chain_package_eval.py`, `runtime/command_permission_catalog.py`, `runtime/secret_file_requests.py` | enforce on package path | No |
| Advisory escalation | escalation | `runtime/advisory_escalation.py` | can raise, never lower | No |
| Dashboard | UI display | `daemon/static/assets/*` (js) | display only | No (read-only) |
| Schemas | product model | `schemas/guard_product_model_v1.json` | declares value | No |
| Consumer service | orchestration | `consumer/service.py`, `decision_boundaries.py`, `harness_usage.py` | enforce at boundary | No |

## Downgrade audit

No consumer lowers `sandbox-required` to `allow`. The only downgrade paths in the codebase are the false-positive composition rules in `runtime/composition_rules.py:108-121`, which produce `review` or `warn` from `block`/`review` respectively and structurally cannot produce `sandbox-required` or lower it. The lattice guarantees `sandbox-required` is strictly stronger than `review` and never collapses to it.

## Notes

- This matrix records consumer semantics as of the pinned ref; it does not authorize changing the lattice order.
- Dashboard JS consumers are display-only and carry no enforcement authority.
