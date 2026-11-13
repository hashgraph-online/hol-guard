# Cloud Policy Presets

A workspace picks one of three presets for hosted actions: `relaxed`, `balanced` (the default) or `strict`. Each
preset is a policy pack in `contributions/cloud-policy-packs/`, compiled into the runtime and validated when it
loads. A preset decides a call only from the facts its action pack extracted; it never reads arguments itself.

## What a policy pack holds

| Field | Meaning |
|---|---|
| `schema` | Always `guard.cloud-policy-pack.v1`. |
| `preset` | `relaxed`, `balanced` or `strict`. Every rule id starts with this name and a dot. |
| `windows` | Counters a rule may bound, with their length in seconds (at most 30 days). |
| `unclassified` | The action for a call no admitted pack describes, and for one whose name reads as destructive. |
| `rules` | Fact rules in the evaluator's wire form, each with the risk family it covers and a one-line summary. |
| `workspace_rules` | Rules a workspace must add itself because they need its own data, such as trusted domains. |

The loader refuses a pack whose schema it does not know, whose rule ids repeat or lack the preset prefix, whose
rules bound an undeclared window, whose rules carry more than four or repeated obligations, or whose unclassified
action is weaker than `review`. A destructive-looking name is never treated more leniently than any other name.

The pack digest is a domain-separated hash of the canonical document, so a decision can name the exact preset bytes
that produced it.

## How a call is decided

The evaluator joins the preset's rules with the workspace's own rules and takes the strictest match. A call no rule
matches gets its effect's default: reads allow, writes review, destructive actions need re-approval, and admin
actions block. The effect is the stricter of the action's declared effect and the effect of its class. A missing
counter counts as past its limit, and an unknown count, environment or sensitivity counts as the risky value.

| Family | Relaxed | Balanced | Strict |
|---|---|---|---|
| R1 Permanent delete | review | review; re-approval for everything in scope or 50+ records | block |
| R2 Recoverable delete | allow | allow up to 25 records and 100 per hour, else review | review |
| R3 Database or table destroy | re-approval | block in production, else re-approval | block |
| R4 Update | allow | allow under 100 named records, else review | review by effect |
| R5/R6 Send | allow | review outside the workspace or to 20+ people | review by effect |
| R7 Public share | review | review; block for confidential data | block |
| R8 Named share | allow | review outside the workspace | review by effect |
| R9 Export | allow | allow up to 10 MiB and 1,000 records | review by effect |
| R10 Money out | review | review | block |
| R12 Secret in arguments | review | block | block |
| R13 Untrusted read, then egress | warn | review | block |
| R14 Injection signal, then destructive | review | re-approval, including a recoverable delete | block; re-approval for a recoverable delete |
| R15 Repository and deploy changes | review | review; block branch delete and force push | block |
| R16 Unclassified action | review | review; re-approval for a destructive name | block |

`review by effect` means the preset has no rule for the family, so the write default applies.

## Unclassified actions

A tool with no admitted pack entry is treated as a `write` and labelled Unclassified. The name classifier
(`cloud_action_classifier.rs`) splits the tool name on separators and camel case, matches verbs and verb-noun pairs
such as `delete`, `purge`, `transfer ownership` and `api key`, and proposes the strictest class it finds. An input
schema with an amount and a currency proposes `pay`. Upstream annotations such as `readOnlyHint` are ignored. The
proposal can only tighten: its floor is `update`, and the preset's `unclassified` action applies on top.

`contracts/cloud-actions/classifier-corpus.json` lists the names the classifier is tested against and the class each
must receive.

## Running the tools

`hol-guard-runtime cloud-action pack` answers two preset operations; see
[Cloud Action Packs](cloud-action-packs.md#running-the-tools):

```
{"op": "policy", "preset": "balanced"}
{"op": "classify", "name": "deleteRepository", "preset": "strict"}
```
