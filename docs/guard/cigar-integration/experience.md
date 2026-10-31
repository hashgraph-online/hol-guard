# Context assistance screens and controls

Guard's primary user is a developer or operator moving between an AI harness, terminal, and approval center. They need to understand a pause and continue their work with little ceremony. The [product principles](../../../PRODUCT.md) favor calm language, clear consequences, local control, and honest execution status.

Call the feature **Context assistance**. Show **Powered by CIGAR** and its version in details. Graphs, tickets, epochs, and retrieval traces belong in diagnostics where they support a real decision.

## Information architecture

Extend the existing screens instead of adding a permanent CIGAR workspace to the sidebar.

| Existing location | Addition | User question answered |
| --- | --- | --- |
| Home | Small assistance status and link to settings | Is assistance on and ready? |
| Settings → Protection | Context assistance section and setup flow | Do I want it, and what does it use? |
| Apps → app detail | Workspace/source scope and permission to expose context tools | What can this app receive? |
| Review detail | Context brief, citations and relevant changes | Why did Guard pause this, and what should I inspect? |
| Evidence → action detail | Context association, source versions and comparison | What evidence informed the explanation? |
| Settings → Data & repair | Clear context data and feature diagnostics | How do I stop, inspect or repair it? |

Use the existing Settings section shell and row primitives. Keep the six current settings tabs; link to a subsection within Protection. The existing Approval gate tab stays focused on password, app code, cooldown and approval checks.

## Setup and Python availability

Keep a visible but disabled feature row on unsupported machines so users can understand why it is unavailable. A disabled switch alone is insufficient. Put a readable explanation and a working **Check again** or **Choose Python** action beside it. Setup and diagnostics can be available while execution capability remains unavailable.

| State | Suggested copy | Available action |
| --- | --- | --- |
| No selected Python 3.14 | “Context assistance requires Python 3.14 on this machine.” | Choose Python; installation instructions; Check again |
| Selected Python 3.13 or 3.15 | “The selected Python is 3.13. Choose Python 3.14 to use context assistance.” | Choose Python |
| Eligible Python, package absent | “Python 3.14 is ready. Install the CIGAR package to continue.” | Inspect the version/platform and install plan, then explicitly install |
| Candidate not available for public installation | “CIGAR 0.14.1 is awaiting release qualification.” | View status; recheck availability |
| Ready, off | “Use local context to add sources and clearer explanations to reviews.” | Set up context assistance |
| Enabled | “Context assistance is on for the selected apps and workspaces.” | Manage access; Turn off |
| Runtime lost or verification failed | “Context assistance is unavailable. Guard is still running.” | Recheck runtime; repair verified package |
| Organization prohibits the feature | “Context assistance is disabled by your organization.” | Show policy owner and reason when available |

These messages describe the selected runtime on the machine running Guard. A dashboard opened on a phone or another browser must show the Guard host's capability, not the browser's environment.

After eligibility is established, use a three-step setup:

1. **What it helps with.** Show one example brief with explicitly illustrative content. Explain that existing Guard approvals continue to apply.
2. **What it can use.** Select apps/workspaces. Start with current native policy facts and sanitized receipt facts. Additional workspace documents require explicit selection. Preview source categories and exclusions.
3. **Enable.** Show local memory behavior and resource preset. Offer **Enable context assistance** and **Cancel**. Use the existing settings write protection where its policy applies; do not invent another password flow.

Feature enablement is separate from installing software. A missing package never triggers an invisible installation or changes the system's default Python. Reuse the existing Guard installation and verification experience for any explicit package action.

## Settings screen

```text
Protection / Context assistance

Context assistance                         [ Off ]
Add sources and clearer explanations to Guard reviews.

Availability       Python 3.14 ready · CIGAR package needed
                   [Review installation] [Choose Python]

Used by            Selected apps and workspaces
                   [Manage access]

Review briefs      On when assistance is enabled
Agent context      Off       [Learn what an app receives]
Shared agents      Off       [Set up after enabling agent context]

Resource use       Balanced  [Low memory] [Balanced] [Custom]
Data retention     Memory only; cleared when the service stops
                   [Manage data]

                   [Advanced details]
```

The values above are a wireframe state, not current product telemetry. Keep the switch disabled until the host reports a ready capability. Group advanced controls under a disclosure, and show whether a value is organization-managed.

Use plain resource descriptions, with actual measurements only when observed: number of active workspaces, admitted data size, worker count, and measured memory if the platform can provide it. Do not label a cache hit or graph count as an action made safe.

Turning off stops new assistance jobs, withdraws tools, revokes CIGAR scopes/grants, and closes its workers. It does not remove the user's Guard approvals. Offer a separate **Clear saved context** action when persistence has been explicitly enabled; explain what will be removed before applying it.

## App and workspace access

Add a Context assistance section to the existing app detail view. It should list:

- Apps/workspaces selected by the user and their effective source access.
- Which workspace documents have been added, with exclusion reasons and last refresh state.
- Whether the app may call read-only context tools.
- Whether independent agents may share a host-controlled graph.
- Any organization restriction, with its source and scope.

Global enablement alone does not grant every app access. New apps/workspaces start unselected. A repository configuration cannot turn on the feature or widen the user's grants; it can request a narrower scope or offer suggested documents for review.

For cooperating agents, display readable client names, permitted source categories, lease status, recent activity, and **Revoke access**. Show the effective scope before issuing access. Never show broker connection secrets or offer a “copy token into your prompt” shortcut.

## Review detail

Keep the native action, reason, consequences, and approval controls in their current hierarchy. Add an optional brief below the reason. Load it independently so that a slow graph does not hold the review or move the action buttons.

```text
Review action                                  Claude Code
Guard paused an operation that changes a package installation.

Requested action
  [Existing exact command and native risk display]

Context brief                         Sources current
  The prior receipt covers another dependency revision. [1]
  The selected workspace policy describes this install step. [2]

Inspect before deciding
  Compare the changed dependency revision and the package script.
  [View 2 sources] [Compare with previous receipt]

  [Allow once] [Always allow] [Block]
```

This is illustrative copy; the real brief must be generated from verified facts for the current request. Avoid a green “safe” badge, truth percentage, automatic approval recommendation, or an assertion that a previous allow authorizes different bytes.

**View sources** opens a drawer with source name/category, permitted excerpt and line range, observation time, currentness, and the native action association. Redact private paths consistently. A source path must not become an unrestricted file-open or external navigation capability.

**How sources were selected**, inside advanced details, may show available retrieval signals and tokenizer identity. The CIGAR trace cannot explain rejected candidates or prove factual truth, so do not create a “why every other source was ignored” view.

If assistance is pending, show “Preparing additional context…” in its panel. If it fails, show “Additional context is unavailable” with an optional retry. Keep the native reason visible and approval controls usable. A stale source marks the brief stale and withdraws its claims until refreshed; it never disables an otherwise supported Guard approval.

A suggested alternative should first be presented as copyable text or an explicit proposal back to a capable harness. Do not label it “Run safely.” Guard must evaluate the actual new tool call, and the UI must accurately distinguish approved, requested, dispatched, and execution confirmed.

## Evidence and comparison

Extend the existing action detail rather than creating a separate audit database UI.

```text
Evidence / Action detail

Execution status       [Existing native receipt status]
Context assistance     Brief generated · 2 permitted sources

Sources used            Version         Current state
Native policy facts     [revision]      Current
Selected manifest       [revision]      Changed since this brief

[Compare source revisions] [View retained brief]

Advanced
  Context snapshot · tokenizer · feature version
  [Export redacted diagnostics]
```

Keep historical and current claims separate. A retained historical brief can remain viewable as historical evidence after an update, but cannot be presented as the current recommendation. Label whether the source text is retained; a digest-only receipt cannot reproduce deleted text.

A revision comparison should show changed/removed source facts, scope or policy changes, and the native action relationship. It must not imply CIGAR can replay a model's hidden reasoning or prove an external effect occurred. Ordinary local graph use does not include Honey's full replay runtime.

Aggregate counts may include briefs served, unchanged-source reuse, stale results rejected, and assistance availability. Savings estimates need an explicit measured baseline. Never present “tokens saved” as a reduction in total model prompt size when only snapshot transport deltas were measured.

## Data, repair, and model settings

In Data & repair, add **Clear context cache**, **Clear saved context** when applicable, and **Export context diagnostics**. Existing receipt clearing and context clearing are separate actions with clear scopes. Removing a selected source also withdraws it from current contexts and invalidates affected views.

Diagnostics can show the selected runtime version, package/core version, worker verification, capability availability, queue status, bounded errors, and when the last check ran. Treat local executable paths as private details; exports contain redacted identifiers and counts. Recovery uses approved, matching artifacts, not a worker integrity bypass.

A later optional model-assisted explanation control must specify the provider, source categories disclosed, cost behavior, and independent reviewer requirement. Reuse existing cloud/provider configuration when appropriate. Local compilation does not require an account, API key, embedding service, or model subscription.

## Accessibility and behavior acceptance

Use existing primitives and WCAG AA targets. Every unavailable control needs adjacent accessible text. Keep setup, source drawers and confirmation dialogs keyboard operable; restore focus when they close. Announce availability changes politely without moving focus or repeatedly interrupting the user.

Maintain source-access controls and approval choices at narrow screen widths. Do not encode stale/current or enabled/unavailable only by color. Respect reduced motion, reserve space for incremental brief loading, and avoid modal chains during approval. Turning assistance off should have a clear result even when its worker has already failed.
