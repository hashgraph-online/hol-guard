# Command Activity Dashboard Information Architecture

## Purpose

Command activity is local evidence that Guard evaluated a command. It is not a threat feed. A rule match, policy decision, and execution proof are separate facts and must remain separate in data flow, copy, and presentation.

## Surface Map

### Evidence: Commands

- Route: `/evidence?view=commands`.
- The existing Evidence workbench owns the surface; Commands is not a second top-level navigation item.
- Commands remains reachable when receipt evidence is empty because command activity and receipts have independent lifecycles.
- The surface owns command list, analytics, extension, filter, pagination, detail, feedback, health, and invalidation state.

### App Activity: Command Protection

- Route: `/apps/{harness}?tab=activity&activity=commands`.
- Activity contains three modes: Recorded actions, Command protection, and Pending reviews.
- Command protection queries the server with the exact harness filter. It does not download global data and filter it in the browser.
- Execution-proof language is harness-specific. Harnesses without strong post-execution proof remain explicitly unconfirmed.

### Home: Commands Checked

- The summary appears only when `commands_checked` is greater than zero.
- It states the analytics window and evidence health.
- Loading, unavailable, and zero states omit the card. They do not claim that Guard checked zero commands.
- Degraded health states that counts may be incomplete. Analytics health is not a substitute for overall protection health.

## Data Flow

1. The authenticated dashboard client requests bounded activity, analytics, and extension pages.
2. Strict normalizers rebuild allowlisted domain objects. Unknown fields never pass through to view state.
3. Filters serialize to validated query parameters. Signed page cursors remain opaque and in memory.
4. Filter changes clear cursor history and stale page data.
5. Authenticated fetch streaming receives ID-only invalidations. A reset event discards cached pages and refetches bounded state.
6. Feedback writes one fixed label for an activity ID. Feedback never changes policy automatically.
7. Clear-evidence uses the existing high-risk confirmation flow and invalidates all command state after success.

## State Ownership

| State | Owner | Persistence |
| --- | --- | --- |
| Evidence view and command filters | URL state | Browser history |
| Signed page cursors | Commands workbench | Memory only |
| Selected activity ID | URL state | Browser history |
| Activity and analytics payloads | Commands workbench | Memory cache |
| Invalidation cursor | Commands workbench | Memory only |
| Feedback mutation state | Activity detail | Request lifetime |
| Approval proof for deletion | Clear modal | Request lifetime |

## Copy Contract

- Use "command activity", "command checked", "rule match", and "review".
- Never call an allow, monitor event, or rule match a threat, attack, or incident.
- Present `Decision` and `Execution proof` as separate labeled facts.
- Render `allowed_unconfirmed` as "Allowed; execution not confirmed".
- Do not infer protection from low prompt volume, high allow volume, or analytics health.
- Top extensions and rules describe frequency, not danger.

## Accessibility Contract

- Commands uses keyboard-complete tabs with an accessible tablist label, roving focus, `aria-controls`, and stable panel IDs.
- Filters have persistent labels and report result updates through a polite live region.
- Loading, empty, degraded, and error states do not move focus automatically.
- Detail drawers and destructive confirmation modals return focus to their trigger.
- Reduced motion disables nonessential chart and invalidation transitions.
