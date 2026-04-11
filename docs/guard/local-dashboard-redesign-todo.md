# Local Dashboard Redesign Todo

## Product Reset

- Replace the marketing-style hero with a clear blocked-session status banner.
- Make the first line answer: what got stopped, in which harness, and why.
- Make the second line answer: what the user needs to decide right now.
- Remove any surface that explains Guard abstractly before it explains the blocked request.

## Information Architecture

- Rebuild the page into three primary regions:
  - queue
  - current request
  - decision console
- Keep raw JSON/API links in a clearly secondary advanced area.
- Promote the currently selected blocked request above generic status metrics.
- Show only one dominant request in focus at a time.

## Queue UX

- Change queue cards to lead with “Guard stopped this launch.”
- Translate policy actions into human-readable statuses.
- Show whether the item is first seen or changed since last approval.
- Show package/skill/MCP server type in plain language.
- Show the recommended action and the narrowest safe trust scope inline.

## Request Detail UX

- Add a top summary card:
  - what got stopped
  - why it was stopped
  - whether the session is still waiting
- Replace generic panels with:
  - what changed
  - why Guard cares
  - what was previously trusted
  - what happens if you allow or block
- Move raw identifiers, config paths, and command strings into an advanced disclosure section.

## Decision Console

- Replace the generic scope picker with an explicit rule builder.
- Mark one scope as Guard-recommended.
- Explain each scope in consequence language, not taxonomy language.
- Show a live preview of the exact rule that will be saved.
- Show whether the rule is local-only or will sync later.
- Hide the workspace path field unless workspace scope is selected.
- Rename actions to:
  - Allow and resume
  - Block and keep stopped

## Visual Design

- Use the portal chrome, but switch the content body to a developer-console layout.
- Reduce headline scale and remove decorative marketing rhythm.
- Increase hierarchy between:
  - status
  - evidence
  - action
- Use fewer cards with stronger visual grouping.
- Remove nonessential labels and repeated explanatory copy.
- Keep the page readable in one viewport on a normal laptop.

## Developer Clarity

- Add a compact “How this works” explanation only after the current request details.
- Explain the difference between:
  - this version
  - this workspace
  - this publisher
  - this harness
  - global trust
- Explain first-seen versus changed-since-trusted explicitly.
- Explain that Guard is protecting against malicious or unexpectedly changed packages, skills, and MCP servers.

## Advanced Areas

- Move raw receipt data into an advanced drawer or disclosure.
- Move review commands into an advanced drawer or disclosure.
- Move raw config paths into an advanced drawer or disclosure.
- Keep debug and API affordances available, but visually secondary.

## Runtime Integration

- Surface whether the session is waiting for this approval now.
- Surface whether approving here will resume the harness immediately.
- Keep the daemon as the production backend.
- Keep Vite demo mode as the UI iteration path.
- Ensure `/brand/*` assets are served by the daemon.

## Verification

- Rebuild the dashboard bundle after the redesign.
- Review the Vite `?demo=1` UI visually at desktop width.
- Review the daemon-served UI visually with real queue data.
- Re-run the focused approval and runtime pytest coverage.
- Re-run scanner lint, build, and targeted verification before pushing PR updates.
