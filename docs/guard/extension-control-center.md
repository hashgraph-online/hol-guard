# Extension Control Center

The Extension Control Center is the canonical local security subsystem behind the user-facing **Protection Center**. The product UI describes extensions as protection modules and starts with local protection status, what needs attention, and the next safe action. Canonical extension IDs, permission IDs, detector rules, authority health, and provenance remain available through Advanced and Developer disclosure without becoming the default mental model.

Control semantics, precedence, migration rules, and non-goals are defined in [ADR 0004](adr/0004-extension-control-center-semantics.md). The daemon registry and protected extension-control authority remain the source of truth; the dashboard does not maintain a parallel policy registry.

## Routes

- `/extensions` — Protection Center overview
- `/extensions/:extensionId` — canonical protection-module detail route
- legacy allowlisted detail/query state remains compatible where supported

Only bounded view state belongs in the URL. Dashboard sessions, approval secrets, proof IDs, command text, and local paths do not.

## Presentation model

Protection Center uses three presentation densities over the same canonical data and enforcement contracts:

- **Simple** — local status, protection areas, modules in use, recommended protections, recent redacted decisions, and safe next actions.
- **Advanced** — troubleshooting, explicit protection controls, rule/capability explanations, and local policy configuration.
- **Developer** — canonical IDs, rule metadata, provenance layers, digests, and other implementation details needed for debugging or integration work.

A protection-module detail page starts with plain-language scope, behavior, examples, and recent privacy-safe decisions. `Change settings` opens the existing proof-bound local settings editor, while canonical identifiers and detector metadata stay behind Developer disclosure.

Changing presentation density never changes policy or daemon requests. The installed-browser contract also verifies the settled layout at 320, 390, 720, 800, 1024, and 1440 CSS pixels, including the 720-pixel equivalent of a 1440-pixel display at 200% browser zoom, with no horizontal page overflow. Installed policy verification reopens the settings editor after an apply or restore so the UI proof confirms the daemon's refreshed effective state rather than relying on stale DOM state.

## Recommended settings in the Approval Center

When Guard pauses a command that a built-in command extension already covers, such as `git add` under Git protection, the request page can recommend the matching extension setting. The card names the extension and command, links to the exact pattern on the extension page, and offers **Approve & always allow**, which sets that permission to Allow and then approves the current request.

- Guard shows the card only when allowing the listed permissions (at most three) would actually let that exact command run. It decides this when the request is queued, by re-checking the same command against the same evidence with those permissions allowed. Commands that would still need review for any other reason, such as secret-file reads, uncertain parsing, or native blocks, get no card.
- The daemon re-checks the recommendation each time the request page loads. The card disappears when the permission is already allowed, when an organization-managed control or an extension-wide disable applies, under Emergency Lockdown, or when the extension catalog has changed.
- The one-tap action uses the normal extension-control preview and apply flow. It needs healthy protection settings and a configured approval password or authenticator, so an agent cannot grant itself the setting. Without an approval gate, the card links to approval setup instead. If protection settings need attention, it shows only the link to the extension page.
- Destructive, critical, or sensitive permissions (for example `git push --force` or `git reset --hard`) still offer the one-tap action, but the card and confirmation show an explicit caution first.
- Guard saves the setting first. If the proof or the save fails, nothing is approved. If the setting saves but the approval fails, the card says so, and the request stays open for a normal decision.
- Only new matching commands are affected. Other requests that are already pending stay pending.
- Hosted dashboard origins never receive the recommendation. Links carry only extension and rule identifiers, never command text.

The same change is available from the terminal with `hol-guard command controls set <permission-id> --state allow`.

### Connectors that need setup

A request held only because Guard does not recognise the local CLI it launches (for example a user-installed `lanectl`) records which connector it waits on instead of an extension hint. The request page then carries a `connector_recommendation` (`guard.approval-connector-recommendation.v1`) naming the connector and its Protect page (`/extensions/local-cli/<cli-id>`).

- The daemon re-checks it on every read: the request is still pending and in the connector's `connector:<identity-hash>:` group, the stored connector still has the same identity and is still `unset`, and Emergency Lockdown is off. Once the connector is allowed, blocked or forgotten, the recommendation disappears.
- `status` is `available` only with healthy protection settings and a configured approval gate; otherwise it is `authority_unavailable` or `approval_gate_required`.
- `caution` is set when any pending request in the same connector group carries a destructive, credential, exfiltration or similar risk class.
- The recommendation is read-only. Setting the connector up goes through the same local-CLI preview, one-use proof and apply flow as Protect. Hosted dashboard origins never receive it, and agent-facing text never carries its link.
- `setup_href` opens that Protect page on this request (`?setup=<request-id>&identity=<identity-hash>`); the page offers the pre-filled setup only while the stored connector still has that identity and no decision.
- `setup_request` is a pre-filled body for that same endpoint (`state: "allowed"` plus `connector_group_request_id`). The dashboard adds the revision, approval credentials and session nonce; nothing else can set a connector to `allowed`.
- When an `allowed` apply names `connector_group_request_id`, the daemon resolves the pending rows of that connector's group after the write saves, through the existing bulk approve-once path. The approval gate is checked again and the resident's bulk eligibility still applies, so a row it rejects stays pending. The id must belong to the group, and a `blocked` apply cannot carry it. If the group cannot be resolved, the setting stays saved and the rows stay pending.
- Every row the bulk path approves runs the existing continuation for its own agent: Codex rows get the `approvals resume` binding, and other harnesses get the same retry text as `hol-guard approvals retry-hint`. The response's `connector_group.continuation` is the one for the request the setup started from.
- `GET /v1/local-clis?identity=<identity-hash>` lists only the connector with that exact identity and no seeded profile rows, so a Protect deep link never shows a changed binary as the one that was held.

## Local and Cloud boundary

Local Guard remains the enforcement authority on the device. Local interception, policy evaluation, approvals, local receipts, recovery, Test Lab evaluation, and current-device protection do not depend on a paid Cloud plan. Guard Cloud adds continuity, synchronization, durable history, advanced evidence/search, and team or organization coordination without redefining whether the local device is protected.

## Safety invariants

- detector severity and minimum protection floors are immutable from the dashboard
- local settings cannot weaken signed organization blocks
- Emergency Lockdown remains dominant
- authority failures remain fail-closed
- mutations use server-side preview plus an exact one-use approval proof
- stale revisions or catalogs must be reviewed again rather than silently rebased
- command text and local paths are never placed in URLs or Cloud marketing telemetry