# Protection Center Local Tools

Protection Center is exposed under **Modules** while the existing **Protect** area remains the general protection-health surface. Compatibility routes remain `/extensions` and `/extensions/:id`.

## Test Lab

Test Lab is a local, side-effect-free explanation tool. It evaluates a bounded command against the current extension-control runtime without executing it.

The Test Lab contract requires that:

- the command is not executed through a shell or subprocess;
- the command is not persisted to Activity, receipts, approvals, memory, or settings history;
- the command is not uploaded to Guard Cloud;
- the daemon response does not echo the raw command;
- request and response sizes are bounded;
- the request uses the authenticated local daemon transport;
- command inputs and example selectors are locked while evaluation is in flight so the displayed result cannot drift from the command that was evaluated.

Test Lab returns the local decision, controlling protection metadata, bounded safe matches, and safer alternatives. It does not create a second enforcement path. Dashboard regression coverage enforces the in-flight input lock so a completed result remains bound to the command the user actually checked. Test Lab validation failures use the same bounded daemon error and recovery envelope as the rest of the extension-control API, without creating a dependency on the mutation service.

## Settings history

Local settings history is read from the authenticated extension-control authority transition chain. Guard validates the chain before returning historical entries.

Choosing an earlier entry does not immediately roll back settings. Protection Center takes only the historical **device** layer and prepares it as a draft against the current revision. The current organization-managed layer remains in force. The user must review **What will change** and complete the normal proof-bound approval and apply flow before anything changes.

This preserves the same stale-revision, proof-binding, approval, and managed-policy invariants as an ordinary settings edit.

## Settings integrity repair

When the authority is tampered or recovery is required, Protection Center may offer guided repair. Repair uses the existing local approval gate and authority recovery implementation. It must not mutate the authority database directly or create a weaker recovery path.

## Cloud boundary

These local tools are not subscription features. Local evaluation, blocking, Test Lab, settings history verification, and repair continue to operate independently of Guard Cloud availability. Cloud can add continuity and coordinated history, but it does not decide whether local protection runs.
