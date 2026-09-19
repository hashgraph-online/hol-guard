# Policy delivery and recovery

Create and approve policy changes in Guard Cloud for the intended workspace.
Keep unpublished changes in draft until approval is complete. A valid signature
alone does not make a draft active.

## Verify application

Sync the device and inspect the reported policy status. Publication, delivery,
application, and runtime readiness are distinct states; a pending or failed
state must remain visible. Wrong-workspace, stale, expired, or invalid updates
are refused. A still-current verified policy remains effective after a refused
refresh.

Cloud exceptions are governed risk acceptances. The current runtime recognizes
artifact, publisher, harness, workspace, and global scopes. Availability in a
particular workflow is limited to the targets it advertises. Do not infer an
unsupported scope or target from a display label.

Remembered rules, Cloud exceptions, and strict settings have separate
purposes. Remembered rules apply only within their recorded scope. Evidence
records observations and outcomes; it does not grant policy authority. Exact
Cloud Review resolves one pending request. It does not create
reusable policy. Immutable blocks cannot be approved remotely. Check the
returned continuation result separately from approval; manual retry or an
unsupported continuation must not be presented as successful resumption.

## Recover delivery

1. Confirm that the intended change was published and that the device is
   connected to the correct workspace.
2. Sync again and retain the exact rejection or delivery status.
3. For a stale revision, fetch the current signed revision. Avoid copying
   cached policy material between devices.
4. Retry delivery with valid existing consent. Enable or renew consent
   explicitly when required.
5. Restore an unavailable runtime through the supported installation flow,
   then verify application and readiness again.

A well-formed, authenticated generic v2 document may omit its rollout state
for compatibility with already-published bundles. Explicit null, malformed
containers, and unpublished states do not use that compatibility rule.

Do not edit protected local state to recover a failed delivery. Current
precedence rules still apply: a broad Cloud rule does not silently override
an eligible, more-specific local decision.
