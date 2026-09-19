# HOL Guard Desktop bootstrap contract

Status: Guard 3.x local contract

## Command

```bash
hol-guard desktop bootstrap --json
```

The command is a machine-readable projection for the separately distributed HOL Guard Desktop application. It is not an enforcement API. HOL Guard Core remains the sole authority for detection, policy, approvals, receipts, managed app state, daemon state, and Cloud coordination.

## Schema

The top-level `schema` value is:

```text
guard-desktop-bootstrap.v1
```

Desktop must reject unknown schema identifiers and Core versions outside its declared compatibility range. It must never infer a protected state when the command fails, times out, returns malformed JSON, or reports an incompatible version.

## Included data

The projection contains only bounded product state needed to render the native shell:

- Core version and compatibility status
- Local runtime availability
- Aggregate protection posture
- Managed app identifiers and managed-state summaries from the local store
- Aggregate approval counts and bounded generic approval rows
- Aggregate receipt counts and bounded generic receipt rows
- Optional Cloud connection state
- Whether the canonical dashboard can be launched

## Excluded data

The projection must not contain:

- Guard root credentials or daemon authentication material
- Daemon root tokens or reusable OAuth credentials
- OAuth access or refresh tokens
- Authorization headers
- Raw prompts, command text, tool payloads, or file contents
- Local filesystem paths, Guard home, workspace paths, or shim paths
- Raw approval risk summaries that may contain commands, hosts, or paths
- Raw receipt evidence or action envelopes

The Desktop native process invokes the contract with fixed arguments and a bounded timeout. The startup response may include `dashboard.sessionUrl`, a Core-issued scoped dashboard capability used only for the local handoff. The startup WebView receives that URL through the native bridge. Keep it out of logs, diagnostics and exports; it is distinct from daemon root credentials and OAuth tokens.

## Runtime adoption

`runtimeSource` is descriptive, not authoritative. An active compatible local runtime is reported as `adopted_running`; otherwise a compatible installed Core is reported as `external`. Desktop may bundle an exact Core release later, but it must still use this contract and must not start a second daemon when an authenticated compatible runtime is already active.

## Failure behavior

Desktop must display an unavailable or attention-required state when:

- the Core executable cannot be resolved;
- the command exceeds the Desktop timeout;
- stdout exceeds the Desktop output limit;
- JSON parsing or schema validation fails;
- the Core version is outside the supported range; or
- Core reports that its local runtime is unavailable.

No failure path may be converted into a green or protected state.

## Operational refresh

`hol-guard desktop status --json` uses the same versioned projection and adds no policy authority. It reads current local operational state without calling the dashboard session launcher or starting/adopting a daemon. Its `dashboard` object never contains a session URL. `observedAt` records when this projection was collected; `statusReadSupported: true` advertises this additive command on both bootstrap and status results. Older supported Core versions may omit these fields. Desktop must keep their last known sample age and show unavailable live detail, rather than mark a reused startup sample freshly checked.

Status opens the existing SQLite store in a single read-only transaction. It does not initialize or recover the database, reconcile receipt rollups, create a local device identity, repair OAuth storage, promote secrets, or prompt for Keychain access. Missing or damaged storage fails with a bounded setup/recovery instruction. Startup and explicit account actions retain their existing repair behavior. The connection and policy evidence share the same database snapshot, so a concurrent account switch becomes visible on the next sample.

Passive OAuth health validates the existing current-format local credential vault. A missing, inaccessible, mismatched or legacy-only vault needs the normal foreground account check; status does not migrate it. Receipt summaries reuse clean rows and project missing or dirty rows through Core's existing canonical decision helper without modifying them. Dashboard availability follows the authenticated local endpoint observation; a live process without a usable authentication token is unavailable.

The optional Cloud fields `policyBundleVersion`, `policyBundleHash` and `policyRolloutState` describe the currently validated cached bundle. `appliedRevision` and `policyLastAckAt` are present only for a validated `applied` acknowledgement matching that bundle's hash, version, current workspace and current runtime device identity using the existing strict generic ACK contract. The revision comes from the matched signed payload metadata. Managed Controls application remains unknown until exact delivery and the current protected resident projection can both be proved. The current canonical enforcement lane must also be enabled; a historical ACK remains historical after a flag change. They describe Core's local application evidence, not a new Cloud acknowledgement or remote fleet proof. Missing, legacy, unrelated, invalid or received-only acknowledgement data leaves application unknown. No connection or transport timestamp becomes application evidence.

The approval preview remains bounded to 20 generic local request rows. The exact request IDs support Desktop notification deduplication; the preview does not represent the separate Cloud exact-review queue. Desktop must not log those IDs or private request data.
