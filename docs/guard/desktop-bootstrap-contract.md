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
- Detected app identifiers and managed-state summaries
- Aggregate approval counts and bounded generic approval rows
- Aggregate receipt counts and bounded generic receipt rows
- Optional Cloud connection state
- Whether the canonical dashboard can be launched

## Excluded data

The projection must not contain:

- Guard root credentials or daemon authentication material
- Browser or Desktop session tokens
- OAuth access or refresh tokens
- Authorization headers
- Raw prompts, command text, tool payloads, or file contents
- Local filesystem paths, Guard home, workspace paths, or shim paths
- Raw approval risk summaries that may contain commands, hosts, or paths
- Raw receipt evidence or action envelopes

The Desktop native process invokes the contract with fixed arguments and a bounded timeout. Browser JavaScript receives only the already-projected response and never receives Core credentials.

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
