# GuardPolicy v1alpha1 semantics

`GuardPolicy` is the portable semantic source. Portal graph state is editor metadata; signed Cloud bundles and local SQLite rows are compiled projections. A projection MUST reject a rule it cannot represent without changing meaning.

## Action compatibility

| Canonical effect | Portal `GuardPolicyRule` | Cloud bundle v1 | Local `PolicyDecision` | Classification |
|---|---|---|---|---|
| `allow` | `allow` | `allow` | `allow` | Lossless when scope is representable |
| `block` | `block` | `block` | `block` | Lossless when scope is representable |
| `review` | `review` | `review` | `review` | Lossless; remains an approval gate, never downgraded to `warn` |
| `ignore` | `ignore` | `ignore` | no row | Lossless inert projection; never compiled as `allow` |

Runtime-only actions are not rule effects: local `warn`, `sandbox-required`, and `require-reapproval`; bundle default `warn`; and changed-hash `warn`/`require-reapproval`. They remain typed defaults or legacy runtime results. Importing one as a rule effect is unsupported.

## Status, mode, rollout, and lifetime

- Portal `active`/`disabled` maps losslessly to `enabled: true/false`.
- Cloud modes `observe`, `prompt`, and `enforce` map losslessly to `spec.defaults.mode`.
- Cloud rollout states map losslessly to `spec.rolloutState`.
- `once`, `session`, `project`, `machine`, `workspace`, `team`, and `permanent` preserve Portal review durations. `30d` and `90d` normalize to `until` plus an absolute UTC `expiresAt` at creation time.
- A local null `expires_at` maps to `permanent`; a non-null UTC expiration maps to `until`. Consumed local one-shot approvals map to `once` but remain execution state rather than durable policy rows.
- `until` requires `expiresAt`. Every other mode has a null or omitted `expiresAt` and MUST NOT invent an expiration.

## Matcher compatibility

| Canonical matcher | Existing projection | Classification |
|---|---|---|
| `actors` | Portal `actor` | Lossless |
| `harnesses` | Portal `harness`; Cloud `harnesses`; local `harness` | Lossless |
| `tools`, `paths`, `repositories`, `commands`, `mcps`, `skills`, `packages`, `domains`, `secretTypes` | Corresponding Portal scope | Lossless in Portal; Cloud/local compiler MUST reject unless its fixed matcher-family projection is exact |
| `agents`, `devices`, `ecosystems`, `environments`, `locations` | Corresponding Cloud bundle scope | Lossless |
| `artifacts`, `publishers`, `workspaces` | Local artifact/publisher/workspace decision keys | Lossless for exact singleton values; multi-value rules fan out deterministically |
| `browserIntents`, `browserOperations`, `browserProfiles`, `origins`, `pathPrefixes`, `sensitiveSurfaces` | Portal browser scope and Cloud browser scope | Lossless in signed bundle; unsupported in SQLite because a row would broaden the rule |
| `operations` | Cloud matcher families (`file-read`, `mcp`, `mcp-tool`, `package-request`, `prompt`, `prompt-env-read`, `tool-action`) or a typed Portal operation such as `package.install` | Lossless only through an explicit registered mapping; unknown operations are unsupported |
| empty `match` | Global rule | Lossless; an empty individual matcher array is invalid |

Cloud bundle v1 uses singular browser keys and plural fleet keys. The canonical adapters use the plural names in the schema and MUST perform a named field mapping; unknown keys never pass through as core matchers.

## Defaults compatibility

`defaultAction`, `unknownPublisherAction`, `changedHashAction`, `newNetworkDomainAction`, `subprocessAction`, `telemetryEnabled`, and `syncEnabled` preserve the current signed bundle values. Portal defaults that do not exist in bundle v1 are unsupported until capability negotiation. Local SQLite has no independent defaults projection.

## Provenance

Provenance is immutable semantic data. Suggested Memory emits `source: suggested-memory`, stable `receiptIds`, `suggestionId`, `createdAt`, and `createdBy`. User export MAY redact IDs but MUST record that redaction in an `x-*` extension. Raw secrets, credentials, authorization headers, and secret values are forbidden; `secretTypes` contains categories only.

## Merge and identity

Files are never merged implicitly. An explicit import assembles an ordered effective set, then fails if any rule ID appears more than once, including byte-identical rules. Document IDs identify documents; they do not scope rule IDs. Rule order is presentation order and does not resolve conflicts.

Suggested Memory rule IDs are deterministic from immutable suggestion identity plus the semantic rule digest. Retries reuse the same ID. Editing content does not silently mint a second rule.

## Current runtime precedence (frozen)

This representation release does not change runtime precedence:

1. An eligible local one-shot approval is atomically claimed first.
2. Active persisted rows are ordered by scope: artifact, workspace, publisher, harness, global.
3. Within workspace/harness/global, an artifact-constrained row precedes an unconstrained row.
4. Remaining ties use `updated_at` descending. Source is not a tie-breaker: a local and remote row at the same specificity follow the same timestamp rule.
5. Expired rows do not participate. Integrity-invalid local rows are skipped; a valid next candidate may win.
6. A signed Cloud `block` or `review` does not receive absolute priority over a more-specific or newer local `allow`; changing that rule requires a separate safety contract.

The decision fixtures freeze exact-vs-broad, active-vs-expired, once-vs-permanent, and local-vs-remote outcomes. Compilers and representation changes MUST preserve them.

## Extensions

An object may contain keys matching `x-[a-z0-9][a-z0-9.-]{0,62}`. Extensions are preserved and participate in canonical hashing/signing. Core enforcement ignores them unless both producer and consumer negotiated that extension contract. An unnegotiated extension cannot affect matching, action, precedence, or lifetime.
