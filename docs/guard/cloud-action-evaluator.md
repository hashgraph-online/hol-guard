# Cloud Action Evaluator

`guard-cloud-action` is a stateless native decision authority for hosted actions. A hosting service sends it one
JSON line per action and gets one JSON line back: may this exact action be dispatched now, and if not, why.

It decides. It does not dispatch, store, or remember anything between requests.

## Contract

- The evaluator holds only what it was started with: an admitted binding set and, optionally, the public key that
  verifies workspace activations. Everything else arrives in the request.
- The hosting service owns identity, authentication, consent storage, budgets, and revocation. The evaluator
  never looks them up. It trusts none of them beyond what the request carries and the checks below.
- A request names an action. It never supplies that action's effect, digests, or required restrictions. Those come
  from the admitted binding, so a caller cannot give an unknown action the meaning of a known one.
- Input is read strictly. Duplicate object keys, nesting deeper than 32 levels, numbers that are not integers in
  the IEEE-754 safe range, and arguments larger than 64 KiB are rejected, not repaired.
- The decision is deterministic. The same request line gives the same result.
- Every failure is a result with `action: "block"` and `dispatch_permitted: false`. The process never exits on a
  bad request and never panics on input.

## Running it

```
guard-cloud-action --binding-set <path> [--activation-public-key <64 hex characters>]
```

Each option falls back to an environment variable: `GUARD_CLOUD_ACTION_BINDING_SET` and
`GUARD_CLOUD_ACTION_ACTIVATION_PUBLIC_KEY`. A flag wins over its variable.

The process exits with status 2 and writes one code to standard error if the binding set cannot be read or admitted
or the key is not 32 bytes of hex. It answers no request in that case. Otherwise it reads newline-terminated JSON
from standard input and writes one result line per request line, in order. A line longer than 4 MiB produces an
error result with code `limit`; the rest of that line is discarded and the loop continues. Blank and malformed
lines get an error result too, so results always line up one-to-one with requests.

## Binding sets

A binding set (`guard.cloud-action-binding-set.v1`) lists the actions the evaluator knows. Each binding
(`guard.cloud-action-binding.v1`) fixes:

- `action_id`: `<provider>.<segment>[.<segment>...]`, lowercase ASCII, digits, `_` and `-`;
- `adapter`: kind (`native-connector` or `remote-mcp`), identity, provider, and input schema;
- `effect`: `read`, `write`, `destructive`, or `admin`;
- `resource`: optionally the top-level argument whose string value names the resource;
- `remote_mcp`: required for `remote-mcp` adapters and forbidden otherwise, with an `https://` URL and tool name;
- `required_capabilities`: restrictions the hosting target must enforce. Every binding must include
  `egress-pinned` and `bounded-output`. The others are `resource-allowlist`, `provider-idempotency`,
  `no-filesystem`, and `no-subprocess`.

Any invalid binding rejects the whole set. A partially admitted set would silently drop restrictions. Duplicate
actions, unknown fields, an unsupported schema, and a non-HTTPS remote MCP URL are all rejections.

The set has a digest (`binding_set_digest`). Each request must echo the digest of the set the hosting service
believes is loaded, so a service and an evaluator running different sets fail closed instead of disagreeing.

## Request

Schema `guard.cloud-action-evaluation.v1`. All fields are required, and unknown fields are rejected.

| Field | Meaning |
| --- | --- |
| `schema` | `guard.cloud-action-evaluation.v1` |
| `request_id` | Caller's correlation label, echoed in the result |
| `evaluated_at` | UTC time, `YYYY-MM-DDTHH:MM:SSZ`, used to check activation validity |
| `binding_set_digest` | Digest of the binding set the caller expects |
| `principal` | `workspace_id`, `subject_id`, `client_grant_id` |
| `connection` | `connection_id`, `provider`, `account_digest` (64 lowercase hex characters) |
| `action` | `action_id` and `arguments` (a JSON object) |
| `target_capabilities` | Capabilities the hosting target actually enforces for this call |
| `policy` | `snapshot_id` and `rules` |
| `saved_consents` | Up to 256 `{consent_id, kind: "once" \| "always", action_identity_sha256}` entries |
| `activation` | A signed workspace activation, or `null` |

Labels (`request_id`, ids, `snapshot_id`, rule ids) are printable ASCII with no spaces, up to 256 characters.

A policy rule is `{rule_id, action, match}`. `action` is any Guard action. `match.action_id` is an exact action id,
a `<prefix>.*` family that matches whole dot-separated segments, or `*`. `match.connection_id` and
`match.resource_id` optionally narrow the rule and must match exactly. A request carries at most 4096 rules.

## Result

Schema `guard.cloud-action-evaluation-result.v1`.

| Field | Meaning |
| --- | --- |
| `request_id` | Echo of the request's label |
| `action` | `allow`, `warn`, `review`, `require-reapproval`, `sandbox-required`, or `block` |
| `dispatch_permitted` | `true` only for `allow` and `warn` |
| `review_eligible` | The action is a review that no saved consent has answered |
| `reason_codes` | Why, in the order the steps below applied |
| `matched_rule_ids` | The policy rule that decided, if any |
| `required_capabilities` | What the binding requires |
| `missing_capabilities` | Required capabilities absent from `target_capabilities` |
| `consent_applied` | `none`, `once`, or `always` |
| `consent_id` | The consent that was applied, or `null` |
| `action_identity_sha256` | Digest of this exact action, the key saved consents are stored under |
| `execution_identity_digest` | Digest of the admitted binding that would run |
| `evaluation_provenance_digest` | Digest of the program, binding set, policy snapshot, and activation behind the decision |
| `engine` | Evaluator `version` and request `contract` |

Reason codes are `effect_floor`, `policy_rule`, `admin_effect_unsupported`, `catalog_mcp_extension`,
`global_lockdown`, `capability_unavailable`, `saved_consent_once`, and `saved_consent_always`.

An error result has only `schema`, `request_id` (the caller's label if the request got far enough to read one,
otherwise `null`), `action: "block"`, `dispatch_permitted: false`, and `error: {"code": ...}`.

## Precedence

1. **Intake.** Strict parse, schema version, field shape, labels, and limits.
2. **Binding.** The set digest must match, the action must be admitted, and the connection's provider must be the
   binding's provider.
3. **Arguments.** Canonicalized and bounded. The binding's resource argument must be present and well formed.
4. **Activation.** If present, it is verified (see below). Failing verification is an error, never ignored.
5. **Policy.** An `admin` effect is always `block`, whatever a rule says. Otherwise a matching `block` rule beats
   every other matching rule. Then the most specific matching rule wins: an exact action beats a family, a longer
   family prefix beats a shorter one, and a matching connection or resource narrows further. A tie goes to the
   more severe action. With no matching rule, the effect floor applies: `read` allows, `write` reviews,
   `destructive` requires reapproval.
6. **Catalog tightening.** For a `remote-mcp` binding, a packaged catalog entry for that server can raise an action
   to `review` or `block`. It never lowers one.
7. **Lockdown.** A verified activation with `global_lockdown` blocks every action. Nothing after this step
   lowers it.
8. **Target capabilities.** If the binding requires a capability the target does not enforce, anything below
   `sandbox-required` becomes `sandbox-required`.
9. **Saved consent.** A consent whose `action_identity_sha256` equals this action's identity turns `review` or
   `require-reapproval` into `allow`. It never lowers `block` or `sandbox-required`, and it does not apply to
   an action that already allows. When both kinds match, `always` is reported.

Severity runs `allow`, `warn`, `review`, `require-reapproval`, `sandbox-required`, `block`.

## Action identity

`action_identity_sha256` is a domain-separated SHA-256 over the workspace, connection, account digest, action id,
the binding's execution identity, and the canonical arguments. Arguments are RFC 8785 canonical JSON for the
accepted subset: keys sorted by UTF-16 code units, minimal string escapes, integers only. Strings are compared by
exact code points with no Unicode normalization, so two spellings that look alike are two actions.

Changing an argument, the account, the connection, the workspace, or the binding changes the identity and voids any
saved consent. The principal's subject, grant, the request id, and the time do not.

## Workspace activation

An external catalog extension takes effect only if a workspace activation enables it. An activation is
`{payload, signature}`: a `guard.cloud-workspace-activation.v1` payload and a base64 Ed25519 signature over its
canonical bytes, verified against the public key given at startup. The payload names the workspace, the catalog
digest, `global_lockdown`, per-extension `enabled`/`disabled` controls, and an `issued_at`/`expires_at` window.

An activation fails closed: a bad signature, a different workspace or catalog, an expired or not-yet-valid window,
unknown fields, or no configured key is an error. A `disabled` control for an extension always beats an `enabled`
one. The window is half-open: valid at `issued_at`, expired at `expires_at`. This layer is accepted only by this
evaluator and does not change device-side controls.

## Error codes

| Code | Meaning |
| --- | --- |
| `malformed` | Not valid JSON, trailing data, or `arguments` is not an object |
| `duplicate_key` | An object repeats a key |
| `too_deep` | Nesting deeper than 32 levels |
| `unsupported_number` | A non-integer, an exponent, or an integer outside +/-(2^53 - 1) |
| `too_large` | Canonical arguments over 64 KiB |
| `unsupported_version` | Request schema is not `guard.cloud-action-evaluation.v1` |
| `invalid_request` | Unknown or missing field, bad label, timestamp, digest, rule, or resource argument |
| `limit` | Too many rules, consents, or activation controls, or a request line over 4 MiB |
| `binding_unavailable` | `binding_set_digest` is not the loaded set's digest |
| `action_unknown` | No admitted binding for the action |
| `connection_mismatch` | The connection's provider is not the binding's provider |
| `activation_key_unavailable` | An activation was sent but no key was configured |
| `activation_invalid` | Bad signature or payload, or a malformed activation |
| `activation_unsupported_version` | Activation payload schema is not supported |
| `activation_mismatch` | Activation is for another workspace or catalog |
| `activation_expired` | Outside the activation's validity window |
| `program_unavailable` | The packaged command program could not be loaded |

## Hosting service obligations

**Treat every error as do-not-dispatch.** An error result is always `block`, but a service must not depend on
reading `action`. Dispatch only when the result parses, has the expected schema and `request_id`, carries no
`error`, and has `dispatch_permitted: true`. A closed pipe, a missing line, a timeout, or a result it cannot parse
also means do not dispatch.

Also:

- Send `target_capabilities` that the target really enforces. Overstating them defeats the sandbox check.
- Apply the returned action as the decision for exactly the arguments that were evaluated, and dispatch those
  bytes, not a re-serialization that could differ.
- Keep consent records and consume a `once` consent after it is used. The evaluator does not.
- Record `evaluation_provenance_digest` and `action_identity_sha256` with the decision.
- Restart the evaluator, and reload the binding set digest, whenever the binding set changes.
