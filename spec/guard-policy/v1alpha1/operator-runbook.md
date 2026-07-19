# GuardPolicy operator runbook

## Scope

This runbook covers validation, import, capability-gated bundle activation, observation, and rollback for `guard.hashgraphonline.com/v1alpha1`. It does not authorize a stable-schema claim or a production package release.

## Preconditions

- Keep bundle v1 available for clients that do not advertise bundle v2 support.
- Keep `HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT` at `0` or `legacy` until shadow comparison is clean.
- Confirm the client advertises the required policy schema, bundle, signature, acknowledgement, rollback, and snapshot capabilities.
- Retain the active legacy bundle plus canonical last-known-good and previous-good bundles.
- Use bounded, aggregate metrics. Do not record policy documents, commands, prompts, paths, or secrets.

## Validate a candidate

```bash
hol-guard policy validate ./guard-policy.yaml --json
hol-guard policy fmt ./guard-policy.yaml --check --json
hol-guard policy diff ./guard-policy.yaml --json
hol-guard policy import ./guard-policy.yaml --merge --dry-run --json
```

Treat any parse, schema, semantic, signature, hash, downgrade, or unsupported matcher result as a stop condition. Resolve the document at its source; never weaken validation to make a candidate importable.

## Apply a local document

Use merge when the candidate intentionally augments current local policy. Use replace only when the candidate is a complete authoritative document.

```bash
hol-guard policy import ./guard-policy.yaml --merge --apply --json
```

After import, export the effective policy and compare its canonical digest with the validated candidate:

```bash
hol-guard policy export --output ./effective-policy.yaml --json
hol-guard policy validate ./effective-policy.yaml --json
```

## Capability-gated bundle rollout

1. Serve byte-identical bundle v1 to clients without complete v2 capability support.
2. Send signed bundle v2 only when schema, signature, acknowledgement, rollback, and snapshot capabilities intersect.
3. In shadow mode, validate and cache bundle v2 while continuing to enforce legacy decisions.
4. Require a successful v2 acknowledgement with the expected version, hash, sequence, device, and workspace before promotion.
5. Compare canonical and legacy decisions by bounded reason code. Zero unexplained mismatches is the promotion gate.
6. Set `HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT` to an integer from `1` through `99` for a deterministic workspace-and-device cohort. `true`, `on`, `canonical`, and `100` enable every eligible client.
7. Expand only after the observation window remains inside the stop conditions below.

## Observe

Track aggregate counts and rates for:

- canonical conversion attempted, succeeded, and incompatible;
- shadow match and mismatch by reason code;
- sync latency, retry exhaustion, queue depth, and dead letters;
- client capability and selected bundle version;
- signature, hash, transition, and acknowledgement failures;
- last-known-good fallback and rollback activation.

Stop expansion on any unexplained decision mismatch, invalid signature acceptance, anti-downgrade failure, acknowledgement sequence regression, repeated activation, loss of last-known-good state, or sensitive metric value.

## Release boundary

This alpha release is promoted only by merging the Guard change into `release/3.1` and verifying its published alpha artifact against that release branch. It must not merge directly into `main`, publish a stable release, or enable canonical enforcement by default. Those actions belong to the later consolidated V3 release.
