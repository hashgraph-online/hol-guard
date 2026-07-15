# Command Extension Architecture

## Status and scope

This document defines the target contract for Guard command safety extensions. The schema-v2 registry and canonical command model currently preserve compatibility with existing action and risk classes while rule-level evaluation migrates behind them. Extensions detect and explain command facts; Guard's existing policy, approval, memory, and receipt systems retain decision authority.

## Parse-once command model

Each harness adapter extracts a command and declares its input boundary before parsing:

- **Dialect:** `posix`, `powershell`, `cmd`, `argv`, or `unknown`.
- **Transport:** shell string, argument vector, or embedded script.
- **Provenance:** harness, event, extraction method, workspace/source scope, and whether text was direct or reconstructed.

The parser boundary produces one immutable `CanonicalCommand` per request. The complete contract carries normalized text, cwd and platform context, security-relevant command-local environment overrides, parse confidence, wrapper chain, source spans, embedded scripts, and ordered segments. Segments preserve separators, pipeline position, executable/path source, subcommands, flags, operands, redirects, and execution-versus-data context.

Consumers receive this model; they do not retokenize raw text. Dialects never share quoting rules, parsing never expands or executes shell content, and compound-command suffixes are retained. Unsupported dialects, malformed input, and exceeded limits return typed uncertainty rather than a partial success that can imply safety.

```text
harness request
  -> adapter extraction with dialect, transport, and provenance
  -> canonical parser (once)
  -> context classification and executable/keyword index
  -> all applicable extension matchers
  -> composite evidence artifact
  -> existing policy and memory evaluation
  -> one response, approval item, and receipt
```

## Matcher boundary

A `CommandMatcher` is side-effect-free and evaluates the canonical invocation or one of its segments. It returns zero or more `RuleMatch` values. Matchers use structured executable, subcommand, flag, operand, path, redirect, pipeline, data-flow, platform, and embedded-script fields. Compound matchers expose explicit `all`, `any`, and `not` semantics.

Safe variants are positive, rule-local predicates such as a verified dry run, preview, read-only operation, or bounded target. A safe variant cannot suppress another rule. Regex is a bounded fallback for trusted definitions: compile it at registry construction, validate complexity, constrain input and match count, and evaluate it behind a hard interruption boundary when linear behavior is not guaranteed. Timeout or budget exhaustion produces uncertainty.

Every match carries stable extension and rule IDs, extension version, severity, risk classes, matched segment and source-span references, redaction-safe evidence, confidence, safe-variant results, safer alternatives, and evaluation time. Matchers emit evidence only; they never emit `allow`, approve a request, write memory, or execute commands.

## Registry boundary

The injected registry is the sole source for runtime hooks, command inspection, dashboard APIs, and generated reference documentation. Construction validates:

- schema and semantic versions; unique extension and rule IDs; deterministic ordering;
- required status, source authority, dependencies, conflicts, aliases, and category ownership;
- declared action/risk compatibility during migration;
- matcher type, complexity, count, and time budgets;
- source attribution as built-in, local-admin, or signed managed configuration;
- rollback protection and the rule that external definitions cannot shadow built-ins.

The registry indexes executable and bounded keywords so unrelated extensions are not evaluated. It imports no code from workspace or externally supplied definitions. Declarative external rules remain constrained by the matcher schema and protected configuration authority.

Schema v2 makes leaf extensions own rules. Existing extension IDs, action classes, and risk classes remain available through a single compatibility translator until all consumers migrate. Stored extension settings require an explicit, versioned migration; unknown versions fail closed to a non-weaker state.

## Evidence and policy authority

All matches survive evaluation. The engine creates one composite artifact containing ordered matches, the union of risk classes, parser uncertainty, safe-variant outcomes, and the controlling rule. This produces one policy evaluation and one user action, avoiding duplicate prompts and receipts.

The artifact is evidence, not policy. Guard policy resolves configured risk actions, source/workspace scope, managed policy, remembered decisions, approvals, and final `allow`, `warn`, `review`, `sandbox-required`, `require-reapproval`, or `block` behavior. Extension metadata, modes, and safer alternatives cannot grant authority.

Decision composition must be monotonic:

1. Required critical rules establish a minimum action that lower-authority input cannot reduce.
2. A safe variant affects only its declaring rule.
3. Multiple matches retain all evidence and the strongest controlling requirement.
4. Destructive-executable parser or matcher uncertainty requires at least review.
5. Remembered allow applies only to an equivalent full security identity.
6. Managed, local-admin, workspace, and extension inputs may strengthen an outcome only within their authority.

A versioned truth table covering source authority, required status, extension mode, severity, uncertainty, safe variants, overlap, memory, and configured policy is a release artifact and executable test fixture.

## Memory migration

The new security identity hashes the complete canonical command semantics, not a prefix or display label. It binds dialect, transport, normalized segments and suffixes, wrappers, aliases and executable path source, security-relevant environment overrides including `PATH`, cwd scope, workspace/source scope, parser confidence, and controlling rule ID plus semantic version.

New memory writes use only the versioned identity. Legacy exact-command and pattern memory may be read during a bounded migration window only when every security-relevant field can be proven equivalent. Missing context, changed rule semantics, uncertainty, or broader legacy scope yields `require-reapproval`; it never falls back to a weaker pattern. Migration records the old and new identity versions without persisting newly exposed raw command material.

## Redaction and persistence

Raw text, tokens, embedded payloads, environment values, and source spans are ephemeral parser inputs by default. Persistence stores stable IDs, schema and extension versions, classifications, confidence, hashes, timing, controlling-rule metadata, and redacted excerpts or span descriptors. Secret values must not enter evidence, logs, metrics, generated docs, or matcher errors.

Existing receipt redaction policy controls any authorized raw-command retention. Inspection and policy simulation are side-effect-free: no receipt, approval, memory, event, queue, lease, migration write, or network refresh. Relaxing a display setting must not reconstruct data that was never retained.

## Limits and performance

The parser enforces independent byte, token, segment, wrapper-depth, nesting, embedded-payload, and total-time limits. The evaluator enforces per-rule, per-extension, match-count, regex, and total-request budgets. Every limit failure is typed, observable in explain output, and non-allowing for potentially destructive input.

Evaluation targets are p95 below 5 ms through 1 KiB and below 20 ms through 32 KiB on supported development hardware, with no more than 10% regression in benign hook p95 from the recorded baseline. Timing is available in debug and explain output, not normal hook output.

## Rollout gates

1. **Contract gate:** approve models, schemas, monotonic truth table, threat model, capability matrix, and latency/false-positive baselines.
2. **Parity gate:** ship parser, matcher library, registry v2, and compatibility translator with the existing extension set; remove no legacy path until behavior parity passes.
3. **Required-core gate:** add critical filesystem, Git, system, self-protection, platform, and embedded-script rules only after bypass and false-positive suites pass.
4. **Domain gate:** add infrastructure, container, package, cloud, storage, and data domains in review or monitor mode until corpus and performance evidence supports stronger enforcement.
5. **External-definition gate:** enable declarative local-admin and signed managed definitions only after signature, rollback, authority, corpus, and resource-budget controls pass.

## Acceptance tests

- Assert exactly one parser invocation per harness request and the same injected registry across runtime, CLI, dashboard, and generated docs.
- Cover each dialect/transport independently, wrappers, aliases, cwd, `PATH`, separators, suffixes, pipelines, redirects, heredocs, substitutions, malformed input, and every limit.
- For every rule, test destructive examples, safe counterparts, explicit safe variants, reordered flags, quoted search/print examples, paths with spaces, and platform syntax.
- Assert deterministic registry output; reject duplicate IDs, invalid dependencies, shadowing, rollback, unknown schemas, and unsafe matcher complexity.
- Execute the monotonic truth table, cross-extension overlap, required-rule, safe-variant isolation, uncertainty, and remembered-allow cases.
- Prove one composite artifact, decision, approval item, and receipt while retaining all ordered evidence.
- Verify legacy policy/action compatibility and require reapproval for any non-equivalent memory migration.
- Verify full, partial, and no-redaction persistence; assert secrets and ephemeral parse material are absent from default storage and output.
- Benchmark benign and destructive corpora, matcher timeouts, pathological input, CLI side-effect freedom, harness contracts, and installed-package end-to-end behavior.
