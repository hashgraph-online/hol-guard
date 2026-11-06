# Command Extension Threat Model

## Security objective

Command extensions must improve detection without becoming a second policy engine or a code-loading mechanism. Untrusted command text, workspace content, extension configuration, and remembered decisions must not weaken required protections, disclose secrets, exhaust the hook, or cross workspace/source authority boundaries.

## Assets and invariants

- Final policy authority, approval signing, leases, step-up checks, and managed-policy isolation remain outside extensions.
- Built-in registry content, required status, rule semantics, enabled state, and precedence cannot be downgraded by agent- or workspace-controlled input.
- The complete command, including suffixes, wrappers, executable resolution, cwd, and security-relevant environment, is evaluated once.
- All relevant matches and parser uncertainty survive into one composite evidence artifact.
- Raw command material and secrets are ephemeral unless explicit receipt policy authorizes retention.
- Inspection and simulation never execute commands or mutate Guard state.

## Trust boundaries

| Boundary | Trust and permitted authority |
| --- | --- |
| Harness adapter | May extract text and provenance; may not choose dialect silently or declare safety. |
| Command input and workspace | Untrusted data. Files may recommend extensions but cannot load code, disable required rules, or grant policy authority. |
| Canonical parser | Trusted code processing hostile input under strict limits; performs no expansion or execution. |
| Built-in registry | Trusted, versioned product content protected by existing integrity controls. |
| Local-admin definitions | Declarative and explicitly approved from protected state; cannot shadow or weaken built-ins. |
| Managed definitions | Declarative, signed, fresh, rollback-protected, and bound to the correct workspace/source authority. |
| Matcher output | Untrusted evidence until schema, ownership, confidence, and budget checks pass. Never a final decision. |
| Policy and memory | Sole decision authority, constrained by precedence, scope, identity version, and integrity checks. |
| Receipts, dashboard, and sync | Persistence and display boundary governed by redaction and workspace/source isolation. |

## Threats and controls

### Parser confusion and bypass

An attacker may exploit dialect confusion, quoting, separators, pipelines, nested wrappers, aliases, command substitution, heredocs, embedded scripts, symlinks, cwd, or command-local `PATH` to hide a destructive suffix or change executable resolution.

**Controls:** adapters declare dialect, transport, and provenance; one parser preserves all segments and source spans; dialect parsers do not fall through to another grammar; executable path source and relevant environment are part of the model; parsing performs no expansion; malformed, unsupported, over-limit, or low-confidence destructive input requires review.

### Data mistaken for execution

Destructive words inside search patterns, tests, comments, echo/printf arguments, or quoted examples can cause denial of service through false approvals. Conversely, substitutions or embedded scripts can make executable content look like inert data.

**Controls:** every segment has explicit execution, data, quoted-example, or unknown context; safe variants are structured positive matches; embedded execution is extracted with bounded recursion; unknown context cannot suppress a required rule; canonical corpus tests include quoted and executable counterparts.

### Matcher evasion or resource exhaustion

Hostile input or declarative patterns may trigger excessive tokenization, match explosions, catastrophic regex behavior, deep nesting, or timeouts. A timeout could otherwise become an allow.

**Controls:** independent parser and evaluator byte, token, segment, depth, payload, match-count, and time budgets; executable/keyword indexing; registry-time regex validation and compilation; guaranteed-linear matching or interruptible isolation for non-linear cases; timeout is typed uncertainty and never automatic safety.

### Registry poisoning and authority escalation

A project or managed source may duplicate a built-in ID, redefine risk, mark a destructive operation safe, disable a required extension, import executable code, introduce invalid dependencies, or replay an older definition.

**Controls:** immutable built-in ownership; schema and semantic-version checks; unique IDs; source attribution; dependency/conflict validation; no runtime imports from external locations; local-admin approval; managed signature, freshness, scope, and rollback checks; project definitions remain monitor-only until promoted. External input may not override built-in IDs, required rules, risk classes, or precedence.

### Safe-variant and overlap downgrade

A broad safe predicate or lower-severity match may suppress a critical match from another rule. First-match evaluation may discard evidence or select the weaker result.

**Controls:** evaluate all indexed rules; safe variants apply only to their owner; required critical rules establish a minimum action; union risks and retain ordered evidence; select the strongest controlling requirement through an executable monotonic truth table. Lower-authority input can never reduce that minimum.

### Evidence used as policy

An extension may attempt to return `allow`, self-approve, alter policy state, or manufacture an authoritative source. Multiple matches may create duplicate approvals that users approve inconsistently.

**Controls:** matcher schemas contain facts and safer alternatives, not final actions; extension modes are policy inputs with bounded authority; only the existing policy engine resolves outcomes. One command creates one composite artifact, one policy decision, one approval item, and one receipt.

### Remembered-allow replay

A remembered allow for a prefix or normalized label may be replayed with a destructive suffix, wrapper, changed cwd, alias, `PATH`, workspace source, parser confidence, or changed rule semantics.

**Controls:** versioned memory identity binds the full canonical command, dialect, transport, suffixes, wrappers, executable source, relevant environment, cwd and workspace/source scope, confidence, and controlling rule semantics. Legacy memory is accepted only on proven equivalence; missing context, broader scope, semantic change, or uncertainty requires reapproval.

### Secret disclosure and persistence drift

Commands, environment overrides, paths, embedded payloads, source spans, errors, traces, receipts, dashboard views, or sync records may expose credentials. A later redaction change may accidentally backfill material that was intended to remain ephemeral.

**Controls:** default persistence is stable IDs, hashes, classifications, confidence, timing, and redacted excerpts/span descriptors. Raw parse material is discarded after evaluation unless explicit receipt policy authorizes retention. Matcher errors and metrics contain no raw secrets. Display and sync apply the configured redaction level and workspace/source isolation; relaxed settings cannot recreate unretained data.

### Simulation side effects

Inspection or evaluation intended for debugging may write memory, create approvals or receipts, refresh policy, enqueue work, acquire leases, emit events, or execute a command.

**Controls:** inspection is policy-independent; policy evaluation uses a frozen local snapshot. Both are read-only and have tests asserting no filesystem, database, queue, event, network, lease, or execution side effects.

## Monotonic precedence requirements

The release truth table must prove these invariants for every combination of source authority, required status, mode, severity, safe variant, uncertainty, overlap, remembered decision, and policy action:

1. Required minimum action is never reduced.
2. Safe evidence cannot cancel unrelated unsafe evidence.
3. Parser or matcher uncertainty cannot become an allow for potentially destructive input.
4. A remembered allow cannot outrank changed security identity or controlling rule semantics.
5. External configuration cannot claim stronger source authority than its validated origin.
6. Additional evidence or stronger policy can preserve or increase, never decrease, the controlling requirement.

## Rollout and operational gates

- Record benign/destructive latency and false-positive baselines before enforcement migration.
- Freeze schemas, parser confidence semantics, memory identity, redaction invariants, and the precedence truth table before replacing legacy classification paths.
- Require behavioral parity for existing action/risk classes and remembered-policy flows before expanding coverage.
- Release required rules only after bypass, overlap, safe-variant, and false-positive corpora pass.
- Default ambiguous new domains to monitor or review until coverage and performance evidence justify enforcement.
- Admit external declarative definitions only after integrity, rollback, scope, corpus, and resource-limit tests pass.
- Stop rollout on policy weakening, cross-workspace leakage, secret persistence, matcher budget failure, or benign hook p95 regression above the approved threshold.

## Security acceptance tests

- Dialect-confusion cases and independent POSIX, PowerShell, cmd, argv, and embedded-script fixtures.
- Suffix, separator, wrapper, alias, executable-resolution, cwd, symlink, `PATH`, pipeline, substitution, redirect, heredoc, and source-workspace bypass cases.
- Search/print/test-runner quoted examples paired with executable destructive forms.
- Required-rule versus safe-variant and cross-extension overlap across the full monotonic truth table.
- Duplicate/shadowed IDs, invalid source claims, dependency cycles, unknown schemas, version rollback, bad signatures, stale definitions, and wrong-scope managed content.
- Byte, token, segment, nesting, payload, matcher-count, regex, and wall-time exhaustion with typed uncertainty and no silent allow.
- Composite evidence retains all matches while creating exactly one decision, approval, and receipt.
- Memory replay attempts with changed suffix, wrapper, cwd, environment, source, confidence, or rule version require reapproval.
- Full, partial, and no-redaction tests prove default storage, logs, errors, dashboard output, and sync records contain no unauthorized secret-bearing material.
- Inspection and simulation tests prove deterministic output and zero execution, persistence, network, queue, event, lease, or approval side effects.
- Compatibility, harness contract, benchmark, pathological-input, packaged-install, and representative end-to-end tests pass before release.
