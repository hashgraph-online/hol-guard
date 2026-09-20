# Native command extension program and authority binding

Status: implementation in progress for release/3.2. This record freezes the
contract; the checked coverage manifest distinguishes translation from runtime
execution. A generated artifact alone is not evidence of native enforcement.

## Ownership and authoring

Reviewed Python modules remain the contribution authoring interface. The build
compiler imports only explicit package-owned types and accepts their exact
dataclass identities. It never imports a module named by contribution metadata,
calls a matcher, evaluates a Python expression, or accepts a class because its
name resembles a reviewed matcher. Unknown types reject the build.

The compiler emits `guard.native-command-program.v1` into
`contracts/extensions/native-command-program.v1.json`. The wheel, frozen app,
and Rust resident package the same artifact. `scripts/build_native_command_program.py
--check` rejects a stale artifact. Compiling contributions is a build step; hook
evaluation does not import Python or launch a subprocess.

The program contains every owned rule and safe variant, the complete matcher
configuration, conservative candidate hints, permission dependencies, trust and
activation metadata, and the original Python matcher-contract digests. Repeated
matcher nodes share content-addressed IDs. Node hashes use canonical UTF-8 JSON
and the `hol-guard.native-command-matcher.v1` domain. The program hash uses a
separate `hol-guard.native-command-program.v1` domain and excludes only its own
`program_digest` field. Authoring source fingerprints bind implementation
changes that do not change a dataclass's fields. Native rule identity also binds
the interpreter source and packaged artifact.

Native v1 uses the explicit `cpython-3.12-ucd15` reference profile for Unicode
letter, number, whitespace, and SQL word-boundary semantics. Its differential
fixtures qualify that profile; they do not establish equivalence to every
Python 3.10–3.14 Unicode database. Unsupported case conversions are explicit
matcher uncertainty. Raw literal safety also requires internal parser evidence
that the parser-trimmed request text exactly equals the normalized command; a
deserialized command model cannot supply that proof.

Bounds are explicit: 4 MiB program bytes, 1,024 rules, 16,384 distinct nodes,
32 nested matcher levels, 4,096 items per configuration collection, 4,096 UTF-8
bytes per configuration string, 64 safe variants per rule, and one million
visited configuration values. These are admission limits, not permission to
perform that work on every hook. The native runtime validates and compiles the
program once, constructs immutable candidate indexes, and shares it by `Arc`.

## Snapshot contract

The program is larger than the 256 KiB policy-snapshot limit. Policy snapshots
therefore carry a compact `command_extensions` binding, not the program bytes.
The field is optional on legacy v3 snapshots and has an explicit versioned
schema. A publisher may emit it only after the resident advertises the matching
capability. Production extension coverage requires that capability; a legacy
resident cannot silently claim to enforce the catalog.

The binding carries the program, catalog, and trust digests and the authenticated
extension-control runtime snapshot: health, local revision, managed revision,
effective digest, and at most two bounded control layers. The policy digest and
snapshot HMAC both cover this binding. An absent field retains the exact legacy
canonical representation and digest. Unknown versions, unknown fields, invalid
digests, oversized controls, and program identity mismatches reject admission.

Publication reads the authenticated control authority after durable commit.
Untrusted database timestamps only trigger reconciliation; they cannot create
authority. Local and managed revision numbers are monotonic independently. The
same revision pair with changed effective state is equivocation. Snapshot swaps
publish one immutable policy/program/control view so a hook cannot mix generations.
Existing scope, expiry, generation, authority-loss, and approval fences remain.

The separate `native-command-control-fence-v1` capability requires a durable,
authenticated `native-runtime/command-control-authority.v1.json` marker. Every
authorized mutation takes the retained exclusive control lock and fsyncs a
strictly newer closed marker before changing SQL rows, authority keys, or
anchors. Verified projection commits the resulting effective digest before
publication; readiness opens only for the matching resident acknowledgement.
Native admission, including idempotent acknowledgement, checks that exact
committed marker. Normal decisions and approval creation/claim/consume hold a
nonblocking shared lease on the same lock through their authoritative callback.
Missing, closed, tampered, or mismatched markers reject the operation even when
the daemon is stopped. An old acknowledgement cannot reopen newer controls.

An ordinary health change cannot reset independent revision floors. Explicit
authority recovery creates a strictly newer authority epoch and mutation
revision, signed under the retained native policy verifier key. Its proof names
the prior epoch, mutation revision, authority-key identity, and domain-separated
hash of the complete retained floor. The resident requires an exact predecessor
match before accepting reset local or managed revisions. The new durable floor
retains the predecessor link; expiry, quarantine, and restart cannot erase it.
Windows shared/exclusive lock interoperability and crash-cut behavior remain
part of platform qualification, beyond the portable unit proof.

## Decision semantics

The extension interpreter consumes the same canonical command model as the
native command authority. It does not reparse for each rule. Candidate selection
is a conservative optimization only; catalog ordering and all matching evidence
remain observable. A shared matcher result may be cached within one decision,
but evidence ordering and duplicate indexes are preserved.

First-party and trusted-library defaults remain catalog-defined. External
extensions require explicit local-admin activation; managed enablement alone
does not opt a user in. A composed disable deactivates an external extension.
For an active first-party capability, a disabled extension or permission blocks
the classified action. Control-layer disable dominance, dependencies, implied
permissions, non-configurable floors, and authority failure preserve existing
resolver semantics.

Compatibility attribution is separate from declarative matcher qualification.
The 42 null-matcher identities and four GitHub permissions without rule IDs
receive explicit owned observations. Safe Git identities whose default mode is
disabled remain attribution-only: they preserve the existing intrinsic action
while an explicit control disable still blocks. Unimplemented context proofs
produce owned uncertainty and a block floor. This does not certify complete
Python classifier equivalence or grant permission based on inventory coverage.

Each rule observation retains its base evidence, every matching safe variant,
uncertainty, and effective segment indexes. A safe variant suppresses only its
owner's matching segments. It cannot suppress an unrelated rule, native hard
floor, sensitive path, exfiltration classification, or unknown-command review.
Matcher failure or unavailable native semantics produces explicit uncertainty;
it is never translated to no-match or allow. A safe matcher failure remains
uncertain unless other successful variants cover every base segment. Bounded
parse exhaustion cannot prove a safe option.

Evidence contains only bounded segment indexes, sanitized executable basenames,
owned catalog IDs, and fixed diagnostic text. Raw commands, paths, option values,
and credentials do not enter observations or receipts. The typed result carries
the full bounded observations; the compact receipt binds their digest together
with program/catalog/trust identities and both control revisions. Native v3/v4 approval and replay identity includes the same
policy/program/control domain. The ordinary installed approval flow uses local
review reuse; its stored approval context must separately bind the verified
receipt policy digest and command program/control binding. Unbound prior rows
cannot authorize a new bound review. Native v3/v4 API tests do not qualify that
ordinary installed route.

## Qualification

The compiler inventory at the reconciled release foundation contains 86
extensions, 291 rules, 304 permissions, and 26 instantiated matcher families.
There are 29 explicitly reviewed compiler types; three currently have no catalog
instances. Every rule and safe variant has its own coverage record. A record's
`translation` field describes compilation. `native_execution` remains
`requires-runtime-admission` until the resident checks operation capabilities.

Qualification requires differential benign, malicious, ambiguous, Unicode,
option-value, inverse-flag, overlap, dependency, and safe-variant vectors against
the existing Python behavior. Ollama must traverse contribution, build,
installation, local enablement, native review, receipt persistence, disablement,
update, and rollback. Measurements separate cold compilation/admission from warm
candidate matching and full installed hook latency. A complete manifest or a
fast primitive benchmark is not an installed-route performance claim.
