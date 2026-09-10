# Secret reads and local test execution

## Decision boundaries

A local runner identity does not prove that its tests, configuration, plugins,
imports or child processes cannot read credentials. Guard must not turn a
verified Vitest installation into unrestricted execution permission.

The Python command evaluator now adds a review floor for direct credential
reads and local script execution. The same check runs before benign-command
exemptions. Detected local reads do not need a network destination to require
review. Source inspection reads only bounded local script files, never the
credential file itself. It follows literal shell-script launches using the
caller's working directory and records hashes of inspected source files.
Missing files, symlinks, recursion, size limits and uncertain shell context
retain review. This is not a complete interpreter or an import-graph proof.
Computed paths and uninspected dependencies are reasons to use containment,
not reasons to classify arbitrary code as harmless.

## Native approval retries

A resolved inbox row is not permanent command authorization. A verified
harness Accept may authorize one matching retry for five minutes. Eligible
retries are bound to the Rust-owned semantic request digest, workspace and
native decision fields. The request digest excludes only root transport
metadata such as event aliases and timestamps. Commands that can execute
mutable local code, commands with leading environment assignments, and
multi-command or redirected shell forms are not eligible for Python-side retry
reuse. The consume operation is transactional, so concurrent requests cannot
spend one approval twice. Legacy unbound rows do not match. A later denial for
the same identity supersedes an older allow.

This binds the evidence available to the native hook. It does not make an
unrestricted process immune to filesystem changes between review and execution,
nor does it bind every dynamic import or ambient environment value. Mutable-code
execution therefore remains outside this compatibility reuse path.

## Contained Node runners

The execution-owned package shim can recognize a locally installed `bunx
vitest run <test-file> --reporter=dot` invocation, as well as the existing
`npx --no-install` form. Supported launch evidence includes `package-lock.json`
or a single text `bun.lock`, the installed package metadata, the local runner
and the manager identity. Ambiguous locks, custom reporters and unsupported
arguments still require review.

The contained executor runs the pinned local Node executable and runner
directly. It does not execute `bunx`, fetch a missing package, or inherit the
caller's credential environment. Protected workspace paths are omitted from
the private snapshot without reading their contents. Their exclusions are
included in the snapshot identity. Explicitly requested test inputs must
remain present. Projects under system paths exposed by the containment
backend are rejected. Other snapshot callers retain their previous strict
behavior unless they explicitly request protected-file exclusion.

Silent completion still requires current containment health and a matching,
enforced OS attestation. Launch evidence alone cannot authorize it.

## Remaining native-hook handoff

Raw native PreTool evaluation can require review before the package shim runs.
This change does not add a command-name allowlist or claim to remove that
prompt on every harness. A complete fix for that path needs a verified
handoff to execution-owned containment and harness-level tests showing that
the original uncontained command cannot execute. Until that exists, native
review remains conservative.

The focused tests cover decision floors, source changes, request changes,
expired and one-use approvals, concurrent consumption, Bun launch evidence,
reporter arguments and secret-free snapshot construction. Containment request
tests use a synthetic backend attestation. A host with a working OS backend
must also verify actual secret-read denial before treating the silent path
as deployment-validated.
