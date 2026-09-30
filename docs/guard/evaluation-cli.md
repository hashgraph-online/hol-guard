# Staged evaluation CLI

`hol-guard-eval` provides bounded command stages for the local evaluation
contracts. Every stage writes one JSON object to standard output with a
machine-readable `status`.

## Preflight

Validate a profile and its declared local prerequisites:

```shell
hol-guard-eval preflight --profile profile.json \
  --artifact core-fixture=/absolute/path/to/fixture.bin
```

The command uses `evaluation_preflight.py` and reports `passed`,
`blocked_environment`, or `not_run` with the preflight report. It does not run
evaluation cases. The host `--version` probe is disabled by default, so the
default command cannot invoke the declared host executable. An explicit
`--allow-host-execution` enables only that bounded version probe and is
intended for a separately isolated evaluation VM. It is not a filesystem or
network sandbox and does not provide installed-host proof.

The optional `--setup` flag allocates the private setup only after a passed
preflight. It retains the opaque cleanup token in the profile's private declared
parent, outside the owned setup child. On POSIX the token file is mode 0600
and owner checked. Windows setup and cleanup return `blocked_environment`
because this CLI does not verify private directory and token ACL ownership. The token is
never printed. The command reports the owned setup scope and that cleanup is
available; preserve that scope for the cleanup stage.

## Built-in synthetic adapters

Run the fixed disposable shell/file and loopback receiver adapters declared by
the profile:

```shell
hol-guard-eval run --profile profile.json \
  --case eval.shell.disposable_delete \
  --case eval.egress.loopback
```

The runner accepts only these built-in case IDs. It generates its own witness
paths and loopback endpoints, applies the profile's duration and output
limits, checks receiver readiness before each attempt, and removes its owned
setup in a final cleanup step. The report uses the
`synthetic_adapter_test` proof boundary and `blocked_environment` status
because it is fixture-only: it does not invoke an installed host or bind a
Guard decision to a host event. It does not create an evaluation result or
evidence package.

## Evidence verification

Verify the canonical records and hashes in a package created by the existing
evidence package module:

```shell
hol-guard-eval verify-evidence --package evidence.zip
```

`passed` means the archive is canonical and its records satisfy the v1
contracts. The manifest remains labelled `caller_supplied_unverified`; this
stage does not authenticate a host action, promote evidence to live proof, or
execute a scenario. Inputs are bounded before verification.

## Evidence packaging

Package one validated profile and result pair under the profile's private
temporary root:

```shell
hol-guard-eval package-evidence \
  --profile profile.json \
  --result result.json \
  --output-dir /absolute/path/to/profile-private-root
```

The command reads both JSON inputs with fixed size limits, rejects duplicate
object keys and non-standard numeric constants, validates that the result
matches the profile, and delegates exclusive mode-0600 archive creation to
the evidence package writer. The output is one stable JSON object with the new
archive's digest, path, size, and `caller_supplied_unverified` boundary.
Existing archives and output directories outside the profile's private
temporary root are rejected without overwriting or creating files. Packaging
does not execute a host, run scenarios, or claim installed-host proof.

## Cleanup

Remove one setup created by `preflight --setup`:

```shell
hol-guard-eval cleanup --profile profile.json --owned-root /absolute/path/to/owned-setup
```

Cleanup reads the separate private token file and delegates ownership checks to
`cleanup_interrupted_evaluation_setup`. It removes only the exact owned child
and its token file when the profile scope, marker, token, and local ownership
checks match. A missing or mismatched token returns `blocked_environment`; no
directory scan or token reconstruction is attempted.

All input and contract failures use stable `error.code` and `error.message`
fields. The CLI accepts no arbitrary scenario text, command, path, endpoint,
or package input for the synthetic adapters. A live installed-host proof path
requires separate host-event and Guard-decision binding.
