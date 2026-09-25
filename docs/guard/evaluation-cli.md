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
fields. The CLI never accepts scenario text and has no run or live-proof
command.
