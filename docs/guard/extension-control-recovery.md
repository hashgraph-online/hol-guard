# Recover extension-control authority

Use these commands in a local terminal with the same Guard home used by the daemon.
They do not require deleting runtime state or disabling authentication.

## First enrollment

```sh
hol-guard command controls enroll
```

Enter the configured approval factor and type `ENROLL EXTENSION CONTROL local-admin`
when prompted. A running daemon is supported: enrollment closes the native authority
under the existing cross-process mutation lock, commits the local authority, and asks
the daemon to refresh it. Stopping every healthy daemon before enrollment is unnecessary.

The approval password authorizes the operation. It is not the native signing key.
Changing that password does not, by itself, require removing native authority files.

## Stale or interrupted authority

When enrollment reports that native extension-control authority could not be verified,
use the authenticated recovery command shown in the error:

```sh
hol-guard command controls recover-authority
```

For a custom home, pass it before `controls`:

```sh
hol-guard command --guard-home '/path/to/guard home' controls recover-authority
```

Recovery requires fresh approval. When an authenticator app is configured, the code
must come from a newer time step than the last code accepted in this session; reusing
that code is rejected. It preserves verifiable controls, resumes an
interrupted authenticated transition where possible, and archives unverifiable local
control rows before rebuilding an empty authority. It verifies the retained native
anti-rollback floor and advances the recovery epoch when a reset is necessary. It does
not import unverifiable rules, remove the floor, or silently replace a signing key.

Recovery can enroll an uninitialized local authority whose stale native marker prevented
first enrollment. Do not run `enroll` again after recovery reports `health: protected`.
Check the running daemon's control view instead:

```sh
hol-guard command controls status
```

The recovery response describes the local control authority, not every subsystem's
runtime readiness. An offline daemon must be started before its status can be checked.

## Linux keyring session changes

A desktop daemon and a terminal can have different access to the system keyring. Guard
keeps a local encrypted copy so a missing keyring does not create a new native identity.
When the two stored keys disagree, a candidate must verify the existing signed native
marker and any retained floor, and agree with the resident verifier when present, before
Guard uses it to repair a copy. A stale returning keyring must not overwrite the local
key that the live daemon is using. If neither candidate can be verified, both copies are
left available for explicit recovery rather than destroying potentially valid material.

## Recovery cannot authenticate the retained state

Stop the daemon for the affected Guard home before restoring its original keyring or
local-vault material, then retry recovery and restart the daemon. Preserve the existing
native authority and rollback history while diagnosing the failure. An unavailable
original signing key or a forged floor is not a reason to bypass verification.

Do not delete `command-control-authority*`, `policy-verifier.key`, or native snapshot/floor
files. Removing these files can discard recovery evidence or race a running publisher;
it is not the supported enrollment or recovery procedure.
