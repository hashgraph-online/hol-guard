# ADR 0001: MDM managed-install contract

Status: accepted for implementation; customer platform inputs remain release gates.

## Decision

- Package ownership is per-machine. macOS uses receipt `org.hol.guard`; Windows uses per-machine MSI upgrade code `B15D39B1-6395-4FEA-98A9-5D734DDC455D`.
- Machine runtime/state/log paths are `/Library/Application Support/HOL Guard`, `/Library/Application Support/HOL Guard State`, `/Library/Logs/HOL Guard` and `%ProgramFiles%\HOL Guard`, `%ProgramData%\HOL Guard`.
- User state remains `~/.hol-guard`. Mutating lifecycle commands require the target user session; root/SYSTEM cannot substitute its profile.
- macOS uses a LaunchAgent. Windows uses Active Setup. Both call idempotent repair at user login; runtime daemons remain on-demand by default.
- Managed policy comes only from `org.hol.guard` managed preferences or `HKLM\Software\Policies\HOL\Guard`. Machine policy wins non-action conflicts. Security actions and modes compose to the strongest outcome; local sources may tighten locks.
- MDM owns version changes when `update.owner=mdm`. Downgrades and self-removal fail closed. Evidence is preserved by default.
- External HTTP uses one mandatory-TLS policy supporting system, explicit, or no proxy; private CA trust is additive. Public registry intelligence can be disabled independently from Guard Cloud.
- Production packages require both a signed Ed25519 release manifest and native platform signatures. Unsigned artifacts are CI fixtures and must fail healthy detection.

## Consequences

The package never guesses a user from root/SYSTEM. A device install can succeed with no logged-in user, and each eligible user converges at login without reinstalling. Customer MDM assignment details, minimum OS/CPU scope, publisher identities, signing credentials, and Cloud enrollment remain certification inputs and cannot be inferred in code.

This decision implements the managed-install boundaries in [the self-protection contract](../self-protection-contract.md), with schemas under [`schemas/`](../schemas/), deployment operations in [mdm-deployment.md](../mdm-deployment.md), and network controls in [mdm-networking.md](../mdm-networking.md).
