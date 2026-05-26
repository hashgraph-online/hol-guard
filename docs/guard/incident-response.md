# HOL Guard Incident Response (Blocked Malware / Compromised Package)

Use this runbook when Guard blocks a known-malware or compromised dependency.

## Immediate actions

1. Stop the install pipeline for the affected workspace/repository.
2. Preserve Guard evidence output for incident tracking.
3. Identify where the package was introduced (manifest, lockfile, transitive source).

## Containment

- Remove or pin away from the compromised package/version.
- Re-run dependency installation only through Guard:
  - `hol-guard protect -- npm ci`
- Verify no install-time scripts executed from the blocked package path.

## Recovery

1. Apply the recommended fixed version.
2. Re-run:
   - `hol-guard supply-chain scan --json`
   - `hol-guard supply-chain audit --json` (for broader workspace validation)

## Communication and follow-up

- Record impact scope, remediation actions, and final verification evidence.
- Share a short post-incident note with package/version, detection time, and fix version.
