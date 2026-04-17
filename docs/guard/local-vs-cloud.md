# Works Locally First

Guard works on your machine before you sign in anywhere.

Local features available without sign-in:

- harness discovery
- artifact snapshots
- local diffs
- local policy decisions
- wrapper-mode launch enforcement
- local receipts and explain output
- local policy overrides from home or workspace config

Guard does not meter local safety features. You can detect harnesses, install launchers, diff changes, prompt for approval, and inspect receipts without signing in.

Optional cloud features:

- receipt sync to an optional Guard endpoint
- trust enrichment
- revocation feeds
- billing and entitlements
- shared team policy

The local runtime does not require any hosted service. `hol-guard connect` is the preferred way to pair a machine with Guard Cloud later, and `hol-guard login` remains as a compatibility alias for the same browser sign-in flow. They do not unlock the core safety workflow.
