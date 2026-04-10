# Local vs Cloud

Guard is local-first.

Local features available without sign-in:

- harness discovery
- artifact snapshots
- local diffs
- local policy decisions
- wrapper-mode launch enforcement
- local receipts and explain output

Optional cloud features:

- receipt sync to an optional Guard endpoint
- trust enrichment
- revocation feeds
- billing and entitlements
- shared team policy

The local runtime does not require any hosted service. `guard login` and `guard sync` exist to layer optional cloud features on top of the local product, not to unlock the core safety workflow.
