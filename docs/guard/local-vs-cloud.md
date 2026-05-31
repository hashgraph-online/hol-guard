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

Safe Decode runs locally too. It inspects encoded payload layers for review evidence, but never executes decoded payloads and only syncs redacted summaries when optional cloud receipt sync is enabled.

Optional cloud features:

- receipt sync to an optional Guard endpoint
- trust enrichment
- revocation feeds
- billing and entitlements
- shared team policy

The local runtime does not require any hosted service. `hol-guard connect` is the canonical way to pair a machine with Guard Cloud later, and `hol-guard connect --headless` uses OAuth Device Code for SSH/CI hosts. `hol-guard login` remains only as a redirecting compatibility alias. These commands do not unlock the core safety workflow.

Use these commands when you need to check or repair optional cloud pairing without disturbing local protection:

```bash
hol-guard connect status
hol-guard connect repair
hol-guard sync
hol-guard supply-chain sync
hol-guard supply-chain scan
hol-guard supply-chain explain minimist@1.2.5 --ecosystem npm
hol-guard explain install-connect
```
