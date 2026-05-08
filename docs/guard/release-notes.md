# HOL Guard Release Notes

Release notes document user-visible changes, false-positive improvements, and paid-feature additions.
Update this file for every release that touches a Guard integration path.

---

## Unreleased

### False-positive improvements (T647)

- **Supply-chain artifact fallback** — `SupplyChainRiskCard` now matches `package_request`
  and any `*_package` artifact type in addition to the original `supply_chain` value,
  eliminating spurious "no risk signals" cards for npm/PyPI requests.
- **Encoded-layer count** — `DecodedLayerCard` now reads the true layer count from the
  detector `plain_reason` field (e.g., "Decoded 3 encoding layer(s)") instead of counting
  signal list length, so multi-layer exfil is accurately reported rather than shown as
  "0 additional layers".
- **Detector registry cached across hook calls** — The default detector registry is now
  lazily initialised once per process and reused, reducing per-hook construction overhead.

### Cloud advisory paid sync (T648)

Advisory bundles are signed by the HOL advisory service and verified locally before use.
The free plan receives a graceful 403 fallback with a local-only warning; no advisory data
is sent to the server during sync. Run `hol-guard advisories sync` to pull the latest bundle.

### Settings presets (T649)

Four one-click security presets — **Gentle**, **Balanced**, **Strict**, and **Paranoid** —
are available from the Settings page. Choosing a preset applies a curated `risk_actions`
profile. Custom overrides survive a preset switch unless explicitly cleared.

### Dashboard scale (T650)

The approval center and evidence log now paginate at 50 items per page. Large workspaces
with thousands of receipts will no longer cause the dashboard to stall on load.
