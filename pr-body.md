## Summary
- Add new `/about` route to HOL Guard dashboard
- Hero section: "Open standards. Local protection."
- Local-first promise with 4 trust cards (approvals, receipts, snapshots, optional cloud sync)
- Mission section explaining HOL's open standards work
- Choose-your-path grid with 5 cards (protect locally, sync with team, validate in CI, build standards, teach/promote)
- Standards partner program with 3 levels (Integrator, Standards contributor, Advocate)
- Affiliate starter kit with commission terms and disclosure
- Trust footer with HOL Guard branding
- External links validated against allowlist (hol.org, github.com, x.com, t.me) with HTTPS enforcement
- No session/token leakage in external links
- No new runtime dependencies

## Testing
- `pnpm test` (all tests pass including new about-content and about-external-links tests)
- `pnpm run build` (121 modules, no errors)

## Notes
- External links use `assertSafeAboutExternalUrl()` instead of `guardAwareHref()` to prevent token leakage
- First render works offline (no external data dependencies)
- WCAG AA compliant structure with proper headings and landmarks
