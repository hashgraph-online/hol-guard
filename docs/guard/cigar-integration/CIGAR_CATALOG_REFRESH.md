# Bounded native CIGAR catalog refresh

Guard now supports an explicit background check of a separately configured signed catalog feed. Refresh uses the same authenticated import/resolver as offline distribution. It publishes release metadata only: installation, selection, enablement, feature changes and runtime switching remain separate actions.

A refresh runs in the existing single native preparation worker with a 30-second deadline, cancellation and durable progress. The profile lifecycle lease serializes feed/root changes, refresh publication, installation and switching while the current SDK continues serving. The native resident's bounded optional-work lane and independent health/Stop behavior are preserved.

## Feed configuration and operator actions

The advanced local `hol-guard-runtime context-assistance-install-operator --stdin` command accepts `operation.action: configure_catalog_feed` in the existing strict `guard-cigar-install-operator.v1` request, with absolute `guard_home` and explicit `operator_approved: true`. Its `feed` has schema `guard-cigar-catalog-feed.v1` and `url`. A null URL explicitly disables remote refresh. Public Ed25519 roots are configured separately through `configure_catalog_trust`; a URL never authorizes a signer.

Feeds must be canonical public-domain HTTPS URLs on port 443, at most 2,048 bytes, without credentials, query strings, fragments or IP-literal targets. Actual requests also enforce public DNS answers, pinned peers and TLS through the existing native restricted transport. Redirects are refused, including redirects to the same host. No default production feed or key is configured by this implementation.

The browser/resident accepts only `action: refresh_catalog` and an opaque `job_id`. Caller-supplied URLs, keys, headers, proxy settings, package indexes and activation facts are rejected. CLI commands are:

```text
hol-guard context catalog-refresh check-one
hol-guard context job check-one
hol-guard context cancel check-one
hol-guard context recover check-one
```

The nested `guard context` path provides the same actions. Existing authenticated `POST /v1/context-assistance/versions` framing and its settings approval gate apply to refresh. Job inspection and cancellation retain their existing access-reduction behavior. Refresh uses the ordinary 64 KiB resident request budget; only offline signed-catalog import receives the larger frame.

`context catalog` reports whether a valid feed is configured, its configuration digest and any feed diagnostic. It does not expose the URL or public-key bytes, execute Python, fetch metadata or refresh automatically. A malformed feed does not erase an authenticated installed receipt or retained withdrawal ledger; the explicit refresh request refuses until configuration is repaired.

## Download, publication and recovery

The native downloader caps the complete signed envelope at 1 MiB and uses zero redirects. DNS lookup is bounded by the existing five-second resolver window and global resolver capacity. The shared preparation deadline/cancellation flag reaches DNS and pinned HTTPS transport; Stop remains independent. Machine policy is checked before network work and again before publication. Configured proxies or additive trust roots retain the existing explicit offline-import refusal; this path does not bypass them.

Unsigned/untrusted bytes remain in the job's marked private download directory until protected stable reading and bounded cleanup. The original signed text is then checked against current separately configured roots, time, checkpoint, immutable identity history and permanent withdrawals. The normal native import owner computes the retained envelope before publication. Import never takes a second lifecycle lease while a refresh owns it.

Durable refresh progress records contain opaque ID, request/configuration digests, bounded timestamps, phase/code and an optional verified target checkpoint. They contain no feed URL, key, SDK code, source text, grants or execution approvals. SDK/Python/catalog/switch jobs share the same ID namespace and combined 32-job limit. A duplicate job ID returns that job's existing result; a new check requires a new ID.

Cancellation before publication leaves the retained catalog unchanged. The owner stays live until network work and cleanup acknowledge. A publication that wins a late cancellation is reported as published; progress cannot roll back catalog data. Publication or completion ambiguity becomes explicit recovery. A lost worker is never restarted by status.

Recovery performs no network or SDK work. Under the profile lease it can confirm and durably republish only the identical currently authenticated cache that matches the recorded target checkpoint. It cannot import a catalog from progress, restore an older catalog or silently reset trust/withdrawals. A nonmatching checkpoint becomes an interrupted result; malformed authenticated state refuses. Cleanup is restricted to the job's marked private root, with bounded traversal and refusal of links or unknown ownership. Cleanup faults remain visible for explicit repair/retry.

The later [atomic storage checkpoint](CIGAR_ATOMIC_CATALOG_STORAGE.md) removes the new-profile key/cache provisioning interval and covers nine real process-exit boundaries. Refresh recovery confirms the same authenticated pair; incomplete historical or tampered committed state is never discarded to make refresh succeed. Power/disk-loss and the complete recovery matrix remain unqualified.

## Evidence and qualification

The final native registry suite passes 115 tests with five SDK-gated cases. This includes seven new refresh cases, nine retained catalog cases and exact-feed/no-redirect/envelope-limit transport coverage. The new cases exercise separate configuration, signature/replay rejection, off-state preferences, idempotency/capacity, cross-controller cancellation/exclusion, interrupted publication, deadline and safe cleanup. Native Service 17, protected configuration 19, route authorization 10, optional-work lane 15 and Python framing 76 tests pass. Rust 1.88, Rust/Python formatting, Ruff and native authority/I/O/privacy gates pass. Clippy retains 36 existing errors in 23 hash-verified unchanged sources, with zero new errors; two unused production helpers remain.

The enhanced actual final 0.14.1 SDK case deliberately pauses a synthetic feed response while the real serving SDK explains an existing context snapshot. The source actor, exact configuration bytes, native generation and complete reviewed notes/expiry remain intact across refresh publication. Normal install re-verification then uses the imported catalog, followed by explicit switch and latest-data rollback without resurrecting removed notes. The synthetic transport pause is test-only; trust, worker ownership, publication and job inspection use the native implementation.

This is local macOS ARM64 with exact final 0.14.1 artifacts and external Python 3.14.7/3.14.10, using test-only public roots and qualification receipts. It qualifies no production HTTPS endpoint/key rotation deployment, actual newer SDK, historical b47380 transition, managed-Python end-to-end, installed/frozen delivery, CLI/HTTP-with-SDK end-to-end or other platform. The initial refresh run compiled but failed three cases because the synthetic fixture omitted its qualified feature list; that failure is retained alongside the corrected runs.

[Evidence](evidence/receipts.json) records source/image/log identities, actual inputs and preservation. All new/refactored modules remain within the source-line guideline; the earlier small framing edit to the existing large HTTP server remains a recorded exception. No production feed, live profile, hooks, preview, system Python or upstream SDK was changed.

P7 still needs pin/update/retention policy, off-state selection, safe managed-slot removal and production feed/trust qualification. P8 UI/walkthroughs and the remaining P6/P9/P10 crash/cleanup/data-choice, genuine newer bytes, installed/frozen/platform, approval/load/performance and maintainers' next-bump evidence remain required. The full P0–P10 goal remains active and incomplete.
