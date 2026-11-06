# ADR 0003: HOL Guard Desktop owns persistent native UI

- Status: Accepted for HOL Guard 3.0
- Date: 2026-08-05
- Core integration PR: #1901
- Release line: `release/3.0`
- Temporary branch name: `release/3.1` until the separately owned rename completes

## Context

HOL Guard already owns the security engine, local daemon, policy, approvals, receipts, harness integrations, browser dashboard, and optional Guard Cloud synchronization.

PR #1901 also contains a Python-based persistent menu-bar/system-tray implementation. HOL Guard Desktop is now a separate product and repository, so retaining a second native lifecycle implementation in the core would create duplicate process ownership, duplicated update and autostart logic, a larger dependency and attack surface, and unclear responsibility for notifications and native UI.

The Desktop application needs stable headless contracts from HOL Guard 3.0, but HOL Guard 3.0 must remain independently releasable without the Desktop application being complete.

## Decision

### Core ownership

`hashgraph-online/hol-guard` remains the sole authority for:

- security evaluation and enforcement;
- local policy and integrity;
- approval requests and resolution semantics;
- receipts and evidence;
- harness and package-manager integrations;
- the authenticated local daemon;
- the canonical browser dashboard;
- protocol and compatibility advertisement;
- Desktop bootstrap and short-lived scoped sessions;
- platform-neutral status, attention, and notification-ownership events;
- redacted diagnostics, repair, and core updates;
- a self-contained, headless core artifact for Desktop packaging.

### Desktop ownership

`hashgraph-online/hol-guard-desktop` is the only owner of:

- the persistent menu-bar/system-tray process;
- tray icon state, menu actions, and badges;
- the native application window;
- hide, show, focus, close-to-tray, and single-instance behavior;
- Desktop launch at login;
- native notification presentation and deep-link activation;
- Desktop-specific update orchestration and recovery UI;
- native app icons and tray resources;
- macOS and Windows application installers and signing.

### Release dependency

The dependency is one-way:

```text
HOL Guard 3.0 headless contracts and artifacts
                    ↓
             HOL Guard Desktop
```

HOL Guard 3.0 may ship before HOL Guard Desktop. The Desktop application must target the finalized 3.0 contracts and must not require an unplanned 3.1 architecture migration.

### Tray extraction

The persistent tray implementation currently present in PR #1901 must be removed from the core release. Removal includes tray-only code, dependencies, assets, package metadata, CLI commands, daemon routes, dashboard settings, autostart registration, updater handoff, tests, and documentation.

The extraction must preserve independently useful headless behavior, including:

- daemon singleton and authenticated discovery;
- dashboard launching and short-lived browser sessions;
- approval and receipt event generation;
- platform-neutral attention and notification-owner contracts;
- a best-effort CLI/browser notification fallback that does not require a persistent tray process;
- core update, repair, and diagnostic behavior.

The deleted Python tray implementation must not be copied into the Desktop repository. The Desktop tray will be implemented natively through Tauri.

## Security constraints

- The Desktop WebView must not receive the daemon auth token or unrestricted localhost access.
- The Desktop shell must not become a second policy engine or write directly to Guard storage.
- The core artifact must not launch any native GUI or persistent tray process.
- Notification deduplication must ensure one active presenter per Desktop session.
- Core and Desktop updates must fail safely when their compatibility contract is not satisfied.

## Verification

HOL Guard 3.0 is compliant when:

1. a clean core install starts no tray or native GUI process;
2. the package exports no tray CLI command or tray executable;
3. tray-only dependencies and assets are absent from the wheel and standalone core artifact;
4. no tray-specific launch-at-login registration is installed;
5. CLI, daemon, browser dashboard, approvals, receipts, and fallback notifications still pass;
6. the Desktop bootstrap fixture can establish a scoped session against the 3.0 core;
7. `hol-guard-desktop` is the only repository containing persistent tray behavior.

## Consequences

- The core has a smaller dependency and platform surface.
- Desktop users receive a native, signed lifecycle implementation.
- CLI and headless users retain Local Guard without installing a GUI.
- The existing tray work in PR #1901 must be carefully separated from reusable dashboard-launcher, notification, and daemon behavior.
