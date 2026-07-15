# HOL Guard MDM Compatibility PRD

## Document control

- **Status:** Proposed
- **Priority:** P0 enterprise readiness
- **Platforms:** macOS and Windows
- **Product owner:** TBD
- **Engineering owner:** TBD
- **Security reviewer:** TBD
- **Audience:** Guard engineering, release engineering, security, IT administrators, and customer success
- **Implementation tracker:** [MDM compatibility TODO](./mdm-compatibility-todo.md)
- **Last updated:** July 15, 2026

## Summary

HOL Guard is currently installable through PyPI and `pipx`, stores runtime state per user, and exposes useful noninteractive and JSON commands. That is sufficient for a controlled script-based pilot, but it does not provide the signed artifacts, deployment-context contract, managed policy authority, lifecycle reporting, or enterprise network controls expected from an MDM-managed security product.

This PRD defines the P0 work required to make HOL Guard deployable, observable, repairable, updateable, and removable through enterprise MDM on macOS and Windows. The design separates the machine-owned product runtime from per-user harness activation so device-context installation never writes root- or SYSTEM-owned files into a developer's home directory.

## Problem

The current installation contract has five production blockers:

1. The release is a Python wheel that requires a compatible Python runtime and package installer. There is no signed macOS installer package or signed Windows installer payload.
2. Guard state, shims, and harness configuration live under each user's home directory. MDM commonly installs in root or SYSTEM context, which would target the wrong home and ownership.
3. Local configuration, updates, harness disconnection, and self-uninstall remain under user control. There is no machine-managed policy source whose locked values cannot be weakened locally.
4. There is no stable MDM detection, activation, repair, upgrade, rollback, or uninstall contract with documented exit codes and logs.
5. Cloud, package-intelligence, and update traffic has no explicit enterprise proxy, private certificate authority, offline installation, or endpoint allowlist contract.

## Goals

- Provide signed, versioned, offline-capable MDM artifacts for supported macOS and Windows architectures.
- Install a machine-owned Guard runtime without requiring customer-managed Python or `pipx`.
- Activate Guard independently and idempotently for every eligible local user, including users or harnesses added after machine installation.
- Add a machine-managed policy source with deterministic precedence, integrity checks, and lockable settings.
- Prevent standard users from weakening, updating, or removing an MDM-managed installation while preserving local ability to strengthen policy.
- Give MDM systems stable detection, health, repair, upgrade, rollback, and removal interfaces.
- Support enterprise proxies, TLS inspection with approved private roots, offline installation, and a documented network allowlist.
- Preserve Guard's offline local enforcement and existing user-managed PyPI installation mode.

## Non-goals

- Replacing Guard Cloud workspace RBAC or signed Cloud policy distribution.
- Building a general-purpose MDM server or vendor-specific administration console.
- Requiring an always-on privileged system daemon when per-user hooks can enforce safely.
- Adding kernel extensions, system extensions, packet filters, or broad Full Disk Access without a demonstrated requirement.
- Automatically interpreting arbitrary proxy PAC files in the first MDM release. Static system and explicit HTTPS proxy configurations are required.
- Supporting mobile operating systems.
- Supporting architectures the launch customer does not use. The certified architecture set must be recorded before release.

## Personas

- **Endpoint administrator:** packages Guard, assigns it to device or user groups, monitors deployment, and performs repair or removal.
- **Security administrator:** locks minimum policy, controls update channels and network trust, and reviews tamper or drift evidence.
- **Developer:** receives protection without installing Python, running elevated commands, or repeating setup after every update.
- **Support engineer:** diagnoses a failed installation from stable JSON status and bounded, redacted logs.
- **Release engineer:** produces signed, reproducible artifacts with provenance, SBOMs, checksums, and tested upgrade paths.

## Support promise

An MDM-compatible HOL Guard release is complete only when an administrator can install it silently on a clean managed endpoint, activate it for a standard user, verify protection without parsing presentation text, repair drift, upgrade or roll back, and remove it without leaving active hooks or sensitive state.

“Installed” and “protected” are separate states:

- **Machine installed:** the signed machine runtime, manifest, policy adapter, and lifecycle tools are present and valid.
- **User activated:** the target user's Guard state exists, applicable harnesses are connected, and health checks confirm the intended protection contract.

MDM reporting must never equate a valid machine package with successful per-user protection.

## Target architecture

```text
MDM service
  -> signed machine installer
      -> immutable Guard runtime and release manifest
      -> managed-policy adapter
      -> lifecycle and detection commands
      -> optional login activation registration
  -> per-user activation
      -> user-owned ~/.hol-guard state
      -> user-owned harness hooks, shims, and reversible backups
      -> local loopback daemon started on demand or at login
  -> status / remediation
      -> machine health + one result per eligible user
      -> stable reason codes, versions, and redacted log locations
```

The machine package owns product binaries. The user activation layer owns user-scoped Guard state and harness integration. No package postinstall action may infer a developer home from the root or SYSTEM account.

## Requirements

### MDM-R001: Native, signed, self-contained artifacts

The release pipeline must produce artifacts that require no preinstalled Python, `pip`, `pipx`, `uv`, compiler, or public package-registry access.

Common requirements:

- Bundle a pinned Python runtime and all production dependencies, or produce an equivalent standalone executable distribution.
- Install only versioned product files plus explicit mutable state directories.
- Include a signed release manifest containing product version, build ID, source commit, supported OS and architecture, file hashes, policy schema version, and installer identity.
- Publish SHA-256 checksums, SBOM, and build provenance for every MDM artifact.
- Keep credentials, customer policy, and per-user state out of the installer payload.
- Fail installation before modifying the endpoint if signature, architecture, OS, disk-space, or payload-integrity checks fail.

macOS requirements:

- Produce a component `.pkg` with a payload, stable package identifier and receipt version, and valid install location.
- Sign the package with a Developer ID Installer certificate.
- Sign applicable executable code, notarize the distributed artifact, and staple the notarization ticket.
- Install the machine runtime into a root-owned, non-user-writable location. The final path must be documented and stable across patch releases.
- Support silent installation with `/usr/sbin/installer` and detection with `pkgutil` plus Guard's signed manifest.
- If login or background items ship, provide stable bundle, team, and service identifiers suitable for Apple's Service Management MDM payload.

Windows requirements:

- Produce an Authenticode-signed MSI or signed bootstrapper suitable for wrapping as an Intune Win32 `.intunewin` package.
- Install the runtime under `%ProgramFiles%` and machine state under `%ProgramData%`, protected by standard ACLs.
- Provide silent install, repair, upgrade, and uninstall commands with conventional Windows installer return codes.
- Publish stable MSI product and upgrade identities, display version, publisher, architecture, and detection metadata.
- Do not depend on an interactive desktop, user profile, PowerShell execution-policy weakening, or package-registry access during machine installation.

### MDM-R002: Machine and per-user deployment contexts

Guard must explicitly support device-context installation followed by user-context activation.

- Add an idempotent, noninteractive user activation command that accepts an explicit target home and user identity.
- Reject root or SYSTEM as the implicit target for user activation.
- Create user files with the target user's ownership and restrictive permissions.
- Detect eligible local users without activating service accounts, disabled accounts, temporary accounts, or the MDM agent account.
- Activate users at next login when no interactive user exists during machine installation.
- Support multiple eligible users on one endpoint without sharing tokens, approval state, receipts, keyring items, or databases.
- Detect and connect supported harnesses installed after initial activation.
- Make activation atomic and safely repeatable after interruption, package upgrade, harness upgrade, and MDM remediation.
- Preserve and restore preexisting harness configuration using the existing adapter backup contracts.
- Never open a browser, connect Guard Cloud, display a notification, or prompt for approval during silent activation.
- Report machine installation and each user's activation status separately.

The first-release commands should expose a stable contract equivalent to:

```text
hol-guard mdm activate --home <absolute-home> --user <identity> --json
hol-guard mdm status --scope machine --json
hol-guard mdm status --scope user --home <absolute-home> --json
hol-guard mdm repair --home <absolute-home> --json
hol-guard mdm deactivate --home <absolute-home> --json
```

Exact command names may change during design review, but the machine/user scope separation and JSON semantics are required.

### MDM-R003: Managed policy authority and self-protection

Guard must load validated machine-managed configuration from platform-native policy locations:

- macOS: a documented managed preferences domain, proposed as `org.hol.guard`.
- Windows: a documented policy registry path, proposed as `HKLM\Software\Policies\HOL\Guard`.

Both adapters must map to one versioned managed-policy schema. Managed input must be type-checked, size-bounded, fail-closed for locked security settings, and surfaced in status by schema version and content hash without exposing secrets.

Policy composition must be monotonic:

1. Built-in required protections establish a non-reducible floor.
2. Valid machine-managed policy and signed Cloud team policy are managed authorities.
3. For action strength, the strongest managed requirement wins.
4. Machine-managed locks prevent user, saved-decision, home, workspace, dashboard, or CLI input from weakening the locked value.
5. Local sources may strengthen managed policy.
6. Conflicting non-action managed settings use documented deterministic precedence and emit a `managed_policy_conflict` diagnostic.
7. Missing, malformed, stale, wrong-scope, or rollback policy never silently falls back to a weaker outcome.

The managed schema must cover at least:

- security level, mode, action overrides, receipt redaction, telemetry, and Cloud sync enablement;
- approval and remembered-trust limits;
- allowed Cloud issuer and workspace enrollment boundaries;
- proxy mode and approved private CA paths;
- update owner, channel, version ceiling/floor, and downgrade policy;
- local setting locks and whether local users may strengthen specific controls;
- permitted harnesses and required protection surfaces;
- daemon startup mode and health interval;
- uninstall, deactivate, and repair authorization policy.

When `install_owner = "mdm"`:

- `hol-guard update` must return a stable managed-update reason and make no changes.
- `hol-guard uninstall --self` and user deactivation must require authorized administrator context or an MDM removal token that is bound, short-lived, and auditable.
- Standard users must not be able to modify machine binaries, release manifests, managed policy, lifecycle registrations, or machine logs.
- Direct deletion or corruption must produce tamper diagnostics and a repairable MDM state.
- Removing the MDM profile must not automatically relax policy unless the administrator explicitly configures that behavior.

### MDM-R004: Lifecycle, detection, remediation, and updates

Every MDM artifact must ship a documented lifecycle contract.

Detection and health:

- A signed machine manifest and native installer identity are the authoritative installation markers.
- A stable JSON schema must report installed version, build ID, signature state, package identity, architecture, managed-policy state, update owner, daemon state, and one activation result per eligible user.
- Human-readable text is not an automation contract.
- Status must distinguish absent, installed, activated, protected, degraded, repairable, policy-invalid, tampered, and unsupported states.
- Each nonhealthy state must include stable reason codes and a safe remediation hint.
- Detection commands must be read-only, bounded, prompt-free, and suitable for standard Intune detection scripts and MDM extension attributes.

Lifecycle operations:

- Install, activate, repair, deactivate, upgrade, rollback, and uninstall must be idempotent where applicable.
- MDM owns version changes for MDM-managed installs. In-product PyPI updates must not race or overwrite the package.
- In-place upgrades must preserve compatible user state and run explicit, versioned migrations.
- Downgrades must be rejected by default and permitted only through an authenticated MDM rollback policy with schema compatibility checks.
- Failed upgrades must leave either the previous healthy version or a machine-detectable repair state.
- Uninstall must remove machine runtime, lifecycle registrations, managed hooks, shims, and temporary files while preserving or deleting user evidence according to explicit administrator policy.
- A package uninstall must not leave a running daemon or a harness hook that references a removed runtime.
- New users and newly installed harnesses must converge through login activation or scheduled MDM remediation without reinstalling the machine package.

Operational contract:

- Emit redacted machine logs to a documented machine path and user activation logs to documented user paths.
- Bound log size and retention; never log tokens, approval secrets, proxy credentials, raw sensitive commands, or private key material.
- Publish vendor-neutral install, detection, remediation, and uninstall scripts plus tested Intune examples.
- Define installer and CLI exit codes, including Windows reboot-required behavior.
- Provide a versioned JSON schema for MDM status and lifecycle results.

### MDM-R005: Enterprise networking, trust, and offline behavior

All Guard HTTP clients, including `requests`, `urllib`, update checks, Cloud sync, OAuth/device flows, policy bundles, advisory feeds, and package intelligence, must use one enterprise network policy.

- Support platform system proxy configuration and an explicit managed HTTPS proxy.
- Support an additive administrator-approved CA bundle without disabling normal certificate validation.
- Keep TLS verification enabled in every mode. No managed option may set insecure verification.
- Do not store proxy credentials in plaintext policy, logs, command arguments, or user-readable machine files.
- Ensure detached or login-started daemon processes receive the same managed network configuration as foreground CLI commands.
- Add a prompt-free network diagnostic that reports DNS, proxy selection, TLS trust, endpoint reachability, and redacted failure reasons.
- Publish a machine-readable and human-readable endpoint manifest listing hostname, port, purpose, required/optional status, HTTP methods, data classification, and offline fallback.
- Separate required Guard Cloud endpoints from optional public package-registry intelligence endpoints.
- Allow administrators to disable direct public-registry access and use signed cached intelligence or approved internal mirrors.
- Make the installer fully offline. Installation and rollback may not require PyPI, GitHub, or Guard Cloud.
- Preserve local protection during proxy failure, TLS inspection failure, Cloud outage, or network isolation. Status must show stale remote data without weakening the local policy floor.

## Security and privacy invariants

- Standard users cannot replace a machine-owned executable or managed policy file.
- MDM authority cannot be claimed through environment variables, workspace files, user preferences, command arguments, or unsigned local files.
- Managed policy identifiers, hashes, and diagnostics may be logged; policy secrets and credentials may not.
- Per-user tokens and keyring material never cross user boundaries or enter `%ProgramData%` or a shared macOS machine-state directory.
- Repair never grants new trust, clears approval history, lowers policy, or silently reconnects Cloud identity.
- Uninstall authorization is separate from approval authorization for agent actions.
- Installer and lifecycle scripts quote every path and handle spaces, Unicode, and adversarial user names.
- No release gate may require disabling Gatekeeper, notarization, Windows signature validation, antivirus, EDR, WDAC, AppLocker, or TLS verification.

## User and administrator experience

### Silent device deployment

1. MDM validates requirements and installs the signed machine package.
2. Installation records the native package identity and signed Guard manifest.
3. If an eligible user is logged in, MDM invokes user activation in that user's context; otherwise activation waits for login.
4. Detection reports machine and user states independently.
5. No browser, notification preview, terminal window, or approval prompt appears.

### Drift remediation

1. MDM runs read-only status.
2. A repairable reason code identifies a missing hook, PATH shim, lifecycle registration, permission, or versioned migration.
3. MDM invokes scoped repair.
4. Repair changes only Guard-owned integration material and returns before/after state.
5. Status confirms protection or reports an actionable failure without falsely marking the app installed.

### Managed removal

1. MDM invokes authorized per-user deactivation for every activated user.
2. Guard stops user daemons and restores reversible harness changes.
3. The native package uninstall removes machine files and lifecycle registrations.
4. Detection confirms absence and reports any intentionally retained evidence.

## Acceptance criteria

### Packaging

- Clean macOS and Windows endpoints install without Python, package managers, public network access, or interactive UI.
- macOS signature, notarization, staple, package receipt, payload, version, and architecture checks pass.
- Windows Authenticode, MSI/installer metadata, silent install, repair, upgrade, uninstall, and Intune detection checks pass.
- Files installed into machine locations are not writable by standard users.
- Published checksums, SBOMs, and provenance match the shipped artifacts.

### Activation and policy

- Root/SYSTEM installation followed by standard-user activation creates no incorrectly owned user files.
- Multiple local users receive isolated state and independent activation results.
- New users and late-installed supported harnesses converge without reinstalling Guard.
- Every locked setting resists CLI, dashboard, saved-decision, home, and workspace attempts to weaken it.
- Local tightening remains possible where allowed.
- MDM and signed Cloud policy conflicts resolve deterministically and are observable.
- Standard users cannot self-update, deactivate required protection, or self-uninstall an MDM-owned install.

### Lifecycle and networking

- Detection output is schema-valid, prompt-free, read-only, and stable across patch releases.
- Install, activation, repair, upgrade, rollback, and removal pass interruption and retry tests.
- Proxy and private-CA tests pass for CLI and detached daemon traffic without disabling TLS verification.
- Offline install, local enforcement during outage, and cached policy/intelligence behavior pass.
- Logs are bounded, collectable through MDM, and pass secret-redaction tests.

### Certification

- CI covers the approved macOS and Windows architecture/OS matrix with standard-user and administrator contexts.
- A real MDM validates install, detection, remediation, update, rollback, and removal on each customer platform.
- Pilot telemetry meets the agreed deployment and activation success thresholds with no policy weakening or cross-user data exposure.

## Success metrics

- At least 99% successful machine installation across the supported pilot fleet.
- At least 98% successful activation for eligible users within 15 minutes of login or MDM remediation.
- At least 99% agreement between MDM detection state and Guard's detailed health state.
- Zero standard-user policy downgrades, unauthorized updates, or unauthorized removals.
- Zero secrets in installer, lifecycle, status, network diagnostic, or MDM-collected logs.
- Failed upgrades automatically retain the previous healthy version or produce a repairable state.

## Rollout gates

1. **Contract gate:** approve paths, identities, schemas, precedence, authorization, exit codes, supported OS/architectures, and customer MDM.
2. **Packaging gate:** signed offline artifacts install, upgrade, repair, and uninstall on clean VMs.
3. **Managed-policy gate:** monotonic precedence, locks, tamper detection, and update/uninstall ownership pass adversarial tests.
4. **User-activation gate:** multi-user, no-user-at-install, late-user, late-harness, and interrupted activation tests pass.
5. **Network gate:** direct, system proxy, explicit proxy, private CA, blocked registry, and offline scenarios pass.
6. **MDM lab gate:** real vendor deployment passes detection, remediation, update, rollback, and removal.
7. **Pilot gate:** phased customer rollout shows healthy activation and no security or support stop condition.

Stop rollout on signature or notarization failure, policy weakening, wrong-user ownership, cross-user data exposure, false healthy detection, unrecoverable upgrade, TLS verification bypass, or unmanaged removal.

## Dependencies and risks

- Code-signing and notarization certificates require protected release credentials, rotation, and incident procedures.
- Bundled Python and native dependencies increase artifact size and cross-architecture testing requirements.
- Harness updates can overwrite hooks or configuration, so continuous reconciliation is part of the product contract.
- macOS Keychain and Windows Credential Manager operations must execute in the intended user session.
- Security products may block unsigned wrappers or scripts; signed publisher identities and a process/file/network manifest are required for customer allowlisting.
- MDM vendors differ in user-context execution, login triggers, script result handling, and package detection.
- Existing user-managed installations need a supported migration path that preserves state without allowing a user-owned runtime to shadow the machine runtime.

## Open decisions

Implementation defaults are frozen in [ADR 0001](./adr/0001-mdm-managed-install-contract.md): stable paths and identifiers, machine precedence for non-action conflicts, on-demand daemons, strongest-action composition, MDM-owned updates, downgrade/removal fail-closed behavior, and evidence preservation by default.

The remaining items are launch-customer certification inputs rather than code decisions:

- Customer MDM vendor and whether macOS, Windows, or both are in the first rollout.
- Required macOS CPU architectures and minimum macOS version.
- Required Windows CPU architectures, editions, and minimum Windows version.
- Final Apple team identity and Windows Authenticode publisher identity.
- Whether zero-touch Guard Cloud workspace enrollment is required for the first customer or remains a separate user/admin step.
- Required deployment and activation success thresholds if the defaults in this PRD are not accepted.

## Required deliverables

- Signed and notarized macOS package with uninstall and MDM examples.
- Signed Windows installer and Intune Win32 package recipe with detection rules.
- Self-contained runtime and reproducible packaging pipeline.
- Versioned managed-policy and MDM status JSON schemas.
- Per-user activation, status, repair, and deactivation commands.
- Vendor-neutral lifecycle scripts and customer-vendor profiles/scripts.
- Endpoint allowlist, proxy/private-CA guide, offline deployment guide, and support runbook.
- MDM OS/architecture test matrix, release checklist, pilot plan, rollback plan, and collected evidence.

## Primary references

- [Apple: Distribute packages to Mac computers](https://support.apple.com/guide/deployment/dep873c25ac4/web)
- [Apple: Manage login items and background tasks on Mac](https://support.apple.com/guide/deployment/depdca572563/web)
- [Apple: Managed Login Items payload settings](https://support.apple.com/guide/deployment/managed-login-items-payload-settings-dep07b92494/web)
- [Microsoft: Add macOS line-of-business apps to Intune](https://learn.microsoft.com/en-us/intune/app-management/deployment/add-lob-macos)
- [Microsoft: Add and manage Win32 apps in Intune](https://learn.microsoft.com/en-us/intune/app-management/deployment/add-win32)
- [Microsoft: Windows app deployment contexts](https://learn.microsoft.com/en-us/intune/app-management/deployment/deploy-windows)
- [Requests: proxies and custom CA bundles](https://docs.python-requests.org/en/latest/user/advanced/)
