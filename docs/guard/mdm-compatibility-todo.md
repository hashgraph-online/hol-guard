# HOL Guard MDM Compatibility TODO

## Purpose

This checklist implements the P0 requirements in the [HOL Guard MDM Compatibility PRD](./mdm-compatibility-prd.md). A checked item means the code, tests, documentation, and release evidence for that item are merged. Design notes or partial platform support do not count as complete.

## Requirement map

| Requirement | Scope | Task groups |
| --- | --- | --- |
| MDM-R001 | Signed self-contained artifacts | A, C, D, J |
| MDM-R002 | Machine install and per-user activation | A, B, E, F, I |
| MDM-R003 | Managed policy and self-protection | A, B, G, I |
| MDM-R004 | Lifecycle, detection, remediation, updates | B, C, D, F, G, I, J |
| MDM-R005 | Proxy, private CA, endpoint contract, offline behavior | H, I, J |

## Completion rules

- Keep task IDs stable in issues, commits, tests, and release evidence.
- Add focused tests with each behavior change; do not defer all verification to the certification phase.
- Run macOS and Windows packaging work in isolated CI jobs with protected signing credentials.
- Never put signing material, removal tokens, proxy credentials, customer policy, or private CA keys in the repository.
- Stop if implementation would require disabling OS security, TLS verification, antivirus, EDR, WDAC, or AppLocker.

## Current implementation status

The shared runtime, managed policy, lifecycle CLI, enterprise network layer, native package sources, unsigned artifact proof, schemas, CI matrix, and administrator documentation are implemented on `feat/mdm-compatibility`. Checklist boxes remain open until merge because this file defines “checked” as merged with release evidence.

Production certification still requires external inputs unavailable to the repository: Apple Developer ID/notarization credentials, Windows Authenticode credentials, the launch customer's MDM vendor and OS/architecture scope, test devices, Cloud enrollment choice, and security/release/support/customer-IT sign-off. The evidence form is [mdm-release-evidence-template.md](./mdm-release-evidence-template.md).

## Critical path

1. Complete group A before freezing schemas or installer identities.
2. Complete the shared foundation in group B before platform lifecycle implementations.
3. Build the self-contained runtime in group C before finishing native packages in group D.
4. Develop user activation, lifecycle, self-protection, and networking in groups E-H against the frozen contracts.
5. Complete group I before customer deployment and group J before production compatibility is declared.

## A. Contract and architecture freeze

- [ ] **MDM-T001 (R001-R005):** Record the launch customer's MDM vendor, platforms, minimum OS versions, CPU architectures, device/user assignment model, proxy/TLS inspection, and required Cloud enrollment flow.
- [ ] **MDM-T002 (R001):** Approve stable macOS package, bundle, team, receipt, binary, and service identifiers.
- [ ] **MDM-T003 (R001):** Approve stable Windows publisher, MSI product/upgrade identities, install scope, binary names, and registry roots.
- [ ] **MDM-T004 (R001-R002):** Approve machine runtime, machine state, user state, logs, backups, and command-discovery paths for both platforms.
- [ ] **MDM-T005 (R002):** Define eligible-user discovery and exclusions for service, disabled, temporary, MDM-agent, and noninteractive accounts.
- [ ] **MDM-T006 (R002):** Freeze machine-installed, user-activated, protected, degraded, repairable, tampered, and unsupported state definitions.
- [ ] **MDM-T007 (R003):** Freeze the managed-policy schema, source identities, lock semantics, and monotonic merge truth table.
- [ ] **MDM-T008 (R003):** Decide deterministic precedence for non-action conflicts between machine MDM and signed Guard Cloud policy.
- [ ] **MDM-T009 (R003-R004):** Approve MDM update owner, channel, version floor/ceiling, downgrade, rollback, and removal authorization contracts.
- [ ] **MDM-T010 (R004):** Freeze lifecycle CLI JSON schemas, reason codes, exit codes, and Windows reboot-required mappings.
- [ ] **MDM-T011 (R005):** Freeze proxy modes, private-CA behavior, endpoint manifest schema, offline fallback, and internal registry/mirror behavior.
- [ ] **MDM-T012 (R001-R005):** Add an architecture decision record linking the approved contracts and threat model.

## B. Shared managed-install foundation

- [ ] **MDM-T013 (R001):** Add a build-time release-manifest model with version, build ID, commit, architecture, policy schema, installer identity, and file hashes.
- [ ] **MDM-T014 (R001):** Verify the release manifest before executing any machine-owned Guard command and return stable tamper reasons.
- [ ] **MDM-T015 (R002-R004):** Add a typed managed-install context that separates machine paths, target user, target home, workspace, and mutable user state.
- [ ] **MDM-T016 (R002):** Reject implicit root/SYSTEM user activation and validate that explicit homes belong to the intended local identity.
- [ ] **MDM-T017 (R002):** Add secure target-user file creation with correct ownership, atomic writes, symlink defense, and restrictive permissions/ACLs.
- [ ] **MDM-T018 (R003):** Add the versioned platform-neutral managed-policy model and strict external-input validation.
- [ ] **MDM-T019 (R003):** Add macOS managed-preferences and Windows policy-registry readers behind the same interface.
- [ ] **MDM-T020 (R003):** Implement monotonic policy composition, locked fields, strongest-action resolution, and conflict diagnostics.
- [ ] **MDM-T021 (R003):** Prevent saved decisions, home config, workspace config, dashboard writes, CLI writes, and environment variables from weakening locked values.
- [ ] **MDM-T022 (R003-R004):** Add managed installation metadata to `status`, `doctor`, diagnostics, receipts, and support exports without exposing policy content or secrets.
- [ ] **MDM-T023 (R004):** Add versioned machine and user lifecycle result schemas under `schemas/`.
- [ ] **MDM-T024 (R002-R004):** Add the `mdm` command group, or approved equivalent, with machine status and scoped activate/status/repair/deactivate commands.
- [ ] **MDM-T025 (R004):** Make all MDM status operations read-only, prompt-free, time-bounded, and independent of browser or desktop availability.
- [ ] **MDM-T026 (R004):** Add stable result classification and nonhealthy reason codes with safe remediation hints.

Likely working set: `src/codex_plugin_scanner/guard/config.py`, `cli/commands_parser_*.py`, `cli/commands_dispatch_*.py`, `daemon/manager.py`, new `guard/mdm/` modules, `schemas/`, and focused `tests/test_guard_mdm_*.py` files.

## C. Self-contained runtime and release pipeline

- [ ] **MDM-T027 (R001):** Select and document the supported standalone Python/runtime packaging approach.
- [ ] **MDM-T028 (R001):** Produce deterministic platform runtime bundles with pinned production dependencies and no install-time package resolution.
- [ ] **MDM-T029 (R001):** Prove runtime bundles work without system Python, `pip`, `pipx`, `uv`, compilers, or user PATH changes.
- [ ] **MDM-T030 (R001):** Generate per-artifact SHA-256 files, SBOMs, and provenance tied to the release manifest.
- [ ] **MDM-T031 (R001):** Add dependency-license collection and review for redistributed runtimes and native libraries.
- [ ] **MDM-T032 (R001):** Add reproducibility checks or document and gate every nondeterministic build input.
- [ ] **MDM-T033 (R001):** Isolate protected signing and notarization jobs from untrusted pull-request code.
- [ ] **MDM-T034 (R001):** Add signing-certificate rotation, revocation, expiry monitoring, and emergency release procedures to the release runbook.
- [ ] **MDM-T035 (R001-R004):** Publish artifacts with consistent semantic version, manifest version, native installer version, and Cloud-visible version.

Likely working set: `.github/workflows/publish.yml`, a new `packaging/` tree, release scripts under `scripts/`, and release documentation.

## D. Native platform packages

### macOS

- [ ] **MDM-T036 (R001):** Build a component `.pkg` with a real payload, stable receipt, version, architecture requirements, and root-owned machine runtime.
- [ ] **MDM-T037 (R001):** Code-sign executable payloads, sign the package with Developer ID Installer, notarize, staple, and validate every release.
- [ ] **MDM-T038 (R001-R004):** Implement silent preinstall/postinstall behavior that never targets root's home and leaves explicit machine installation state.
- [ ] **MDM-T039 (R002-R004):** Add the approved login activation mechanism and stable Service Management identifiers when required.
- [ ] **MDM-T040 (R004):** Provide signed install, detection, activation, remediation, and removal examples for generic Apple MDM and the customer vendor.
- [ ] **MDM-T041 (R004):** Validate package replacement, patch upgrade, authorized rollback, failed-install recovery, and complete receipt removal.
- [ ] **MDM-T042 (R001-R004):** Verify Intune macOS LOB requirements if Intune manages customer Macs.

### Windows

- [ ] **MDM-T043 (R001):** Build the approved MSI or signed bootstrapper with machine runtime under `%ProgramFiles%` and machine state under `%ProgramData%`.
- [ ] **MDM-T044 (R001):** Authenticode-sign all executable installer payloads and validate publisher identity in CI.
- [ ] **MDM-T045 (R001-R004):** Implement silent install, repair, upgrade, rollback, and uninstall with conventional installer return codes and logs.
- [ ] **MDM-T046 (R002-R004):** Add the approved user-login activation mechanism without requiring interactive administrator privileges.
- [ ] **MDM-T047 (R004):** Create the `.intunewin` recipe, install/uninstall commands, requirements, detection rules, return-code map, and supersedence guidance.
- [ ] **MDM-T048 (R004):** Validate user-context and device-context assignments and document the supported assignment contract.
- [ ] **MDM-T049 (R001-R004):** Test clean install, in-place upgrade, authorized rollback, repair, uninstall, and reinstall through Intune.

## E. Per-user activation and reconciliation

- [ ] **MDM-T050 (R002):** Implement idempotent noninteractive activation for an explicit user and home.
- [ ] **MDM-T051 (R002):** Ensure activation defaults to skipping browser launch, Cloud pairing, notification setup, and approval prompts.
- [ ] **MDM-T052 (R002):** Reuse adapter backup/restore contracts and make partial activation rollback atomic.
- [ ] **MDM-T053 (R002):** Isolate databases, OAuth credentials, keyring records, tokens, receipts, approval state, and daemon state per user.
- [ ] **MDM-T054 (R002):** Activate a logged-in eligible user after device install and defer safely when nobody is logged in.
- [ ] **MDM-T055 (R002):** Activate newly eligible users at their first login without reinstalling the machine package.
- [ ] **MDM-T056 (R002-R004):** Detect newly installed supported harnesses and connect or report them according to managed policy.
- [ ] **MDM-T057 (R002-R004):** Reconcile hooks, shims, PATH integration, runtime overlays, and daemon compatibility after Guard or harness upgrades.
- [ ] **MDM-T058 (R002):** Add multi-user concurrency and interrupted-activation locking without cross-user ownership changes.
- [ ] **MDM-T059 (R002):** Add migration from user-managed PyPI installs to the machine runtime, including shadowed-command detection and reversible state migration.
- [ ] **MDM-T060 (R002-R004):** Add user deactivation that stops the correct daemon and restores Guard-owned harness changes without touching unrelated user data.

## F. Detection, health, and remediation

- [ ] **MDM-T061 (R004):** Implement machine health from native package identity, release-manifest integrity, architecture, policy adapter, and lifecycle registration.
- [ ] **MDM-T062 (R004):** Implement per-user health from activation state, harness contracts, shims, hooks, daemon compatibility, policy status, and Cloud freshness.
- [ ] **MDM-T063 (R004):** Return separate machine and per-user results; never report machine installation as user protection.
- [ ] **MDM-T064 (R004):** Add repairable versus nonrepairable classification and ensure repair never grants trust or weakens policy.
- [ ] **MDM-T065 (R004):** Implement scoped remediation for permissions, missing hooks, stale shims, lifecycle registration, and versioned migrations.
- [ ] **MDM-T066 (R004):** Add machine and user log locations, rotation, retention, redaction, and MDM diagnostic collection guidance.
- [ ] **MDM-T067 (R004):** Provide vendor-neutral detection and remediation scripts with shell/PowerShell linting and signature options.
- [ ] **MDM-T068 (R004):** Provide Intune detection/remediation scripts whose stdout, stderr, and exit behavior match Intune contracts.
- [ ] **MDM-T069 (R004):** Add schema compatibility tests so patch releases do not break deployed detection scripts.
- [ ] **MDM-T070 (R004):** Add performance budgets for fleet status and remediation commands.

## G. Managed updates, removal, and tamper response

- [ ] **MDM-T071 (R003-R004):** Disable PyPI/in-product updates when managed policy declares MDM ownership and return a stable no-change result.
- [ ] **MDM-T072 (R003-R004):** Require authorized administrator or MDM removal authorization for self-uninstall and required user deactivation.
- [ ] **MDM-T073 (R003):** Design removal authorization so it is scoped, short-lived, replay-resistant, auditable, and absent from command-line history.
- [ ] **MDM-T074 (R003-R004):** Protect machine binaries, manifest, policy adapter, lifecycle registrations, and logs with platform ACLs.
- [ ] **MDM-T075 (R003-R004):** Detect deleted, modified, shadowed, downgraded, wrong-owner, or wrong-permission machine files.
- [ ] **MDM-T076 (R003-R004):** Make tampered states fail to a non-weaker policy and expose bounded repair guidance.
- [ ] **MDM-T077 (R004):** Add versioned state migrations with forward compatibility checks and interruption recovery.
- [ ] **MDM-T078 (R004):** Reject downgrade by default and implement authenticated MDM rollback with schema compatibility checks.
- [ ] **MDM-T079 (R004):** Ensure uninstall stops all owned daemons and removes or restores every Guard-owned hook, shim, overlay, login item, task, and temporary file.
- [ ] **MDM-T080 (R004):** Implement explicit administrator choices for preserving or deleting receipts, logs, Cloud credentials, and user evidence during removal.

## H. Enterprise network and offline operation

- [ ] **MDM-T081 (R005):** Inventory every Guard HTTP client and route it through one enterprise network-policy abstraction.
- [ ] **MDM-T082 (R005):** Implement platform system proxy and explicit managed HTTPS proxy modes with consistent CLI/daemon behavior.
- [ ] **MDM-T083 (R005):** Add approved private-CA bundles additively while preserving public trust and mandatory certificate validation.
- [ ] **MDM-T084 (R005):** Keep proxy credentials out of policy, arguments, logs, diagnostics, and user-readable machine files; use approved OS credential storage when credentials are required.
- [ ] **MDM-T085 (R005):** Ensure detached and login-started daemons receive the same network and trust configuration as foreground commands.
- [ ] **MDM-T086 (R005):** Add prompt-free DNS, proxy, TLS, endpoint, and clock diagnostics with stable redacted reason codes.
- [ ] **MDM-T087 (R005):** Create versioned machine-readable and human-readable endpoint manifests with purpose, port, required status, methods, data class, and fallback.
- [ ] **MDM-T088 (R005):** Separate Guard Cloud endpoints from optional public registry intelligence and support administrator-disabled direct registry access.
- [ ] **MDM-T089 (R001-R005):** Prove clean install, upgrade, rollback, and uninstall work without internet access.
- [ ] **MDM-T090 (R005):** Prove local enforcement remains active during Cloud outage, proxy failure, TLS failure, and network isolation while freshness diagnostics remain accurate.
- [ ] **MDM-T091 (R005):** Add internal mirror and signed cached-intelligence documentation and tests.
- [ ] **MDM-T092 (R005):** Add negative tests proving no code path disables TLS verification or accepts an unapproved CA.

## I. Test matrix and adversarial verification

- [ ] **MDM-T093 (R001-R005):** Expand CI to the approved macOS/Windows OS and architecture matrix; record unsupported combinations explicitly.
- [ ] **MDM-T094 (R001-R004):** Test administrator install plus standard-user activation with no root/SYSTEM-owned user files.
- [ ] **MDM-T095 (R002-R004):** Test no-user-at-install, first login, multiple users, fast user switching, deleted users, renamed homes, and concurrent activation.
- [ ] **MDM-T096 (R002-R004):** Test late harness installation, harness upgrade overwrites, MDM remediation, and adapter backup restoration.
- [ ] **MDM-T097 (R003):** Execute the full managed-policy truth table against CLI, dashboard, saved decisions, home, workspace, environment, and signed Cloud inputs.
- [ ] **MDM-T098 (R003-R004):** Attempt standard-user update, uninstall, deactivation, binary replacement, manifest edit, policy edit, PATH shadowing, permission change, and downgrade.
- [ ] **MDM-T099 (R001-R004):** Test installer interruption, disk exhaustion, locked files, reboot-required outcomes, rollback, repair, and retry.
- [ ] **MDM-T100 (R004):** Validate detection against absent, healthy, degraded, repairable, tampered, policy-invalid, unsupported, and partially removed fixtures.
- [ ] **MDM-T101 (R004-R005):** Run secret-redaction tests over installer logs, lifecycle logs, status JSON, network diagnostics, and MDM-collected bundles.
- [ ] **MDM-T102 (R005):** Test direct network, system proxy, explicit proxy, authenticated proxy, private CA, blocked registry, DNS failure, clock skew, and offline operation.
- [ ] **MDM-T103 (R001-R004):** Validate WDAC/AppLocker and macOS Gatekeeper behavior using signed publisher identities without broad exclusions.
- [ ] **MDM-T104 (R001-R005):** Run real-MDM install, detection, activation, remediation, update, rollback, and removal on every launch-customer platform.

## J. Documentation, release, and pilot

- [ ] **MDM-T105 (R001-R004):** Publish administrator install, assignment, detection, activation, remediation, update, rollback, and uninstall guides.
- [ ] **MDM-T106 (R001-R005):** Publish the process/file/path/identifier/network manifest for endpoint security and MDM teams.
- [ ] **MDM-T107 (R005):** Publish proxy, TLS inspection, private CA, endpoint allowlist, internal mirror, and offline deployment guides.
- [ ] **MDM-T108 (R002-R004):** Publish user-managed-to-MDM migration and MDM-to-user-managed rollback guidance.
- [ ] **MDM-T109 (R004):** Update the enterprise packet, architecture, testing matrix, troubleshooting, incident response, and release checklist with the managed-install contract.
- [ ] **MDM-T110 (R001-R005):** Add an MDM release evidence template containing signatures, notarization, hashes, SBOM/provenance, platform matrix, lifecycle tests, and real-MDM results.
- [ ] **MDM-T111 (R001-R005):** Define pilot rings, success thresholds, health dashboards, support ownership, rollback triggers, and stop conditions.
- [ ] **MDM-T112 (R001-R005):** Run an internal canary, then customer IT canary, then limited developer pilot; record evidence for every rollout gate.
- [ ] **MDM-T113 (R001-R005):** Close every PRD open decision or record an approved scoped deferral that does not weaken a P0 acceptance criterion.
- [ ] **MDM-T114 (R001-R005):** Obtain security, release engineering, support, and launch-customer IT sign-off before declaring production MDM compatibility.

## Required verification commands

The final command set will be implemented with the packaging work. At minimum, release evidence must include equivalents of:

```bash
# Repository quality
uv run --no-sync python -m ruff check src/
uv run --no-sync basedpyright --level error
uv run --no-sync pytest tests/test_guard_mdm_*.py --tb=short
uv run --no-sync pytest --tb=short

# macOS artifact
pkgutil --check-signature <hol-guard.pkg>
spctl -a -vv -t install <hol-guard.pkg>
xcrun stapler validate <hol-guard.pkg>
sudo installer -pkg <hol-guard.pkg> -target /
pkgutil --pkg-info <approved-package-id>

# Windows artifact (PowerShell / cmd in the Windows CI or MDM lab)
Get-AuthenticodeSignature <installer>
msiexec /i <hol-guard.msi> /qn /norestart /l*v <install-log>
hol-guard mdm status --scope machine --json
msiexec /x <product-code> /qn /norestart /l*v <uninstall-log>
```

Replace artifact and package-identity placeholders only after the contract tasks freeze those values.
