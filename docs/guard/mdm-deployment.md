# HOL Guard MDM deployment

## Supported contract

HOL Guard uses package identity `org.hol.guard` on macOS and the stable MSI upgrade code `B15D39B1-6395-4FEA-98A9-5D734DDC455D` on Windows. The package owns the machine runtime; activation owns only the target user's `~/.hol-guard` state and reversible harness integrations.

Builds require Python 3.12, the locked `uv` environment, and PyInstaller. macOS additionally requires Xcode command-line tools; Windows requires WiX 4 and SignTool. Production artifacts must be signed and, on macOS, notarized and stapled. Unsigned builds are test fixtures only.

## Vendor-neutral deployment contract

All MDM products use the same signed package, machine-policy schema, lifecycle commands, JSON status schema, and exit-code contract. Organization-specific assignment, proxy, trust, enrollment, retention, and policy values remain external configuration. Vendor adapters may translate these contracts into native packaging and detection formats, but must not fork Guard behavior or require a custom binary.

### Policy-bundle signing trust

Organizations that enable signed Guard Cloud policy bundles must provision the initial workspace signing trust through the optional top-level `policyBundleKeyring` field in the machine policy. The value uses the `guard-policy-keyring.v1` contract and contains:

- `purpose: "policy_bundle"`;
- a non-empty `workspaceId`;
- `keys`, containing zero or more workspace-bound PEM-encoded RSA public verification keys with their SHA-256 fingerprints, state, purpose, and optional validity window. RSA moduli must be at least 2048 bits.

The wrapper is strict: it contains exactly `contractVersion`, `purpose`, `workspaceId`, and `keys`. Each key requires `keyId`, `publicKeyPem`, `fingerprintSha256`, `state`, `purpose`, and `workspaceId`; only `validFrom` and `validUntil` are optional. Unknown wrapper or key fields are rejected. `fingerprintSha256` is the lowercase hexadecimal SHA-256 digest of the normalized PEM text encoded as UTF-8: CRLF line endings are converted to LF, then leading and trailing whitespace is stripped. It is not a fingerprint of decoded DER bytes.

An empty key list is an explicit managed disable/revocation state. A Cloud response's `policyBundleVerificationKeys` value is rotation metadata, not initial trust, and cannot replace this machine-managed anchor.

Guard never uses trust-on-first-use. In the v1 production contract, MDM is the supported initial provisioning path; there is no Cloud-sync or CLI bootstrap path for a fresh unmanaged local anchor. An unmanaged installation without an out-of-band pre-provisioned compatibility anchor rejects policy bundles with `trusted_key_unavailable` instead of trusting a key delivered by sync. Key state `active` is required for live enforcement. `grace` may be retained as rotation metadata, but does not authorize a current bundle; `revoked` is always rejected.

During `mdm activate` and `mdm repair`, Guard validates and normalizes the managed keyring, then atomically stores a diagnostic-only per-user mirror, an empty quarantined local-anchor slot, and provenance bound to the managed-policy content hash, workspace, and exact mirror before starting user protection. The diagnostic mirror is never a verification anchor. Rotation replaces it rather than merging keys. Machine management owns the policy-signing trust domain: activation quarantines the user-local anchor slot, and removing `policyBundleKeyring` or deactivating management atomically removes the mirror, its legacy provenance, and the legacy shared slot. Authorized repair and deactivation force that cleanup even if the user-writable provenance row was removed or malformed, so modified user state cannot survive managed teardown as signing authority.

The user-store mirror and its unkeyed provenance hashes are never cryptographic authority. Every bundle validation resolves managed anchors from the live machine policy (or, on Unix, its root-owned cached profile), persists no managed key into the local anchor slot, and ignores user-store substitutions while machine policy is present. Windows accepts signing anchors only from the live HKLM policy; a ProgramData cache is never promoted to authority until native owner/DACL verification is available, and its presence after registry-policy removal is reported as tampered so verification fails closed. A legacy provenance marker also quarantines the old shared slot if the live source and cache disappear before migration. An active machine policy with an omitted or empty `policyBundleKeyring`, or an invalid/inaccessible/tampered machine source, makes policy-bundle verification fail closed. This makes key rotation and revocation effective without waiting for user repair.

On Unix platforms the native policy file and every path component must be root-owned, must not be a symlink, and must not be group- or world-writable. Windows policy is read from HKLM. A permissive deployment path is reported as tampered and cannot provide signing authority.

The machine-status JSON reports only whether this trust is configured, its workspace, and its key count. Public keys and fingerprints are not included in status output. The package's `release-trusted-keys.json` is a separate Ed25519 release-manifest trust domain and must not be used as policy-bundle signing authority.

## Intune adapter example

- macOS install: `/usr/sbin/installer -pkg hol-guard.pkg -target /`
- macOS uninstall: run the signed `uninstall.sh` as root.
- Windows install: `msiexec /i hol-guard.msi /qn /norestart /l*v hol-guard-install.log`
- Windows uninstall: `msiexec /x {product-code} /qn /norestart /l*v hol-guard-uninstall.log`
- Detection runs the platform `detect` script in device context. Exit `0` means healthy, `1` means absent/degraded, `2` means invalid input, and `3` means removal authorization is required.
- User activation runs the platform activation command in user context. Device installation must never substitute SYSTEM/root's home.
- Managed deactivation is two-context: the device authority creates a ≤2-minute authorization under machine state, then the user-context command consumes it and restores that user's adapters. macOS `deactivate-user.sh` performs both steps; Windows uses `authorize-deactivation.ps1`, assigns `deactivate-user.ps1` in user context, then removes the authorization in device context.

Use Intune supersedence for upgrades. The MSI blocks downgrades. Rollback requires an administrator-authorized package and managed policy permitting the target version. Preserve user evidence by default; remove it only through an explicit organization retention decision.
