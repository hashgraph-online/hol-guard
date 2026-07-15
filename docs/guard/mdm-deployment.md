# HOL Guard MDM deployment

## Supported contract

HOL Guard uses package identity `org.hol.guard` on macOS and the stable MSI upgrade code `B15D39B1-6395-4FEA-98A9-5D734DDC455D` on Windows. The package owns the machine runtime; activation owns only the target user's `~/.hol-guard` state and reversible harness integrations.

Builds require Python 3.12, the locked `uv` environment, and PyInstaller. macOS additionally requires Xcode command-line tools; Windows requires WiX 4 and SignTool. Production artifacts must be signed and, on macOS, notarized and stapled. Unsigned builds are test fixtures only.

## Intune

- macOS install: `/usr/sbin/installer -pkg hol-guard.pkg -target /`
- macOS uninstall: run the signed `uninstall.sh` as root.
- Windows install: `msiexec /i hol-guard.msi /qn /norestart /l*v hol-guard-install.log`
- Windows uninstall: `msiexec /x {product-code} /qn /norestart /l*v hol-guard-uninstall.log`
- Detection runs the platform `detect` script in device context. Exit `0` means healthy, `1` means absent/degraded, `2` means invalid input, and `3` means removal authorization is required.
- User activation runs the platform activation command in user context. Device installation must never substitute SYSTEM/root's home.
- Managed deactivation is two-context: the device authority creates a ≤2-minute authorization under machine state, then the user-context command consumes it and restores that user's adapters. macOS `deactivate-user.sh` performs both steps; Windows uses `authorize-deactivation.ps1`, assigns `deactivate-user.ps1` in user context, then removes the authorization in device context.

Use Intune supersedence for upgrades. The MSI blocks downgrades. Rollback requires an administrator-authorized package and managed policy permitting the target version. Preserve user evidence by default; remove it only through an explicit customer retention decision.
