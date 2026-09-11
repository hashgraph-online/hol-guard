# Paseo adapter

Paseo is a control plane for coding agents. Its providers execute tools in their own runtimes, so Guard installs the existing native integrations on the **Paseo daemon host**, not on the phone or remote client.

**This is limited, provider-specific protection, not a firewall for everything Paseo does.** The adapter does not install a permission-event listener and call it enforcement.

## Install and verify

Use the same operating-system account and native configuration home as the Paseo daemon:

```bash
hol-guard install paseo --dry-run
hol-guard install paseo
hol-guard apps test paseo --json
```

The installer discovers `~/.paseo/config.json`, or `$PASEO_HOME/config.json` when an absolute `PASEO_HOME` is set. An explicit Guard `--home` selects that home's `.paseo/config.json` instead of inheriting `PASEO_HOME`. Install on each daemon host separately. Relative `PASEO_HOME` values are rejected rather than resolved against an unrelated working directory.

It installs Guard only for enabled, supported providers whose native executable is available. Missing runtimes are listed as `runtime-unavailable`; OMP is disabled by default, matching Paseo. Custom profiles that extend a supported native provider share one native installation. The adapter never enables disabled providers or changes Paseo credentials, models, provider commands, permission modes, or `plugins.enabled`.

Start new provider sessions after installation or repair. Existing sessions can retain old hooks. The installer does not interrupt active sessions or restart the daemon. Changes to Paseo's own provider configuration remain subject to Paseo's normal `paseo reload` behavior.

`guard-paseo` is also installed as an optional pre-launch inventory-check wrapper. Native provider commands are **not** replaced with wrappers, preserving the Claude SDK, Codex app-server, Pi/OMP RPC, and ACP stdio transports.

## Native providers

| Paseo provider | Guard integration installed | Boundary |
| --- | --- | --- |
| `claude` | `claude-code` user settings hooks | Native Claude tool/prompt hooks, including `PreToolUse` |
| `codex` | Codex native hooks and existing MCP integration | Codex's native hook enforcement, including app-server sessions that load those settings |
| `copilot` | Copilot global hooks and existing MCP integration | Native Copilot hook events; not an independent Paseo ACP interceptor |
| `pi` | Managed Pi runtime extension | Events forwarded by the native extension in Pi sessions |
| `omp` | Managed Oh My Pi runtime extension | Events forwarded by the native extension; only installed when enabled |
| `opencode` | OpenCode native pretool plugin and existing native configuration | Native pretool protection; Guard-launcher-only overlays are not injected into Paseo |

Each integration retains its existing approval behavior, failure behavior, and blind spots. Hook failures are **not** claimed to be uniformly fail-closed. Native hooks keep their native harness identity in Guard's policies, activity, and approvals. For example, a Claude action launched by Paseo is evaluated as `claude-code`, not as a fabricated `paseo` tool event. Native install records are registered so normal Guard health checks and repairs can verify them.

OpenCode's Guard-launcher runtime overlay and any other launcher-only provider features are not inherited merely by installing this adapter. Read the native provider's coverage documentation for those distinctions.

## Unsupported and unverified surfaces

The following are not protected by this adapter:

- Paseo terminals, daemon-managed git/browser operations, plugin execution, and other daemon hosts.
- Arbitrary ACP or plugin providers. A display name that resembles a supported provider is not sufficient evidence.
- Providers with custom `command` arrays, including wrappers, containers, custom binaries, and flags that disable hooks.
- Provider environment overrides that redirect native homes/configuration, change executable lookup, or may disable Guard. Ordinary API credentials and endpoint profiles do not themselves redirect the native hook installation.

The installer checks provider configuration and relevant environment overrides visible to the installing process. It cannot prove the environment of an already-running daemon or inspect future per-session/plugin launch overrides. Different daemon accounts, native settings overrides, disabled extensions, and per-session runtime options require separate verification. The adapter never changes those options silently.

Paseo's `agent.permission_requested` event is a best-effort notification. It does not cover every tool call and event-handler errors do not prevent the original operation. The adapter intentionally does not use it to allow, deny, auto-approve, or claim coverage.

## Diagnostics and repair

`hol-guard apps test paseo --json` includes a `providers` report with these statuses:

| Status | Meaning |
| --- | --- |
| `native-hooks-installed` | Recorded native installation files still match their installation fingerprints |
| `disabled` | Disabled in Paseo; no native installation is requested for this profile |
| `runtime-unavailable` | The native executable was not found in the installation context |
| `unsupported` | Provider type, command, or environment needs separate integration/verification |
| `not-installed` | A supported available provider has no recorded installation |
| `changed` | A recorded native configuration, extension, or hook artifact changed or disappeared |

Unsupported profiles remain coverage caveats and do not erase verified supported-provider installation. An enabled native provider that is unavailable or not installed makes aggregate setup `partial`; changed native artifacts make it `broken`.

The report always says `coverage_status: limited` and `runtime_verification: not-performed`. A matching installation fingerprint is not a live model/tool execution attestation. Check native Guard receipts from a harmless action in a new Paseo session before relying on a deployment. Do not use real secrets as a smoke test.

```bash
hol-guard apps repair paseo
hol-guard apps test paseo --json
```

Repair validates configuration before modifying native settings. Malformed JSON, duplicate keys, oversize files, and unsafe managed paths are rejected. A failed multi-provider install does not leave a successful Paseo receipt. Native integrations successfully installed before a later failure remain installed and registered; rerun repair after correcting the failure. The adapter does not roll back shared protections to an older snapshot.

Receipts are stored under Guard's `managed/paseo` directory, keyed by the Paseo configuration path. They contain native file fingerprints, not provider credentials. Config/extension fingerprints also participate in Guard's normal managed-install proof validation. New available providers and unsupported profiles are reflected by diagnostics rather than inferred from an old install flag.

## Cloud inventory compatibility

The Paseo composite inventory is available in local diagnostics and exports. It is not uploaded as a new `paseo` cloud agent type: the current portal contract does not accept that type yet. Guard continues syncing the supported native provider inventories under their existing identities. Paseo diagnostics expose `cloud_inventory_status: native-providers-only`. This avoids rejecting a batch of otherwise valid native inventories or uploading Paseo configuration content through an unsupported schema.

## Uninstall and ownership

```bash
hol-guard uninstall paseo
```

This removes only the Paseo installation receipt and `guard-paseo` launcher. **Shared native Guard hooks remain installed**, including native integrations originally installed through Paseo. This avoids disabling protection in another client or standalone CLI.

To remove a native integration for every client using that native home, explicitly run its normal uninstall command, for example `hol-guard uninstall pi`. Paseo configuration and credentials are never restored from a stale backup or overwritten during uninstall.

## Design reference and tests

The integration was checked against the Paseo 0.8 source snapshot [`f22a37e613e965c8ebc02e1f5565e21fd72eaf2f`](https://github.com/getpaseo/paseo/tree/f22a37e613e965c8ebc02e1f5565e21fd72eaf2f):

- [Provider configuration](https://github.com/getpaseo/paseo/blob/f22a37e613e965c8ebc02e1f5565e21fd72eaf2f/docs/custom-providers.md), including built-in defaults, `extends`, `command`, and `env`.
- [Lifecycle contract](https://github.com/getpaseo/paseo/blob/f22a37e613e965c8ebc02e1f5565e21fd72eaf2f/packages/plugin/src/server/lifecycle.ts) and [hook failure semantics](https://github.com/getpaseo/paseo/blob/f22a37e613e965c8ebc02e1f5565e21fd72eaf2f/public-docs/plugins/v0.8/reference.md#context-and-cleanup).
- Native launch implementations under `packages/server/src/server/agent/providers`: Claude loads user/project/local settings, Codex starts the native app-server, Pi/OMP preserve extension-loading RPC launches, and OpenCode adds its bridge plugin without replacing the native integration.

`tests/test_paseo_adapter.py` exercises real native installers in isolated homes. Only executable discovery is substituted; no paid model requests or real credentials are required. Tests cover configuration preservation, native proof registration, workspace independence, custom profiles, unsupported overrides, malformed input, unsafe paths, repeated installation, drift, credential-free inventory, public CLI management, and conservative uninstall. These tests do not represent a live authenticated Paseo/model session.
