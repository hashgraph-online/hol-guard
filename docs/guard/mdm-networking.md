# HOL Guard enterprise networking

HOL Guard uses one managed network-policy contract for external runtime HTTP. Managed policy selects `direct` behavior with `network.proxyMode=none`, the platform system proxy with `network.proxyMode=system`, or an administrator-defined HTTPS proxy with `network.proxyMode=explicit`. The same policy is loaded by foreground commands and detached Guard processes. User shell proxy and CA variables are not managed authority and cannot override an active managed policy.

## Runtime HTTP inventory

External Guard traffic is required to use the enterprise transport in `src/codex_plugin_scanner/guard/mdm/network.py`:

- Guard Cloud synchronization, OAuth/device authorization, remote pairing, policy and entitlement retrieval, Cloud exception requests, insights sharing, and other Guard Cloud calls use `managed_urlopen` through the shared runtime helpers.
- Package provenance, signed supply-chain intelligence, user-owned update checks, internal package indexes, and remote MCP forwarding use the same managed transport.
- Credential-free verified public GitHub reads use `managed_opener` so they retain their bounded origin/redirect proof while inheriting managed proxy and TLS policy.
- Telegram and administrator-configured HTTPS webhook notification egress uses `managed_requests_session`.

Raw `requests`, `urllib`, and `http.client` transports are confined to the managed transport itself or authenticated loopback IPC between Guard hooks, the Bridge, and the local daemon. Loopback daemon URLs are validated as local HTTP origins before Guard daemon credentials are attached. CI inventories these constructors so a new external bypass fails the enterprise networking tests instead of creating a parallel convention.

## Proxy policy

`network.proxyMode=none` disables proxy use for managed requests. `network.proxyMode=system` reads platform proxy configuration without treating `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, or their lowercase variants as administrator authority. macOS reads the System Configuration proxy state and Windows reads the Internet Settings policy/state. Linux does not expose one universal platform system-proxy authority; enterprises that require deterministic Linux proxy routing should configure `network.proxyMode=explicit`.

`network.proxyMode=explicit` requires `network.proxyUrl` to be a credential-free HTTPS proxy origin. Paths, queries, fragments, whitespace, invalid ports, and embedded user information are rejected. Explicit proxy routing does not honor `NO_PROXY`, so a shell variable cannot bypass administrator policy.

Proxy credentials are never accepted in managed policy, CLI arguments, proxy URLs, status, diagnostics, receipts, or user-readable Guard files. When proxy authentication is required, Guard reads an optional record from native OS credential storage under service identifier `hol-guard-enterprise-proxy-v1`: macOS Keychain, Windows Credential Manager, or Linux Secret Service. The lookup key is the SHA-256 digest of the normalized credential-free proxy origin. The record is a bounded JSON object containing only `username` and `password`. Provisioning that record is an administrator/OS credential-management operation outside the Guard policy contract. Guard exposes only whether authentication material was available, never the credential value.

## TLS and private CAs

TLS certificate and hostname validation are mandatory. Managed contexts require TLS 1.2 or newer, `CERT_REQUIRED`, and hostname verification. No runtime path may set `verify=false`, use `CERT_NONE`, disable hostname checks, or create an unverified SSL context.

Public roots are loaded explicitly and platform roots are added without consulting shell CA overrides. `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, and `CURL_CA_BUNDLE` therefore cannot add trust to an active managed network context. If `network.caBundlePath` is configured, the PEM bundle is added to existing public/system trust rather than replacing it. The path must be absolute and resolve to a regular non-symlink file; on Unix, group- or world-writable CA files are rejected. A malformed or unavailable bundle fails closed.

## Daemon authority

Detached and login-started daemon environments strip ambient proxy variables. Every external daemon request resolves managed policy from the same machine authority as foreground Guard commands. The managed `requests` transport also sets `trust_env=false`, and the urllib-compatible transport uses a policy-owned direct opener or HTTPS proxy tunnel rather than shell proxy state. Local daemon IPC remains authenticated loopback traffic and is intentionally not sent through an enterprise proxy.

## Diagnostics

`hol-guard mdm network-diagnose --endpoint https://host.example` is prompt-free and always emits the versioned `hol-guard-mdm-status.v1` JSON contract, even when `--json` is omitted. Each result contains:

- destination hostname and DNS state;
- selected proxy mode, whether a proxy was selected, a SHA-256 proxy-origin fingerprint, proxy DNS state, and only a boolean indicating whether proxy authentication material was available;
- TLS trust state;
- clock state and bounded absolute skew derived from the HTTPS `Date` response header when available;
- endpoint reachability; and
- a stable redacted reason code.

The diagnostic never emits proxy URLs, proxy credentials, exception strings, certificate contents, tokens, or response bodies. DNS, proxy, TLS, clock, and endpoint failures are reported independently. The JSON shape is validated by `docs/guard/schemas/mdm-status-v1.schema.json`.

## Endpoint classes and offline behavior

`docs/guard/mdm-endpoints.v1.json` is the versioned machine-readable endpoint inventory. Every entry contains hostname, port, purpose, required/optional status, methods, data classification, and offline fallback.

`hol.org` is required only for Guard Cloud features such as identity, OAuth, policy/evidence synchronization, and signed remote intelligence. It is not required for local protection or native lifecycle operations. Public package registries and `api.github.com` are optional intelligence/read endpoints. `network.allowPublicRegistries=false` blocks known public package registries before network I/O without weakening local enforcement.

For user-owned Guard updates, an organization may set `update.indexUrl` to an internal Python package index. This value is managed-policy authority: it must be an absolute credential-free HTTPS URL with no query, fragment, or whitespace. When public registries are disabled, an internal index is required before a user-owned online update can run. The updater uses the same explicit index for the initial installer attempt and any retry; project-local pip/uv configuration and ambient index variables are not trusted source configuration. Public status exposes only that an index is configured and its SHA-256 source fingerprint.

Signed supply-chain intelligence is cached locally and remains subject to signature, binding, expiry, and stale-data checks. During DNS failure, proxy failure, TLS failure, Guard Cloud outage, blocked public registries, or full network isolation, Guard continues local policy and package enforcement using validated local policy and signed cached intelligence where available. Remote freshness is reported as stale or unavailable rather than silently treated as current. Network recovery is never a prerequisite for the local block path.

## Offline lifecycle

Native macOS and Windows Guard packages stage the Guard runtime before packaging. Install, activation, repair, rollback/replacement, deactivation, and uninstall scripts do not fetch public dependencies or call Guard Cloud. The portable MDM lab statically rejects network primitives from native lifecycle scripts and network-client imports from lifecycle modules, while existing native lifecycle tests exercise idempotent install/repair/removal behavior.

The portable lab does not claim Apple MDM enrollment/supervision, Apple signing/notarization, Windows CSP enrollment, Windows SYSTEM execution, Authenticode/WDAC, or real vendor command delivery. Those remain native certification gates and are reported separately from the enterprise networking contract.

Run the portable enterprise networking evidence suite with:

```bash
python scripts/mdm/run-local-lab.py --suite enterprise-network --json
```

That suite includes real local TLS and CONNECT-proxy socket scenarios in addition to unit-level failure injection, schema validation, HTTP-client inventory checks, signed-cache enforcement, Guard Cloud outage behavior, internal update-index isolation, and offline lifecycle checks.
