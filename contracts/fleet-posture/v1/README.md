# fleet-posture/v1

`fleet-posture/v1` is the contract for the machine and AI-tool posture that Guard reports to Guard Cloud.
Guard sends it as `syncContext.fleetPosture` inside the receipt-sync request, so no new endpoint or
credential is involved.

- `schema.json` is the JSON Schema (draft 2020-12) for the object.
- `fixtures/` holds example payloads. `solo-macos`, `team-linux-delta`, `digest-only` and `with-runtimes` are valid.
  `too-large` is deliberately invalid: it exceeds the 65,536-byte limit and shows what a sender must
  never emit.

## Rules a sender follows

- One object per sync request, on the first request of a sync cycle. Later batches in the same cycle
  carry receipts only.
- The serialized object is at most 65,536 bytes (compact JSON, UTF-8). When the inventory does not fit,
  Guard sends it as several delta chunks, and falls back to `digest_only` only when not even one item fits.
- `inventory.mode` is `full` (every item present), `delta` (items added or changed since the last
  accepted send, plus `removed`) or `digest_only` (no item rows, only digests).
- Digests are `sha256:<64 hex>`. They are computed over rows sorted lexicographically and serialized as
  compact JSON. See the [Fleet posture guide](../../../docs/guard/fleet-posture.md) for the exact rows.
- File paths and host names are never sent in the clear. `hostnameHash` and `pathHash` are
  `sha256:` digests computed as an HMAC-SHA-256 under a random per-install secret that never leaves the machine.
- Timestamps are UTC and end in `Z` or `+00:00`.
- `runtimes` is optional and observation only: it lists the runtime executables configured MCP servers
  would launch, without running them or enumerating running processes. `coverage` is always
  `observed_only` and `scopeComplete` is always `false`, and no runtime is reported safe. Rows carry no
  paths, server names or command lines: `executableHash` is the executable's content digest and
  `locationHash` a keyed digest of its path. A minimal report leaves the section out.

## Receiver behaviour

When a `digest_only` or `delta` report does not match the digest the receiver holds, it can answer the
sync request with `fleetPostureRequest: {"inventory": "full"}`. Guard then sends a full inventory on its
next sync.

## Compatibility

`v1` only changes in backward-compatible ways. A breaking change ships as `v2` under a sibling directory,
and Guard advertises the version it speaks through the `fleet-posture/v1` capability in its sync session.
