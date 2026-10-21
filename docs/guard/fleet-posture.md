# Fleet posture

When a machine is connected to Guard Cloud, Guard reports a small, structured summary of that machine so
Cloud can show which AI tools are protected, which need setup, and which policy each machine has applied.
The contract is [`fleet-posture/v1`](../../contracts/fleet-posture/v1/README.md). Local protection never
depends on it: if reporting is off, offline or rejected, interception, blocking and receipts work exactly
as before.

## What Guard reports

| Section | Contents |
| --- | --- |
| `client` | Guard version, release channel (`stable` or `alpha`), runtime, and auto-update status. |
| `machine` | OS name, OS version, CPU architecture, and a keyed hash of the host name. |
| `aiTools` | One row per supported AI tool: tool version when known, setup status, protection state, hook coverage, blind spots, posture override, artifact count, last activity, and an inventory digest. |
| `inventory` | Installed skills, plugins, MCP servers and hooks, as full, delta or digest-only (see below). Items come from the local inventory (artifacts Guard scanned itself) and from the last AIBOM collection, so a machine protected only through hooks still reports what it carries. |
| `policy` | Applied bundle version and hash, applied policy version number, status (`applied`, `validated`, `rejected` or `none`), error code and apply time. |

Guard does not send file contents, prompts, command lines, environment values, user names or raw paths.
Each sync also names the machine with its label. Until you set one with `hol-guard device label set <name>`,
Guard sends the host name without its domain (`Ada-MacBook-Pro` for `Ada-MacBook-Pro.local`), so every machine in
a fleet is not shown as the same "Local machine". Set a label to choose a different name.
Item locations are sent as a keyed hash of the config path. The key is a random secret kept in the local Guard
store and never sent, so the hashes cannot be reversed by guessing user names or paths. Reinstalling Guard on a
machine creates a new key, which changes these hashes.

## Protection state

Each AI tool gets one `protectionState`:

| State | When |
| --- | --- |
| `protected` | Guard setup for the tool is active. |
| `broken` | Guard is set up for the tool but its hooks or config do not work. |
| `needs_setup` | The tool is installed (its config or command is present) but Guard is not set up for it. |
| `paused` | Protection for the tool is turned off in Guard (the `watch` posture). |
| `stale` | Guard is set up for the tool, but the last activity Guard saw was more than 7 days ago. |
| `not_detected` | The tool is not installed on this machine. |

## Inventory modes and size limit

- **full**: every installed item. Sent on the first report, after Guard Cloud asks for one, after
  `hol-guard inventory --sync`, and at least every 7 days.
- **delta**: only items added or changed since the last accepted report, plus `removed` entries.
- **digest_only**: no item rows, only the inventory digest. Used when reporting is minimal (below) or when
  not even one item fits in a request.

A request carries at most 250 items and 65,536 bytes. A larger inventory streams over several syncs as
delta chunks, each chunk as large as fits. A full refresh that needs several chunks keeps going across
syncs even if Guard Cloud asks for another full inventory, and removals that did not fit in one chunk are sent
in later ones. Guard only records a report as sent after Guard Cloud accepts
the request, so a failed sync repeats the same changes next time.

### Digest

The inventory digest is `sha256:` plus the hex SHA-256 of the item rows sorted lexicographically and
serialized as compact JSON (`separators=(",", ":")`). Each row is the list
`[kind, name, version, hash, harness]` with `null` written as an empty string. Per-tool digests use the
same rows restricted to one harness. Cloud compares digests to detect drift without receiving every row.

## Turning reporting down

```bash
hol-guard settings set fleet-posture off
hol-guard settings set fleet-posture on
```

With `off`, Guard still reports its version, each tool's protection state and the policy status, which
Cloud needs to show whether a machine is protected. The minimal report is:

- `client`: unchanged.
- `machine`: OS name, CPU architecture and the host-name hash, without the OS version.
- `aiTools`: the same rows as a full report (protection state, hook coverage, artifact count, last activity,
  inventory digest), but with empty `blindSpots`.
- `inventory`: the digest only, in `digest_only` mode. No item rows are sent.
- `policy`: unchanged.

Turn the setting back on to resume full reporting.

### Full inventory requests from Guard Cloud

Guard Cloud can ask for a full inventory by answering a sync with `fleetPostureRequest: {"inventory": "full"}`.
Guard records the request and starts a full refresh on its next sync. An inventory that fits one request goes
out as a single `full` report. A larger one is refreshed as `delta` chunks over successive syncs, as described
above, and the request stays pending until Guard Cloud accepts a report that is not `digest_only`, so a failed
sync keeps it pending.

The opt-out wins over the request. While `fleet-posture` is `off`, Guard keeps the request queued but still
sends `digest_only`; the full refresh starts the first time reporting is turned back on. Installs managed
by an organization cannot opt out, so they honour the request on the next sync.

Installs managed by an organization (MDM-installed Guard) cannot opt out. `settings set fleet-posture off`
exits with status 2 and explains why, and `hol-guard cloud status` shows the install as managed.

## Seeing what is reported

```bash
hol-guard cloud status [--json] [--offline]
```

Prints the last sync time, a summary of the last report Guard sent, and what Guard Cloud currently shows for
this machine (`GET /api/guard/v1/fleet/machines/self`). If you are signed out, offline, or Guard Cloud does
not offer that route yet, the command still succeeds and prints a plain message. `--offline` skips the
Cloud lookup.

```bash
hol-guard inventory --json --sync
```

Prints the local inventory and queues a full inventory for the next sync.

```bash
hol-guard extensions list [--json]
hol-guard mcp list [--json]
```

`extensions list` prints the installed plugins and extensions from the same local inventory and AIBOM items
that fleet posture reads. It shows name, harness, type, scope, last policy verdict and last-seen time as a table, or the
full records with `--json` (`generated_at`, `kind`, `count` and `items`, where each item also carries
`config_path`, `artifact_hash`, and `first_seen_at`). It covers the items reported as the `plugin` kind
(plugins, plugin files and extensions). Items Guard has marked removed, and items from tools that fleet
posture does not report on, are left out.

`mcp list` prints the MCP servers the Protect page lists: servers configured in a harness, stdio or remote,
and servers Guard has seen an agent call. Each one is grouped as needing setup, allowed, or blocked. When the
local dashboard is running, a server that needs setup comes with a link to its Protect page. See
[custom extensions](./local-cli-allowlist.md#from-the-command-line).

Both commands are read-only: they do not send anything and do not queue an inventory request.

## Policy acknowledgement

The posture's `policy` section and the existing policy acknowledgement describe the bundle applied on the
machine. A bundle applied during a sync cycle used to reach Cloud one sync interval later. Guard now
sends one extra, receipt-free request in the same cycle with the new acknowledgement. It sends that
follow-up at most once per bundle hash and records the attempt before sending, so a failure never loops.

Bundles whose version is a legacy string rather than an integer are reported with
`appliedBundleVersion: null`; the bundle hash still identifies them.

## Known gaps

- The native runtime does not assemble sync context; the Python runner does, so the posture is built in
  Python. The native sync transport identifies itself as `hol-guard-native/<version>`.
- `postureOverride` reports `default` when no override is set, `off` for the `watch` posture and
  `enforce` otherwise. `observe` is part of the contract but Guard does not emit it.
