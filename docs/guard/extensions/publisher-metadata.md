# Extension publisher metadata

HOL Guard Extensions separates a contributor's public profile from an extension's
security behavior. Claiming a profile never enables an extension, changes its
trust class, approves a command, or implies ownership of the upstream tool.

## Identity and eligibility

The stable contribution ID is the public identity. `command.blitcp` uses
`contributions/extensions/command.blitcp.json`. An MCP contribution such as
`mcp.filesystem` keeps that identity even though its runtime catalog entry is
`command.mcp-filesystem`.

Publisher verification uses numeric GitHub account IDs recorded in accepted
publisher metadata. Pull-request authorship is attribution evidence only; it never
creates publisher authority by itself. A profile link, username, repository
membership, authorship of the contribution, commit email, or authorship of an
unrelated change is not sufficient. The contribution and the authority-bearing
metadata must still exist on canonical `main`. Ambiguous history, renames, direct
pushes, and disputed attribution require maintainer review rather than an automatic
grant.

The first accepted claimant set is established through normal protected repository
review of `maintainerGithubIds`. Adding or removing one of those IDs is an
authority-bearing metadata change and must be reviewed as such. An empty claimant
set deliberately leaves the extension unclaimable until maintainers accept an
explicit mapping; consumers must not fall back to PR authorship.

First-party and trusted-library coverage is project-maintained. It is not claimable
by the last person who edited its source.

## Optional presentation file

Publisher presentation and claim authority belong in:

```text
contributions/extension-listings/<contribution-id>.json
```

A sidecar is optional for public presentation, but an external extension cannot be
automatically claimed until an accepted sidecar names at least one authorized
numeric GitHub ID.

Example for `command.blitcp`:

```json
{
  "schemaVersion": "guard.extension-listing.v1",
  "extensionId": "command.blitcp",
  "tagline": "Reviewed file-transfer operation coverage for blitcp.",
  "category": "delivery-remote",
  "limitations": [
    "Coverage is limited to the reviewed operations and the surrounding Guard policy."
  ],
  "documentationUrl": "https://github.com/hashgraph-online/hol-guard",
  "tags": ["file-transfer"],
  "maintainerGithubIds": ["12345678"]
}
```

The [`JSON Schema`](../../../contracts/extensions/listing.v1.schema.json) checks
field shapes, bounds, enumerated values, and duplicate array members. The Python
listing validator additionally checks plain text, public URL policy, symlinked
paths, and filename identity. The exporter checks that each sidecar belongs to a
native contribution. These filesystem and source checks are not JSON Schema
capabilities. URLs are references only; validation never fetches them.

Use a public HTTPS hostname without credentials, a nonstandard port, or a literal
IP address. Do not include policy, executable code, activation state, trust classes,
private email addresses, secrets, or commands. Native contribution contracts remain
the only source of runtime behavior.

### Reviewed claim authority

`maintainerGithubIds` may contain up to eight numeric GitHub IDs as decimal strings.
Each ID is an explicit, reviewed authorization to manage the extension's publisher
profile. It never changes runtime trust, code ownership, or upstream ownership.
GitHub login names remain display data and can change without changing identity.

Omitting `maintainerGithubIds` and providing an empty array both mean there is no
automatic publisher claimant. Pull-request authorship remains useful context for a
maintainer review, but it cannot substitute for an accepted numeric-ID mapping.
The directory always emits an array. For `claimPolicy: provenance`, Cloud must grant
or transfer elevated publisher authority only to IDs present in that accepted array.
`claimPolicy: project` never grants a third-party claim through this field.

Once claimed, profile editors may be invited explicitly without gaining source
maintainer authority. Primary or maintainer roles must remain bound to the current
accepted claimant set and must be revalidated before a transfer or other elevated
action. Contribution IDs retain the native 256-character contract; mapped MCP
runtime IDs and source paths allow the additional prefix and filename characters.

## Generate a separate listing template

The optional helper reads and validates an existing contribution kit, then prints
presentation metadata. It does not modify the kit, add managed paths, upgrade a
builder version, write files, or contact a service:

```bash
uv run python -m codex_plugin_scanner.guard.extension_builder.listing_cli path/to/kit
```

Review the output before saving it as a sidecar. No GitHub identity is inferred.
An accepted native homepage that is unsuitable for public presentation is omitted
from the optional template; it does not prevent native contribution generation.
Existing kit formats and their ownership checks are unchanged.

## Public catalog projection

```bash
uv run python scripts/export_extension_directory.py
uv run python scripts/export_extension_directory.py --check
uv run python scripts/render_command_extension_directory.py --check
```

The compact generated [`catalog.v1.json`](catalog.v1.json) follows
[`directory.v1.schema.json`](../../../contracts/extensions/directory.v1.schema.json).
It carries contribution IDs and digests, runtime IDs, coverage counts, MCP
inheritance, native trust classes, and presentation fields. It carries no activation
decisions, installation counts, ratings, certification claims, or secrets.

The exporter reads each contribution once through the bounded regular-file reader,
validates that payload, and hashes the same bytes. Catalog writes stage a complete
file and check output paths before replacement instead of truncating through a
symlink. Contribution files use LF checkout semantics so digests match canonical
Git blobs on Windows, macOS, and Linux. Consumers pin an immutable source commit
and verify provenance independently. A source merge does not prove release
availability, publisher authority, or enabled protection on a device.

## Cloud availability

The directory and metadata contract can be used independently of Guard Cloud.
Extension Studio is a separate rollout. This helper deliberately includes no
sign-in instruction or claim notification. The Cloud entry point must be deployed
and verified before contributor invitations are enabled. A maintainer profile is
not a security certification or an upstream endorsement.
