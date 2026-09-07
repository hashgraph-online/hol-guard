# Extension publisher metadata

HOL Guard Extensions separates a contributor's public profile from an extension's
security behavior. Claiming a profile never enables an extension, changes its
trust class, approves a command, or implies ownership of the upstream tool.

## Identity and eligibility

The stable contribution ID is the public identity. `command.blitcp` uses
`contributions/extensions/command.blitcp.json`. An MCP contribution such as
`mcp.filesystem` keeps that identity even though its runtime catalog entry is
`command.mcp-filesystem`.

Publisher verification checks the numeric GitHub account that authored the merged
pull request introducing that specific file. A profile link, username, repository
membership, or authorship of an unrelated change is not sufficient. The contribution
must still exist on canonical `main`. Ambiguous history, renames, direct pushes,
and disputed attribution require maintainer review. An ordinary later edit does
not replace the original contributor's claim.

First-party and trusted-library coverage is project-maintained. It is not claimable
by the last person who edited its source.

## Optional presentation file

Existing contributors do not need a sidecar merely to establish the introducing-PR
relationship. Optional presentation data belongs in:

```text
contributions/extension-listings/<contribution-id>.json
```

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
  "tags": ["file-transfer"]
}
```

The schema is [`listing.v1.schema.json`](../../../contracts/extensions/listing.v1.schema.json).
Validation rejects unknown fields, control characters, excessive lengths, duplicate
values, unsafe links, identity mismatches, symlinks, and orphaned listings. URLs are
references only; validation never fetches them. Use a public HTTPS hostname without
credentials, a nonstandard port, or a literal IP address.

Do not include policy, executable code, activation state, trust classes, private
email addresses, secrets, or commands. Native contribution contracts remain the
only source of runtime behavior.

### Reviewed delegation

`maintainerGithubIds` may contain up to eight numeric GitHub IDs as decimal strings.
Omit it unless maintainers have reviewed that delegation. It can establish another
eligible profile claimant, not runtime trust or upstream ownership. Once claimed,
additional roles and transfers require an explicit invitation and the named
account's acceptance. Renaming a GitHub account must not change ownership.

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

Contribution files use LF checkout semantics so digests match canonical Git blobs
on Windows, macOS, and Linux. Consumers pin an immutable source commit and verify
provenance independently. A source merge is not evidence of release availability
or enabled protection on a device.

## Cloud availability

The directory and metadata contract can be used independently of Guard Cloud.
Extension Studio is a separate rollout. This helper deliberately includes no
sign-in instruction or claim notification. The Cloud entry point must be deployed
and verified before contributor invitations are enabled. A maintainer profile is
not a security certification or an upstream endorsement.
