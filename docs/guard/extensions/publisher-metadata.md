# Extension publisher metadata

HOL Guard Extensions separates a contributor's public profile from an extension's
security behavior. Claiming a profile must never enable an extension, change its
trust class, approve a command, or imply that the contributor owns the upstream tool.

## Identity and eligibility

The stable contribution ID is the public identity. For example, `command.blitcp`
uses `contributions/extensions/command.blitcp.json`. An MCP contribution such as
`mcp.filesystem` keeps that identity even though its runtime catalog entry is
`command.mcp-filesystem`.

The publisher workflow verifies the numeric GitHub account that authored the
merged pull request introducing that specific file. A profile URL, username,
repository membership, or authorship of an unrelated change is not sufficient.
The contribution must still exist on the canonical `main` history. Ambiguous
history, renames, direct pushes, or disputed attribution require maintainer review.
An ordinary later edit does not replace the original contributor's claim.

First-party and trusted-library coverage is project-maintained, not automatically
claimable by the last person who edited its source.

## Optional presentation file

Existing contributors do not need a new metadata file merely to establish the
introducing-PR relationship. Optional presentation metadata belongs in:

```text
contributions/extension-listings/<contribution-id>.json
```

For example, this is a valid presentation file for `command.blitcp`:

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
It rejects unknown fields, control characters, unbounded prose, duplicate values,
unsafe links, identity mismatches, and symlinked files. URLs are references only;
validation never fetches them. Use a public HTTPS hostname, not a literal IP address,
local host, credential-bearing URL, or nonstandard port.

Do not add `activation`, `trustClass`, policy decisions, executable code, email
addresses, secrets, or commands to presentation metadata. Runtime contribution
contracts remain separate and strict.

### Reviewed delegation

`maintainerGithubIds` may contain up to eight numeric GitHub user IDs represented
as decimal strings. Omit it unless maintainers have reviewed the delegation. This
field can establish an additional eligible profile claimant; it does not create
runtime trust or establish ownership of an upstream product. Once claimed,
additional roles and transfers require the existing publisher's explicit
invitation and the named account's acceptance. Renaming a GitHub account must not
change ownership.

## Builder compatibility

Builder 1.1 creates an inert `listing-template.json` beside its README. Review it
before copying it into the optional presentation directory. The template does not
infer a GitHub identity and is not installed as a runtime artifact.

Builder 1.0 kits remain byte-reproducible and verifiable. Updating an old kit to
1.1 adds presentation guidance without changing its native artifacts or native
revision digest. Existing ownership-file and local-edit protections still apply.

## Public catalog projection

Generate and verify the catalog from the canonical native registry:

```bash
uv run python scripts/export_extension_directory.py
uv run python scripts/export_extension_directory.py --check
uv run python scripts/render_command_extension_directory.py --check
```

The generated [`catalog.v1.json`](catalog.v1.json) follows
[`directory.v1.schema.json`](../../../contracts/extensions/directory.v1.schema.json).
It carries source IDs, exact contribution digests, runtime IDs, coverage counts,
MCP inheritance, trust classes, and presentation fields. It does not contain
activation decisions, install counts, ratings, certification claims, or secrets.
An entry being present in this catalog does not mean it is enabled on any device.

Consumers should pin an immutable source commit, verify provenance independently,
and distinguish merged source from an actually published release. A public
maintainer profile is not a security certification or an upstream endorsement.

## Publisher workflow availability

The catalog and metadata contract are independently useful to directory consumers.
The companion Guard Cloud Extension Studio rollout is tracked separately. Do not
send claim reminders until the deployed claim route has passed its production
canary. The planned entry point is `/guard/extension-studio?extension=<id>`;
possession of that link grants no authority.
