# Proposed Google Workspace pack

`contributions/extension-packs/business.google-workspace.json` groups the
existing `command.google-workspace.gws` and `command.google-workspace.gog`
extensions into one business pack. The schema is
[`pack.v1.schema.json`](../../../contracts/extensions/pack.v1.schema.json). The
pack is a presentation and setup grouping only. It carries no policy, trust
class, activation state or grant, and the schema rejects those fields.

The pack lists:

- each extension ID with the catalog version it was reviewed against;
- operation families, each naming the catalog permissions it covers. Every
  permission of a listed extension belongs to exactly one family;
- role suggestions for `personal` and `managed-team` use;
- operations the pack does not cover, with the reason;
- setup recipes that point to the existing extension documentation.

`validate_pack` in `guard/extension_builder/pack.py` checks the pack against the
generated catalog. Unknown extensions, version drift, permissions outside the
pack, missing or duplicated coverage and missing setup documents are rejected.

## What selecting the pack does

`plan_pack_selection` describes a selection and changes nothing:

- `grants` is always empty, and `activatesExtensions` is always false.
- An extension is `active` only if local extension control already enabled it.
  A disabled external extension stays `inert`, and its suggestions show
  `applies: false`.
- Role suggestions are limited to `review`, `require-reapproval` and `block`.
  Validation rejects a suggestion weaker than a permission's baseline floor,
  and the plan composes each suggestion with the floor again, so a suggestion
  can keep or tighten a floor but never lower it.

## Current grouping

| Family | Permissions | Personal | Managed team |
| --- | --- | --- | --- |
| Email send, reply and forward | gws `send`, gog `send` | review | review |
| Sharing, calendar access and mail routing | gws `share`, gog `share` | review | block |
| Permanent deletes | gws `delete` | block | block |
| Calendar event changes | gws `calendar`, gog `calendar` | review | review |
| Drive downloads and exports | gog `export` | review | review |
| Sign-in, credential export and account overrides | gws `auth`, gog `identity` | review | block |
| Generic API, batch and raw requests | gog `opaque` | review | block |

The pack does not cover search and read, draft creation, volume caps for
labels, archive and trash, account or audience binding, or Workspace MCP
servers. The sharing family blocks for managed teams because the rules cannot
tell internal recipients from external ones, and forwarding and delegation
share that permission.

The status stays `proposed`. The pack is not a qualified business mode or a
protected account journey.
