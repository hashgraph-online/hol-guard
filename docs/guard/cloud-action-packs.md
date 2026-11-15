# Cloud Action Packs

A cloud action pack describes one provider's hosted actions as data. It says which hosts requests may reach, how
the provider signs in, and for each action: the exact request, the arguments a caller may set and their bounds, the
facts Guard derives from those arguments, the response fields that come back, and the limits a host must enforce.

Packs live in `contributions/cloud-actions/`. The schema is
[`contracts/extensions/cloud-action-pack.v1.schema.json`](../../contracts/extensions/cloud-action-pack.v1.schema.json)
(`guard.cloud-action-pack.v1`). The Rust tooling in `guard-command` validates, tests, compiles, renders and diffs
them. Nothing in it sends a request.

## What a pack cannot say

The language is small on purpose, so a pack from a third party can be reviewed as data:

- No expressions, scripts or loops. A body is built from constants, whole arguments, one bounded copy of an
  array argument (`each`), one field named by an argument (`keyed`), the `rfc822` mail template described
  below, and a flat `form` body described below.
- No URL outside the declared `hosts`. The scheme is always `https`, the host is fixed per action, and an argument
  can fill only whole path segments.
- No credential headers. Header names are lowercase constants. Names containing `auth`, `cookie`, `token`,
  `secret`, `key`, `session`, `password` or `credential`, and framing headers such as `host`, `content-length`,
  `forwarded`, `proxy-*` and `x-forwarded-*`, are refused. `content-type` is refused too, because rendering
  sets it from the body: JSON, or `application/x-www-form-urlencoded` for a `form` body. The host adds the credential and the `user-agent`.
- No unbounded input. Every string has a `maxLength`, every integer a range, every array an item limit. Patterns
  must start with `^` and end with `$`, compile on the linear-time `regex` engine within 1 MiB, and are matched
  against the whole value, so an alternation such as `^a|b$` cannot match a value that only starts with `a`.
- No effect weaker than the facts. An action whose fact class is `send` cannot declare `effect: read`.

## Facts

Each action names a fact class and may add extractors for object, reversibility, scope, counts, audience,
recipient domains, environment and sensitivity. An extractor is a constant, a boolean flag, the length of an array
argument, a bounded integer argument, or the domains of address arguments. Extraction is total: a value that is
missing, malformed or out of range becomes `unknown`, never a guess. The facts feed the version 2 evaluator in
[Cloud Action Evaluator](cloud-action-evaluator.md).

An action that moves money adds `money`: the integer argument holding the amount in the currency's minor unit
(`amount`), either a string argument holding the ISO 4217 code (`currencyArgument`, pattern-bound and at most three
characters) or a fixed code (`currency`), and a `direction` of `out` or `in`. The code is uppercased. A missing
amount or currency, or one that is not a three-letter code, leaves the money fact `unknown`, which a rule with
`min_amount_minor` treats as the stricter branch. A Stripe refund takes no currency argument, so its money fact stays
`unknown` and it is reviewed like any other money out.

## Form bodies

Some APIs, Stripe's among them, accept only `application/x-www-form-urlencoded` bodies. A `form` body is a flat list
of fields, allowed only as the whole body. Each value is a string, integer or boolean argument, or a scalar
constant of at most 256 characters; a field whose argument is absent is left out. Field names use letters, digits and
`_ . - [ ]`, so the bracket notation such APIs read as nesting (`metadata[order]`) is available, and both names and
values are percent-encoded with spaces as `+`, so a tab or other control character in a value travels as `%09` and
so on. Rendering stops as soon as the body passes 1 MiB.

## Mail messages

Mail APIs such as Gmail take a whole encoded message rather than separate recipient fields. Passing a caller's
message through would let it name recipients Guard never saw, so a pack builds the message with the `rfc822`
template instead:

```json
{"rfc822": {"to": "to", "cc": "cc", "bcc": "bcc", "subject": "subject", "text": "text"}}
```

Each value names an argument. `to` must be a required array with at least one item, `cc` and `bcc` are optional
arrays, and `subject` and `text` are strings. Every recipient must be a bare `local@domain` address: a display
name, a second address or a line break refuses the call. The subject is always RFC 2047 encoded and the text is
always base64, so neither can add a header. Rendering writes `To`, `Cc` and `Bcc` from the arguments alone and
base64url-encodes the message.

An action that uses the template must read `recipientDomains` and `recipientCount` from exactly its recipient
arguments, so the facts Guard decides on name every address the message goes to. The template cannot appear
inside `each`.

## Fields named by an argument

Some providers name a field after the user's own data, such as a Notion database column. `keyed` writes a
one-field object whose name is a string argument:

```json
{"keyed": {"key": "property", "value": {"object": [{"name": "select", "value": {"object": [{"name": "name", "value": {"arg": "option"}}]}}]}}}
```

The key argument must be required, carry a pattern, and allow at most 256 characters. The name is written as a
JSON string, so it cannot add a sibling field. A call without the key is refused rather than rendered.

## SQL statements

An action that runs SQL adds `sql`: the argument holding the statement text, and `field` when the text is one key of
a JSON argument. The value may be one string or an array of strings. Guard reads the text without running it and
raises the declared class when a statement does more:

- `SELECT`, `WITH`, `VALUES`, `SHOW`, `DESCRIBE`, `EXPLAIN` without `ANALYZE`, and transaction control read.
- `INSERT`, `MERGE`, `CREATE`, `ALTER` that adds, `SET`, and `UPDATE` or `DELETE` with a real top-level `WHERE`
  write. A write that a `WHERE` narrows reports scope `query_selected`.
- `DROP`, `TRUNCATE`, `UPDATE` or `DELETE` without a `WHERE` (or with a constant-true one such as `WHERE 1=1`),
  `ALTER ... DROP`, `CREATE OR REPLACE`, `EXPLAIN ANALYZE` of a write, and any statement the reader does not know
  (`CALL`, `DO`, `COPY`, `EXECUTE`) are a permanent delete on a table, or on a database for `DROP DATABASE` and
  `DROP SCHEMA`. A delete with no `WHERE` reports scope `all`.
- `GRANT`, `REVOKE`, `SET ROLE` and changes to users, roles and policies are `admin`.

Every statement in a batch is read, and the strictest one decides. Write and side-effect functions inside a query
(`nextval`, `dblink`, `pg_terminate_backend`) count as the statement they cause. Text the reader cannot follow the
way every dialect would is destructive: an unclosed quote or comment, a backslash inside a string, a `#` comment,
`--` without a following space, nested or MySQL executable comments (`/*! ... */`), more than 64 statements, an empty
batch, or a value that is not text. The SQL can only raise the declared class, never lower it.

## Rendering and projection

Rendering checks every argument against its rule, then builds the request. Path segments and query values are
percent-encoded. A path segment that is empty, `.` or `..` (including full-width and ideographic full stops) or
that contains a control character is refused, as is a query value with a control character. Bodies are JSON.

Projection reads a response the host already received. It refuses a body over `response.maxBytes`, refuses
duplicate keys, keeps only the declared fields, refuses a list longer than its `maxItems`, and labels fields that
carry provider text (`untrusted: true`) so the caller can treat them as data, not instructions.

An action whose provider answers success with no body (HTTP 204 for most deletes, workflow dispatches and secret
writes) sets `response.emptyOk: true`; an empty body then projects as `{}`, so `exists` fields read `false`. Without
it an empty body is `response_json_invalid`, which keeps a read that comes back empty from passing as an empty
result. Turning `emptyOk` on is a widening change in `diff`. Size `maxBytes` for the largest response the provider
can send back, including any argument it echoes: GitHub returns the full issue or pull request body, so those
actions allow 512 KiB.

## Fixtures

Every action in a source pack carries at least one `safe` and one `risky` fixture. A fixture states the arguments
and what must happen: the error code, the facts, the exact rendered request, or the projection of a recorded
response. Compilation runs the fixtures and stops on any failure.

A fixture may also name the decision each shipped preset reaches for its call, as
`expect.decisions: {"relaxed": ..., "balanced": ..., "strict": ...}`. The fixture runner evaluates the extracted
facts against each named preset with the action's declared effect, a clean session and empty windows, and fails on
any difference. See [Cloud policy presets](cloud-policy-presets.md).

## Artifacts and digests

`compile` validates the pack, runs its fixtures, strips them, and returns a
`guard.cloud-action-pack-artifact.v1` artifact with three SHA-256 digests over canonical JSON:

- `packDigest`: the whole compiled pack.
- `factsProgramDigest`: each action's id, fact extractors and effect, so a change to what Guard decides on is
  visible apart from request or wording changes.
- `artifactDigest`: everything else in the artifact: schema, compiler version, provider, the two digests above
  and the compiled pack.

Loading an artifact recomputes all three and refuses any mismatch, so an artifact whose content no longer matches
its digests does not load. Key order does not change a digest.

The digests are not keyed, so they do not authenticate an artifact: anyone who edits a pack can recompute all three.
A host must compare `artifactDigest` with a pin it trusts independently, such as a signed catalog entry, before it
activates an artifact.

## Widening

`diff` compares two packs or artifacts for the same provider and lists each change with a code. A change is
widening when it lets a pack do more than before: a new host, scope or action, a looser argument, a weaker effect,
a dropped capability, a new response field, a removed untrusted label, looser limits, a changed executor or
link, or any changed fact extractor. Any edit to a pattern or forbidden rule counts as widening, because whether a new pattern accepts less
cannot be decided in general. A widening pack version needs fresh review.

## Running the tools

```
guard-cloud-action pack
hol-guard-runtime cloud-action pack
```

Both read one JSON request per line on standard input and write one JSON result per line:

| `op` | Input | Result |
|---|---|---|
| `validate` | `pack` | `actions` count |
| `test` | `pack` | fixture `report` |
| `compile` | `pack` | `artifact` |
| `diff` | `old`, `new` (pack or artifact) | `diff` |
| `render` | `pack` or `artifact`, `actionId`, `arguments` | `request` |
| `extract` | `pack` or `artifact`, `actionId`, `arguments` | `facts` |
| `project` | `pack` or `artifact`, `actionId`, `response` | `projection` |
| `policy` | `preset` name or `policyPack` | `preset`, `packDigest`, `factRules`, `unclassified` |
| `classify` | `name`, optional `inputSchema`, optional `class`, optional `preset` or `policyPack` | `proposal`; `facts` that claim only one class (the proposal's, or `class` when a workspace admin approved one for the tool); and `action` when a preset is named |
| `explain` | `actionId`, `arguments`, optional `pack` or `artifact` (defaults to the shipped packs) | `providerId`, `effect`, `facts`, `decisions` by preset |
| `simulate` | `preset` or `policyPack`, and `calls`: up to 1000 stored calls, each `provider`, `actionId`, `facts`, optional `effect`, `connectionId`, `resourceId`, `sessionFlow` and `usageWindows` | `results`: per call `action`, `matchedRuleIds`, `unknownRuleIds` |
| `generate` | `providerId`; `openapi` or `mcpTools`, or `from` and `document` text; optional `providerName`, `publisher`, `host`, `authMode` | draft `pack`, `proposals`, `notes` |

`simulate` reads only the facts a host stored when it decided each call, never arguments or payloads. A call with
no stored session flow reads as a clean session, and one with no stored usage reads every window at zero. When a
rule that covers a call is scoped to a connection or resource the call does not carry, the request is refused with
`scope_unknown`; a call that named no resource sends `resourceId: null`, so a resource-scoped rule cannot match it. A host
adding a draft rule to a preset names it with the preset prefix (for example `balanced.workspace.r0`).

A result is `{"ok": true, ...}` or `{"ok": false, "error": {"code": ..., "pointer" | "argument": ...}}`.

## Drafting a pack

`hol-guard extensions generate --cloud` drafts a pack from an exported description of a provider's API. It ships in
the released CLI and runs the native runtime, so it needs no Rust toolchain.

```
hol-guard extensions generate --cloud --from openapi --input api.json --output pack.json --slug shop
hol-guard extensions generate --cloud --from mcp --input tools.json --output pack.json --slug files \
  --host mcp.files.example --auth-mode oauth2
```

`--from openapi` reads an OpenAPI 3 document. Each operation whose path, path and query parameters and JSON body a
pack can express becomes a `declarative-http` action on the host of the first `https` server, or on `--host`. `--from
mcp` reads a `tools/list` result (or its `tools` array) and makes one `remote-mcp` action per tool; `--host` is
required.

The draft leans strict, so an author loosens it with evidence rather than tightening it later:

- The class comes from the name classifier, which never proposes less than `update`. Only a `GET` whose name gives the
  classifier no evidence drops to `read`, and a `DELETE` is never below `delete`. MCP tools keep the classifier's
  class, whatever their annotations claim.
- Every action that is not a read is proposed `permanent`.
- String, integer, boolean and string-array arguments take their bounds from the schema: `maxLength`, `minimum` and
  `maximum`, `maxItems`, an anchored `pattern`, or an `enum` turned into a whole-value pattern. A missing bound gets a
  fixed limit. Arguments no pack type can bound are left out and listed in `notes`.
- Response fields are the scalar properties of the success schema; text fields are marked `untrusted`.
- OAuth scopes come from each operation's `security`. When the source names none, the draft uses the scope `api`.

The output names a new file and the draft carries no fixtures, so `validate` refuses it with
`cloud_pack_fixtures_missing` until every action has a safe and a risky fixture. `proposals` lists each action's
class with the evidence behind it, and `notes` lists everything left out or guessed. Review both before filling in
the fixtures.

## Checking a pack from the CLI

```
hol-guard extensions validate --cloud pack.json
hol-guard command explain --cloud slack.chat.post_message --arguments '{"channel": "C0123456789", "text": "hi"}'
hol-guard command explain --cloud shop.remove_pet --pack pack.json --arguments '{"pet_id": 7}'
```

`extensions validate --cloud` checks the pack and runs every fixture, and fails with the first fixture that does not
hold. `command explain --cloud` checks the example arguments against the action's bounds, then prints the facts Guard
derives and the decision each shipped preset (`relaxed`, `balanced`, `strict`) gives the call. Without `--pack` it
looks the action up in the shipped packs. The decision is the preset's fact rules over a clean session with every
rate window at zero; workspace rules, capabilities and consent are applied later and can still change the outcome.
Both commands run the native runtime, read nothing beyond the named file and never contact the provider.

## Shipped packs

`github.json`, `notion.json` and `slack.json` cover Slack channel reads, posting, editing and deleting messages,
reactions, pins and channel topics, file deletes, channel archive and restore, and inviting, sharing with and removing
members; GitHub issues, comments and labels, pull requests, reviews and merges, branch deletes and force updates,
repository archive, visibility and delete, release deletes, Actions secrets and workflow runs, and collaborators; and
Notion blocks, pages and their properties, page archive and restore, block deletes, database queries and creation, and
database column removal and type changes. A pull request review can comment or request changes but never approve. The
actions that match an existing hosted tool link to its name; the others have no hosted tool yet. `gmail.json`,
`drive.json` and `calendar.json` cover Google Workspace: reading, drafting and sending mail, archiving, trashing and
deleting messages, mail forwarding and filters, file search, export, sharing with a person, a domain or anyone with
the link, trash and permanent delete, and calendar events with and without guests. Their actions link to the matching
Google Workspace command permissions. `sheets.json` and `docs.json` read, write and export Google Sheets and Docs:
reading tabs and ranges, writing down a column, appending a row, clearing a range and deleting a tab, and appending,
replacing and deleting document text. `outlook.json`, `onedrive.json` and `teams.json` cover Microsoft 365 through
Microsoft Graph: listing, drafting, sending, forwarding, moving and deleting mail (to Deleted Items or permanently),
calendar events with and without attendees, OneDrive and SharePoint files with organization and anyone links,
invitations, the recycle bin and permanent delete, and Teams channel and chat messages, soft deletes and channel
deletes. `airtable.json` lists, reads, adds, updates and deletes records, at most ten per call as Airtable allows.
`dropbox.json` lists, moves and deletes files one at a time or in batches, deletes permanently, creates public and
team links, shares with people and makes four-hour download links.

Twenty-three packs cover provider-hosted MCP servers rather than REST APIs. `salesforce-mcp.json` and `notion-mcp.json` name
each tool argument: Salesforce queries, searches, record reads, creates, updates and deletes (recoverable from the
Recycle Bin), and Notion search, fetch, data source queries, page creation (at most twenty per call), updates, moves,
duplicates, trash, version restore and comments. A record body or page list is a bounded JSON argument. `asana.json`,
`atlassian.json`, `hubspot-mcp.json`, `box.json` and `stripe-mcp.json` cover providers that do not document their tool
arguments, so each tool is one action whose arguments are open but bounded in total size, and whose facts are
constants: the class and object the tool works on, never a count it cannot prove. HubSpot is read-only. Stripe money
movement (`send_money`, `transfer_money`, `convert_currency`) is class `pay` and adding a payout recipient is `admin`.
Tools that multiplex several operations behind one name (Stripe `stripe_api_write`, Atlassian `executeRead`,
`executeWrite` and `executeDestructive`, HubSpot `manage_*`) and Linear, whose tool names are not published, are not
covered.

Fourteen more tool-level packs follow the same pattern for developer, operations and support servers:
`github-mcp.json` (GitHub's hosted MCP server), `gitlab-mcp.json`, `azure-devops-mcp.json`, `buildkite-mcp.json`,
`vercel-mcp.json`, `render-mcp.json`, `sentry-mcp.json`, `pagerduty-mcp.json`, `postman-mcp.json`,
`huggingface-mcp.json`, `webflow-mcp.json`, `monday-mcp.json`, `paypal-mcp.json` and `intercom-mcp.json`. Each tool
name comes from the provider's published tool list. Reads are class `read`. Tools that start a deployment, run a
pipeline, run a command in a sandbox, merge a pull or merge request, or roll a release forward or back are class
`execute`. Tools that write an environment variable, a project secret, a DSN or an SDK key are writes on a `secret`.
Tools that change who can reach a project or a workspace (firewall rules, deployment protection and bypasses,
signing keys, team roles, private networks, governance rules, webhooks and log drains) are class `admin`, which
every preset blocks. Buying a domain and PayPal money movement are class `pay`. A tool whose single name covers
several operations takes the class of its riskiest one. Every tool's arguments are open but bounded in total size,
and a key that no tool argument could have (such as `$where`) is refused. monday.com's `all_monday_api`, which sends
any GraphQL query, is not covered.

`supabase-mcp.json` and `neon-mcp.json` cover the Supabase and Neon MCP servers. Their SQL tools (`execute_sql`,
`apply_migration`, `run_sql`, `run_sql_transaction`, `explain_sql_statement` and `prepare_database_migration`) carry
an `sql` fact, so a query is allowed, a narrowed write is reviewed in Balanced, and dropping or emptying a table is
blocked in Balanced and Strict and needs a fresh approval in Relaxed. Deleting a Neon project, which removes every
branch and backup, and deleting or resetting a Supabase or Neon branch are permanent deletes on a database. Deploying
a Supabase Edge Function is a production deployment.

`bigquery.json` and `cloudflare.json` cover data stores over REST. BigQuery lists datasets and tables, reads a table
schema, runs a GoogleSQL query through `jobs.query` with the `sql` fact, and deletes a table or a dataset (with or
without `deleteContents`). Cloudflare lists and queries D1 databases with the `sql` fact, lists Workers KV namespaces
and Workers scripts, and deletes a D1 database, a KV namespace or a Worker. Every delete is permanent: a dataset, D1
database or KV namespace is a database-wide delete, so Balanced and Strict block it and Relaxed needs a fresh
approval. Deleting a Worker removes one production deployment: Relaxed and Balanced review it and Strict blocks it. Cloudflare's OAuth scopes are the ones Wrangler
requests (`d1:write`, `workers_kv:write`, `workers_scripts:write`); R2 has no OAuth scope there and is not packed.
Snowflake (a host per account), MongoDB Atlas (service-account credentials without OAuth scopes), Railway (one
GraphQL endpoint) and AWS (SigV4 request signing) are not packed.

`quickbooks.json` and `monday.json` cover accounting and work management. QuickBooks Online reads an invoice, emails
it to one named address, and voids or deletes it; deleting an invoice is permanent, so Relaxed and Balanced review
it and Strict blocks it. monday.com creates and deletes items and deletes boards through fixed GraphQL mutations
whose ids travel only as variables, so an argument cannot add a second operation. A deleted board takes every item
with it, so Balanced and Strict block it. Zendesk and Shopify (a host per account), Xero (a tenant header per call),
Trello (credentials in the query string), and the Intercom and ClickUp REST APIs (OAuth without scopes) are not
packed; Intercom's MCP server is, as described below.

`sendgrid.json`, `zoom.json`, `figma.json` and `discord.json` cover messaging and collaboration. SendGrid sends one
plain-text message whose recipients come only from the `to` argument, so the recipient facts name every address.
Zoom lists upcoming meetings, deletes a meeting, and moves a meeting's recordings to the trash or deletes them
permanently as separate actions with different reversibility. Figma reads, adds and deletes file comments. Discord
posts with every mention turned off, deletes one message, and bulk-deletes up to 100; a bulk delete of 100 needs a
fresh approval in Balanced. Twilio, Mailchimp, DocuSign, Calendly and Zapier are not packed: their credentials carry
no scopes Guard can name, or the action needs a per-account host.

`stripe.json` covers the Stripe REST API for money movement the MCP server multiplexes: reading the balance,
refunds, payouts, transfers to connected accounts and new prices, all with form bodies. Payouts, transfers and
prices carry money facts, so a workspace limit on `min_amount_minor` applies to the exact amount. `hubspot.json`
covers HubSpot CRM records over REST: listing contacts, companies and deals, setting one property on up to 100 records
in a call, archiving up to 100 records (restorable for 90 days), permanently erasing a contact under GDPR, and deleting
a custom object type, which is a delete on a table. Salesforce REST is not packed: its API host is per org, and a
pack's hosts are fixed.

Pack authors choose reversibility from what the provider can undo. An Airtable record delete is marked permanent: the
API has no undo, even where a plan keeps a history in the web app. Deletes that land in a trash, recycle bin or
version history (Dropbox, OneDrive, Outlook mail in Deleted Items, Teams soft delete, cleared Sheets ranges) are
marked recoverable. An action that can tell other people something is judged by that notice: deleting an Outlook
meeting sends cancellations to its attendees, so `outlook.events.delete` is permanent with a named audience, and
moving a meeting sends updates, so `outlook.events.update` is a send.

Known limits of the format, compared with hand-written adapters:

- An argument cannot be normalized before use (for example, removing dashes from an id). The pattern accepts only
  the canonical form.
- Paging values that a provider returns in a response header (such as a `Link` header) cannot be projected.
- A list longer than its `maxItems` is refused rather than truncated.
- Responses are projected from JSON only. Drive export therefore uses the `files/{id}/download` operation, whose
  JSON result carries a download link, rather than `files/{id}/export`, which returns the file bytes. When the
  export is still running, `drive.operations.get` reads the same operation until it carries the link.
- A Drive, Dropbox or OneDrive id or path does not say whether it names a folder, and deleting a folder takes
  everything inside it. Their trash, restore and delete actions therefore leave the scope and record count
  unknown, and Guard treats them as it treats any action of unknown size.
- A Calendar event delete is permanent whether or not guests are told: the quiet delete and the cancellation
  differ only in the notice. A rename and a reschedule are separate actions because an object field is always
  written, so one action cannot leave the event times unchanged when only the title changes.
- `gmail.messages.modify` changes user labels and the star, importance and unread marks only. Archive, trash
  and spam have their own actions with their own facts.
- A response path is split on dots. A step that starts with `@` reads the rest of the path as one key, so
  Graph's `@odata.nextLink` is projected as `next_link`. Any other key that contains a dot, or one that starts
  with a dot (such as Dropbox's `.tag`), cannot be projected. A digit step reads an array element, so
  `values.0` and `roles.0` work.
- An optional object field is still written as `{}` when its arguments are left out. OneDrive rename and move
  are therefore separate actions, as Calendar rename and reschedule are.
- A list page must be bounded by the request. Dropbox listings require a page size, and `sheets.values.get`
  requires a range with explicit row bounds in columns A to Z; a read longer than 1,000 rows is refused, so read
  a long tab in ranges.
- A placeholder fills a whole path segment, optionally followed by a Google-style custom method such as
  `{document_id}:batchUpdate`. Graph's inline function syntax (`search(q='...')`) is not expressible.
- An array argument in the query repeats the parameter (`records[]=a&records[]=b`), and a parameter name may start
  with one `$` for OData options such as `$top`.
- Response fields are scalars. Airtable records project their id, creation time and `Name`, `Status` and `Notes`
  fields when present; other columns are dropped.
- A secret pasted into an argument is not a fact. Guard's inspection finds it at call time, not the pack.
