# Build an extension contribution from exported metadata

The Extension Builder converts an exported CLI inventory or MCP tool list into
native Guard contribution files, tests, and a reviewable integration plan. It
never imports or runs the target, installs packages, connects to a server, or
changes local protection settings.

```text
exported metadata -> discovery snapshot -> explicit review -> native contribution
```

Generated contributions remain **External, opt-in, and off until enabled**.
Names, help descriptions, and MCP annotations do not establish safety.
Unreviewed CLI operations require review; unreviewed and unknown MCP tools inherit
Guard's existing handling. Generated coverage is not a security certification.

## Generate a CLI kit

The checked-in examples describe synthetic tools, not production extensions.
Run from a HOL Guard checkout with this version installed:

```sh
hol-guard extensions generate \
  --from cli \
  --input docs/guard/extension-builder/examples/cli-surface.json \
  --slug samplectl \
  --executable samplectl \
  --name 'Sample CLI' \
  --publisher community.example \
  --publisher-name 'Example Maintainer' \
  --homepage https://example.test/samplectl \
  --upstream-version 1.0.0 \
  --output samplectl-kit

hol-guard extensions validate samplectl-kit
```

The output directory must not exist, and its parent must already exist. A kit
contains `discovery.json`, `review.json`, `report.json`, a README, a file manifest,
and native artifacts. CLI artifacts include contribution JSON, a detector, and
pytest cases. MCP artifacts include contribution JSON and pytest cases without
a CLI detector.

## Review and recompile

Read `report.json` and compare each operation with the upstream implementation.
Inventory coverage is not behavioral coverage. Copy `review.json` to a separate
file before editing it; generated code and manifests are compiler output.
Stable operation IDs map to structured paths or tool names in `discovery.json`.

A reviewed CLI entry has this shape:

```json
{
  "state": "review",
  "reviewed": true,
  "rationale": "The exact invocation prints local inventory without changing it.",
  "evidenceUrl": "https://example.test/samplectl/reference",
  "riskClasses": ["execution"],
  "saferAlternative": "Inspect the selected workspace before running mutations.",
  "safeArgv": [["items", "list", "--json"]]
}
```

This demonstrates the contract, not a recommendation about an actual executable.
`safeArgv` excludes the executable, starts with the exact operation path, and must
use discovered option names and arity. Its native parse must belong unambiguously
to that operation. Shell syntax, expansions, wrappers, environment overrides,
redirection, compound commands, unknown flags, and extra arguments cannot satisfy
the exact literal matcher. Root safe vectors are limited to known literal flags.

CLI states are `review` or `block`. Blocked operations cannot have safe vectors.
The root row (`path: []`) must remain `review`: its generic matcher covers the
whole executable. A root `block` is rejected as `root_block_scope`; root-only
blocking requires a purpose-built native matcher. A safe vector removes only its
own generated rule's review evidence, never an independent rule or required
floor. It does not attest executable identity or the ambient environment.

MCP states are `inherit`, `allow`, or `block`, and `safeArgv` stays empty.
Nondefault behavior requires `reviewed: true`, rationale, and a public HTTPS
reference. The reserved `other` row always inherits. Custom-grant precedence and
first-party block/sandbox floors remain unchanged.

```sh
hol-guard extensions generate \
  --from snapshot \
  --input samplectl-kit/discovery.json \
  --review samplectl-review.json \
  --output samplectl-reviewed

hol-guard extensions validate samplectl-reviewed
hol-guard extensions diff samplectl-kit samplectl-reviewed
```

`diff` exits 1 when valid kits differ. Changed source bytes, identity, or metadata
invalidate the old review binding. Review the new snapshot rather than copying
approvals forward. Snapshot replay rejects identity and adapter overrides.

## Generate an MCP kit

```sh
hol-guard extensions generate \
  --from mcp \
  --input docs/guard/extension-builder/examples/mcp-tools.json \
  --slug sample-server \
  --launcher npx \
  --package @example/sample-server \
  --publisher community.example \
  --homepage https://example.test/sample-server \
  --upstream-version 1.0.0 \
  --output sample-server-kit
```

Supply a complete `tools/list` result, JSON-RPC response envelope, or ordered
cursor-linked export. A result containing `nextCursor` without its remaining
pages is rejected. A paginated export uses this wrapper:

```json
{
  "pages": [
    {
      "requestCursor": null,
      "response": {
        "tools": [{"name": "read_item", "inputSchema": {"type": "object"}}],
        "nextCursor": "page-2"
      }
    },
    {
      "requestCursor": "page-2",
      "response": {
        "tools": [{"name": "write_item", "inputSchema": {"type": "object"}}]
      }
    }
  ]
}
```

Schemas are validated locally and fingerprinted, not executed or copied into
public source. External schema references are rejected. No `tools/call` request
is made. Exported inventories can depend on authentication scope and server
version, so an export is not a universal server census.

## Source adapters

| `--from` | Input | Supported representation |
| --- | --- | --- |
| `cli` | `guard.cli-surface.v1` JSON | Nested paths, flags, and single-value options |
| `help` | UTF-8 help text | Conventional Commands, Available Commands, and Subcommands sections; partial inventory |
| `click` | `Context.to_info_dict()` export or its command object | Static nested command metadata |
| `oclif` | `oclif.manifest.json` | Commands, aliases, flags, and explicit topic separation |
| `mcp` | Complete exported `tools/list` response(s) | Package identity, tool names, schema fingerprints, and untrusted hints |
| `snapshot` | Existing `discovery.json` | Exact replay with an optional bound review |

oclif topics default to colon-separated argv tokens. Use `--topic-separator space`
for a CLI configured with space-separated topics. Do not assume `items:list`
always represents two arguments. Click options with `nargs != 1` and greedy
multiple-value oclif options are rejected rather than assigned guessed arity.
Use an explicitly normalized surface or native detector for unsupported grammar.

Produce exports using the upstream project's trusted tools. Exporting can itself
execute upstream code and is outside the builder's trust boundary. The builder
never substitutes a live import, package install, or `--help` execution for a
missing export. All supplied text is data, not instructions.

## Integrate into a checkout

Create a feature branch through your normal Git workflow. The builder does not
create branches, commits, issues, PRs, releases, or activation settings.

```sh
hol-guard extensions apply samplectl-reviewed --repo /path/to/hol-guard
```

Inspect the relative paths and old/new hashes. To apply that exact plan:

```sh
hol-guard extensions apply samplectl-reviewed \
  --repo /path/to/hol-guard \
  --expected-plan THE_PRINTED_PLAN_DIGEST \
  --write
```

Replace the checkout path and digest with real values. Integration updates the
native contribution files, external trust map, CLI catalog when needed, Hatch
wheel inclusions, frozen-build artifact map, and authoring ownership records.
Existing catalog IDs, executable ownership, MCP package identities, or unowned
output files cause a conflict. Extend existing contributions instead of duplicating
them.

Inside the destination checkout:

```sh
python scripts/release/stage_guard_cloud_review_artifacts.py
python -m pytest tests/test_generated_cli_samplectl_extension.py
python -m pytest tests/test_guard_extension_contribution.py tests/test_guard_mcp_server_contribution.py
```

Generated cases exercise Guard's actual parser and registry, not target behavior.
Add implementation-specific cases for credentials, aliases, configuration,
remote targets, destructive flags, and unexpected arguments. Do not execute
destructive commands merely to satisfy a test.

Repeated identical apply is idempotent. Updates require owned files to match their
recorded bytes. Human detector edits are preserved as conflicts and require manual
reconciliation. Unrelated shared-file edits are retained; unknown insertion
anchors are not guessed. Shared LF/CRLF line endings are preserved.

Ordinary write failures trigger rollback. Per-file atomic replacement is not a
crash-atomic multi-file transaction. After a crash, inspect Git status and
`.hol-guard-extension-authoring.lock`; remove a stale lock only after confirming
that no authoring writer is active.

## Reproducibility and limits

Identical source bytes, metadata, review, and builder version produce identical
kit bytes without timestamps, local paths, usernames, or random identifiers.
SHA-256 bindings are integrity checks, not publisher signatures. CLI rule revisions
encode the complete discovery/review digest as an opaque numeric SemVer patch,
not a chronological upstream release number.

Source hashes bind raw bytes. LF-to-CRLF conversion changes the source digest and
invalidates prior review; unchanged snapshot replay remains byte-identical.
Raw descriptions, schema defaults, and examples are not republished from exports.
Explicit metadata, review rationale, guidance, and references are publishable
author input and are not automatically scrubbed of secrets. Inspect the final diff.

Inputs must be regular nonsymlink files with safe ancestors. Limits include:

| Resource | Limit |
| --- | --- |
| Source input | 1 MiB |
| JSON depth / nodes | 32 / 50,000 |
| Integer token | 512 decimal digits, excluding the minus sign |
| CLI operations / path depth / options | 256 / 8 / 128 per operation |
| MCP named tools | 79, plus the reserved `other` row |
| Compiled artifact / total kit | 4 MiB / 16 MiB |

Excessive input fails rather than truncates. Oversized integers produce
`integer_limit`, including in JSON mode, without echoing the input. Other
field-level limits are defined by the versioned authoring schemas in
`contracts/extensions/` and their bundled runtime validators.

These contracts do not certify every flag combination, dynamic plugin, server
scope, upstream version, executable, or Windows shell interpretation. Unsupported
or uncertain forms retain ordinary review or are rejected. Authoring performs no
hidden telemetry or network request.

## Exit statuses and related documentation

| Status | Meaning |
| --- | --- |
| 0 | Successful operation or equal diff |
| 1 | Valid kits differ |
| 2 | Invalid input, unsupported contract, or filesystem error |
| 3 | Output, ownership, layout, plan, or write conflict |
| 130 | Interrupted operation |

Use `--json` on a subcommand for deterministic results and domain error codes.
Argument-parser usage errors retain the normal CLI usage diagnostics.

See [validation instructions](VALIDATION.md), the
[CLI contribution guide](../extension-contributions.md), and the
[MCP contribution guide](../mcp-server-contributions.md) for native contribution
requirements and the activation boundary.
