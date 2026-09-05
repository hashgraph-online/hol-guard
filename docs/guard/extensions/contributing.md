# Contributing a command safety Extension

HOL Guard Extensions are security boundaries, not downloadable regex packs. A contribution must preserve parse-once
command semantics, evidence-only detection, monotonic policy authority, stable public IDs, privacy, and predictable
latency. This guide makes those requirements reviewable and gives contributors one path from idea to merge.

## Choose the contribution type

| Contribution | Use it for | Expected scope |
| :--- | :--- | :--- |
| New Extension | A distinct command capability with its own stable identity | Metadata, rules, fixtures, docs, and registry coverage |
| MCP server | A well-known stdio MCP package with default tool policy | `contributions/mcp-servers/mcp.<name>.json`, trust-class map, catalog tests |
| Coverage expansion | A dangerous operation owned by an existing Extension | Matcher/rule updates plus destructive and safe-counterpart cases |
| False-positive fix | Preview, read-only, help, or bounded behavior incorrectly reaches review | A positive safe predicate and regression cases; never a global suppression |
| Documentation | Better examples, references, or operator guidance | Documentation plus directory validation when catalog metadata changes |

For a new Extension or a material authority change, open an
[Extension proposal](https://github.com/hashgraph-online/hol-guard/issues/new?template=command-extension-proposal.yml)
before implementation. Security vulnerabilities belong in the private process documented by
[`SECURITY.md`](../../../SECURITY.md), not a public proposal.

## Proposal quality bar

A reviewable proposal includes:

1. The capability boundary and proposed `command.<domain>[.<tool>]` ID.
2. Supported executables, dialects, transports, subcommands, and version assumptions.
3. Representative destructive commands and a safe counterpart for every operation family.
4. Compound-command, wrapper, quoting, reordered-flag, and malformed-input cases.
5. Risk and action classes, default severity/mode, and safer alternatives.
6. Overlap with existing Extensions and why a new identity is preferable to extending one.
7. Privacy and performance considerations, with authoritative CLI references.

Maintainers may redirect a proposal to existing coverage when the capability boundary overlaps. Stable IDs are part
of receipts, remembered decisions, managed controls, and automation contracts, so naming is reviewed before merge.

## Implementation map

Use the narrowest existing module that owns the domain:

- Core specs live in `command_builtin_extension_registry.py`; core compatibility rules live in
  `command_builtin_rules.py`.
- Domain specs and rules live together in the matching `command_*_extensions.py` module and are assembled by
  `command_builtin_extension_catalog.py`.
- Package-manager coverage lives in `command_package_extensions.py` and delegates decisions to Package Firewall.
- Shared typed contracts live in `command_extension_specs.py`, `command_rules.py`, and `command_extensions.py`.

Directory categories are presentation-only and never affect runtime authority. The renderer assigns known families to
curated sections and places every otherwise-valid new ID in **Other extensions**, so a registry addition cannot break
documentation generation. Add an explicit category rule when the new family has a durable public taxonomy; do not
add documentation-only fields to the runtime security contract.

Do not add a second parser, retokenize raw shell text inside a matcher, import workspace code, or let an Extension
emit an allow/approval decision. Matchers return structured evidence; Guard policy retains final authority.

## Required test matrix

Every new rule needs table-driven cases that prove:

- destructive examples reach both side-effect-free inspection and runtime review;
- safe previews, read-only variants, and help commands remain non-reviewable;
- reordered flags, quoting, paths with spaces, wrappers, separators, pipelines, and suffixes preserve meaning;
- malformed or unsupported input produces uncertainty and never implies safety;
- overlapping Extensions retain all evidence and the strongest controlling requirement;
- rule IDs, risk classes, action classes, executables, and permissions remain owned by the declared Extension;
- evidence and persisted catalog fields contain no command text, local paths, environment values, or secrets.

Reuse the assertions in `tests/command_extension_contracts.py`. Put focused tests beside the owning domain suite, for
example `tests/test_guard_command_storage_extensions.py`, rather than growing one universal test file.

## Local validation

Run the focused domain suite first, then the registry and documentation contracts:

```bash
uv run pytest -q tests/test_guard_command_<domain>_extensions.py
uv run pytest -q \
  tests/test_guard_command_extension_registry.py \
  tests/test_guard_command_extension_directory.py
uv run python scripts/render_command_extension_directory.py --check
uv run ruff check <changed-python-files>
uv run ruff format --check <changed-python-files>
```

When metadata changes, regenerate the directory and commit the result:

```bash
uv run python scripts/render_command_extension_directory.py
```

Broader parser, policy, persistence, or authority changes require their affected suites and the full release gates.
Document the exact commands and results in the pull request.

## Review rubric

Maintainers evaluate Extension changes against these merge gates:

- **Boundary**: one coherent capability, canonical ID, no ownership ambiguity.
- **Detection**: structured matchers, bounded complexity, complete index hints, deterministic output.
- **Safety**: destructive coverage and explicit safe counterparts without cross-rule suppression.
- **Authority**: evidence cannot weaken required floors, managed restrictions, or another match.
- **Compatibility**: stable IDs and declared action/risk classes preserve existing receipts and controls.
- **Privacy**: no raw command, secret, path, or environment persistence in catalog/evidence fields.
- **Performance**: representative benign and destructive cases stay within parser and matcher budgets.
- **Operability**: clear safer alternatives, authoritative references, directory entry, and focused tests.

A change is complete only when code, catalog, documentation, and tests describe the same protection boundary.
