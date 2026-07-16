# GitHub CLI Capability Boundary

Guard classifies each `gh` invocation before shell pipeline formatting is considered. The classifier uses a positive
allowlist: a command is prompt-free only when its complete remote capability is statically proven read-only.

## Capability decisions

| Capability | Examples of command shape | Guard behavior |
| --- | --- | --- |
| Local metadata | CLI version, help, and completion | Allow without approval |
| Proven remote read | `pr view`, `issue list`, and explicit API GET requests | Allow without approval |
| Remote mutation | Known state-changing subcommands, write-capable REST methods, and GraphQL mutations | Require approval |
| Unverified | Extensions, aliases, dynamic arguments, file/stdin request bodies, or unreviewed pipeline stages | Require approval |

For `gh api`, fields select a write-capable request unless `GET` is explicit. GraphQL is prompt-free only for one
static query document. Mutation and subscription operations require approval; multiple operations, method overrides,
external query files, and external variable files are treated as unverified.

## Pipeline composition

Output formatting does not downgrade the capability of the producer. A known remote mutation still requires approval
when its output is piped through `jq` or a read-only Python observer. Conversely, a proven GitHub read remains
prompt-free when every downstream stage is a reviewed, output-only formatter. Redirection or an unreviewed consumer
requires approval because the complete composition is not proven read-only.

## Developer experience

Common inspection workflows stay prompt-free, including `gh pr view`, `gh issue list`, explicit REST GET requests,
single GraphQL queries, and their reviewed `jq` or Python formatting pipelines. Custom extensions and aliases require a
confirmation because their implementation can change independently of Guard. When an alias is used frequently, invoke
the underlying built-in read command directly to preserve a prompt-free workflow.
