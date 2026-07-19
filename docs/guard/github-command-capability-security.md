# GitHub CLI Capability Boundary

Guard classifies each `gh` invocation before shell pipeline formatting is considered. The classifier uses a positive
allowlist: a command is prompt-free only when its complete remote capability is statically proven read-only.

## Capability decisions

| Capability | Examples of command shape | Guard behavior |
| --- | --- | --- |
| Local metadata | CLI version, help, and completion | Allow without approval |
| Proven remote read | `pr view`, `issue list`, public-key listing, and explicit API GET requests | Allow without approval |
| Local configuration write | Selecting a default repository | Require approval |
| Bounded maintenance | Review-thread resolution and narrow metadata maintenance | Require approval; eligible for a future signed workflow claim |
| Content mutation | Issue, pull-request, review, comment, and repository content changes | Require approval |
| Merge | Pull-request merge and auto-merge operations | Require approval |
| Publication | Release creation, editing, and artifact upload | Require approval |
| Workflow | Dispatch, rerun, cancellation, enablement, and workflow-file changes | Require approval |
| Force or delete | Forced ref changes and local or remote deletion | Require approval |
| Secret or access | Secret changes, key changes, collaborators, permissions, protection, and visibility | Require approval |
| Other remote mutation | Known state-changing operations without a narrower class | Require approval |
| Unverified | Extensions, aliases, dynamic arguments, file/stdin request bodies, or unreviewed pipeline stages | Require approval |

For `gh api`, fields select a write-capable request unless `GET` is explicit. GraphQL is prompt-free only for one
static query document. Mutation and subscription operations require approval; multiple operations, method overrides,
external query files, and external variable files are treated as unverified.

One command may retain multiple capabilities. For example, `gh pr merge --delete-branch` records both merge and
deletion, and mixed GraphQL root fields retain every classified mutation. Guard applies the strongest resulting floor.
Bounded maintenance is only marked as potentially workflow-authorizable; without a valid signed workflow claim it
still requires approval.

## Pipeline composition

Output formatting does not downgrade the capability of the producer. A known remote mutation still requires approval
when its output is piped through `jq` or a read-only Python observer. Conversely, a proven GitHub read remains
prompt-free when every downstream stage is a reviewed, output-only formatter. Redirection or an unreviewed consumer
requires approval because the complete composition is not proven read-only.

## Developer experience

Common inspection workflows stay prompt-free, including `gh pr view`, `gh issue list`, public-key listing, explicit
REST GET requests, single GraphQL queries, and their reviewed `jq` or Python formatting pipelines. Custom extensions
and aliases require a confirmation because their implementation can change independently of Guard. When an alias is
used frequently, invoke the underlying built-in read command directly to preserve a prompt-free workflow.
