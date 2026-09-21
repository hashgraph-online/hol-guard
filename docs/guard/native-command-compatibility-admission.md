# Native command compatibility admission

The reviewed program contains 291 catalog rules. Of these, 249 carry a
declarative matcher and 42 have `matcher = null`. The null entries cannot be
treated as successful non-matches. Some depend on Python request classification,
some exist only as permission/catalog metadata, and GitHub also has permissions
without any corresponding rule. The native compatibility module adds explicit
attribution and bounded admission for that surface. It does **not** certify
complete native parity for all 291 rules.

## Source audit and control attribution

`command_evaluation.evaluate_command` combines declarative observations with an
optional `compatibility_action_class` supplied by the request classifier. The
registry's `rule_for_action_class` supplies that compatibility rule. Separately,
`_direct_github_permission_ids` classifies each GitHub segment and adds every
capability's permission, including permissions that have no rule.

The source catalog has four such GitHub permissions:

| Permission | Rule | Native admission in this tranche |
| --- | --- | --- |
| `command.github.permission.read-local` | None | Static CLI metadata/auth-state forms |
| `command.github.permission.read-remote` | None | Static reviewed CLI reads and REST GET/HEAD forms |
| `command.github.permission.propose-remote` | None | Bounded static title/body PR proposals |
| `command.github.permission.routine-review-thread-remote` | None | GraphQL remains unsupported; owned uncertainty blocks admission |

The classifier returns separate `rule_matches` and `permission_matches`, each
with segment indexes and an uncertainty flag. The native program must validate
their owners against its admitted catalog. Permission-only observations must
participate in disabled permissions, disabled owner extensions, dependency
closures, observation/receipt digests, and accounting. They must not be dropped
because no rule exists or because their baseline action is `allow`.

Fifteen Git porcelain entries are currently inert in Python's observation
registry: they have neither a matcher nor `compatibility_fallback`. For example,
`git status`, `git log`, `git diff --no-ext-diff --no-textconv`, and `git ls-files`
produce no Python extension observations. Native attribution intentionally
closes this omission so an otherwise benign command cannot evade its disabled
permission. This is a stricter control behavior, **not a Python observation
parity result**. It can also apply the catalog's existing baseline review floor
to a newly attributed operation such as `git branch`.

## Admission and qualification boundaries

| Catalog family | Null rules | Implemented behavior | Remaining qualification |
| --- | ---: | --- | --- |
| Git porcelain | 15 | Direct subcommand attribution; leading configuration/context options yield owned uncertainty | Context-bound options and user-visible floor changes require integrated qualification |
| Git fetch/index verification | 2 | Fetch and staged-index forms identify the affected rule and yield uncertainty | Repository origin, helper/configuration, staged-byte and exemption proofs |
| GitHub | 15 | Static CLI and REST capability classification, mixed mutation owners, Boolean merge flags, and permission-only reads/proposals | GraphQL, indirect commands, complex option/selector spellings, dynamic/literal provenance and external bodies |
| Docker | 2 | Direct login/push/run ownership; remaining sensitive-context/config forms yield uncertainty | Compose, Buildx, exported environment, credential/path resolution and context-sensitive safe variants |
| Data transfer | 2 | Network file-transfer/credential candidates yield owned uncertainty | Full upload-operand, source, pipeline and interpreter dataflow classification |
| Kubernetes secrets | 1 | Direct Secret resource/token/extract operations; other contexts yield uncertainty | Global option ownership, raw API, exec/cp, volumes, JSONPath and stdin proofs |
| Shell mutations | 5 | Environment dump attribution and explicit uncertainty for relevant mutation/configuration/expansion candidates | Full write/path provenance, interpreter, destructive-operation exemptions and literal expansion proof |

`compatibility_rule_ids()` inventories the 42 identities handled by this
boundary. The number is not a count of completely translated or qualified
classifiers. The Rust corpus exercises every identity, including explicit
unsupported outcomes. Its metadata declares `complete_python_parity = false`
and `qualification_complete = false`.

The native classifier uses the existing canonical command once. It performs no
shell execution, subprocess launch, filesystem discovery, repository read,
network request, or second shell parse. It bounds command bytes, argument/token
counts, segment count, and individual segment inputs, and checks the caller's
deadline before, during, and after classification. Deadline, byte/count, parser,
wrapper, PATH, and environment-context admission failures return a typed global
error. Relevant forms with unresolved semantics produce owned uncertainty.
Neither is a successful empty observation result.

The integration contract treats uncertainty as a blocking classification
failure. Explicitly enabled permissions cannot erase it or weaken intrinsic
hard floors. Mode-specific final delivery and availability behavior remain the
responsibility of the existing runtime; this helper does not set rollout
capabilities, change Watch delivery, or create an approval authority.

Several conservative consequences are intentional and remain unqualified:
unproven Git aliases/plumbing, including `git rev-parse` without a catalog owner,
do not inherit an unrelated native benign classification; Docker/Kubernetes
forms outside the small admitted subsets can require unsupported admission;
and quoted dynamic-looking GitHub arguments are not assumed to have literal
provenance. A fuller port must replace these uncertainties with evidence and
independent positive/negative vectors before expanding admission.

## Evidence

`native-command-compatibility-v1.json` freezes 193 synthetic command cases. Of
these, 123 carry manually selected GitHub capabilities checked independently
against the Python classifier at `bc5500b18`. The Rust test checks exact rule and
permission ownership, segment indexes, and supported versus uncertain results.
The Python test rechecks the capability oracle and owner mapping independently
of Rust, and explicitly records the Git attribution expansion.

Other focused Rust tests cover the exact 42-entry inventory, permission-only
GitHub reads, the benign Git permission gap, compound occurrence preservation,
deadline/byte/parser/context admission failures, and explicit GraphQL
uncertainty. These are semantic and admission evidence, not installed launcher
latency measurements or cross-platform rollout qualification. Integration must
still exercise disabled/explicitly enabled controls, receipt binding, snapshot
renewal, and delivered runtime behavior at its actual authority boundary.
