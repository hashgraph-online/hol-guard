# Policy validation error guidance

Local `hol-guard policy` document commands retain their existing error exit status
and top-level `error` code. JSON failures from parsing or compilation now include
`diagnostics`: a bounded list of code, rule identity when available, safe field
location, and corrective action. Text output presents the first corrective action.

For example, a rule with a session lifetime cannot become a permanent SQLite
policy row. Validation fails with `unsupported_policy_lifetime`, the affected rule
ID, `$.spec.rules[*].lifetime`, and guidance to choose a supported lifetime only if
it preserves the intended behavior. Do not remove a matcher or broaden its target
to make validation pass.

| Rejection | Location and correction |
| --- | --- |
| Unsupported local matcher | The rule's `match` field; use a supported selector only when it preserves the intended target, or use a compatible runtime. |
| Unsupported local lifetime | The rule's `lifetime` field; permanent and until are the local row lifetimes. |
| More than 10,000 compiled rows | The rule whose expansion exceeds the document-wide row limit; reduce selector combinations without broadening targets. |
| Unknown schema field | The nearest known schema path and parser line/column when available; correct the field against the schema. |
| Credential field | The nearest known schema path; remove credentials and use the configured credential store. |

Compiler rule IDs come from validated documents and are bounded identifiers. A
parser failure may happen before there is a trusted rule identity; its `rule_id`
is then `null`, and an available rule index appears in the path. Arbitrary keys,
extension names, selector values, and raw policy text are excluded from these CLI
messages. Paths stop before an unknown field name. Parser diagnostics remain
limited to 20 entries; existing byte, nesting, collection and 10,000-row compiler
limits remain in effect. The first error message alone is not the complete list.

This projection covers local document parsing and compilation. Cloud bundle
signature rejection and runtime status remain their existing typed contracts;
this change does not claim a new signature-status diagnostic or an installed
runtime workflow result. No schema, signing, authorization, precedence, or import
transaction behavior changes.
