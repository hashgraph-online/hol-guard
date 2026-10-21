# Business selectors in policy drafts

GuardPolicy YAML accepts the versioned `match.business` selector declared in
the canonical policy schema. The packaged schema carries the same definition.
Draft parse and format preserve all selectors, including restrictions beside
`business`. Services and operations must agree; unknown fields, null selectors,
duplicate entries, raw account identities and unsafe counts are invalid.
Account bindings must contain exactly 64 lowercase hexadecimal characters.
The compact serialized business selector must fit the native 64 KiB bound,
even when each array individually fits its limit.

Draft validity does not enable enforcement. The local policy compiler still
refuses an active business rule with `unsupported_policy_match`, including an
`allow` rule. It cannot flatten a business rule into a legacy decision or ignore
its actor, workspace or harness restrictions. Native selector predicates and
snapshot bindings do not supply authenticated document activation or action
facts. An authenticated complete-document consumer and publisher lifecycle
remain required before these drafts can become active business protection.
