# Business cumulative budget contract

The signed native business policy may carry a nonempty `budgets` array. Each
entry declares a versioned identifier, workflow/account/user scope, operation
selector, window and cumulative actions/recipients/records/bytes allowances.
Every allowance is required; zero is zero allowance, never unlimited. Windows
are positive and bounded to 24 hours, counts use the shared safe wire-integer
bound, and duplicate IDs, unsupported scopes/versions, nulls and unknown fields
refuse. Absence preserves the earlier policy wire shape.
Per-request minimum volume selectors are forbidden in cumulative budgets, so
chunking cannot make individual actions fall outside a declared limit.

Complete GuardPolicy documents carry these declarations in `spec.budgets`.
The native compiler retains them in the signed binding and source digest;
changing an allowance changes the reviewed source identity. YAML formatting
preserves declarations. The legacy local-row compiler refuses budget-bearing
documents rather than dropping limits, including when their rules are disabled.

This source contract does not implement cumulative enforcement. A native
business policy containing budgets blocks business actions and refuses review
production with `native_business_budget_executor_unavailable` until durable
reservation authority is integrated. No operator can activate a budget that is
silently ignored. Earlier native clients reject the unknown declaration.

The remaining BIZ-018 work includes authenticated workflow/user context, atomic
durable counters, conservative uncertain outcomes, managed multi-device
reservation or bounded offline allocations, Cloud policy serialization and
version negotiation, retention/reconciliation and real acceptance journeys.
No exact global limit is claimed during disconnection. No route or account
mode is enabled by this contract.
