# Native business attempt journal

This source component records a successful private owned claim before returning
the worker value. Failure to persist spends the approval and returns no value.
There is no account route, provider dispatch caller, restart grant or resend API.

The native transition lock and existing bounded private atomic persistence store
request/input fingerprints and one of `claimed`, `attempt_started`,
`api_accepted` or `unconfirmed`. Provider bodies, addresses, bearer credentials
and raw message IDs are absent. API acceptance is not delivery confirmation.
The owned journal checks its expected persisted bytes before each transition.

A future registered worker must enforce current policy and budgets before
persisting `attempt_started`, then perform at most one provider call. A crash or
terminal-write failure after starting leaves the outcome unknown. A stored
`attempt_started` record must never be interpreted as permission to resend.
No deserializer reconstructs an owned journal handle from stored progress.

The directory has a fixed capacity of 128 validated retained entries; recognized
crash temporary files do not consume record slots. Scanning has a separate
512-entry bound; unexpected or corrupt retained evidence refuses new claims.
Capacity refuses
new claims without deleting evidence. Administrative retention, presentation,
reconciliation, budget reservation and the worker dispatch integration remain
unfinished. Private local storage does not establish isolation from a same-user
agent or customer-specific credential custody. No acceptance mode is qualified.
