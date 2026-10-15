# Native local budget reservations

This component serializes reservations under the existing native transition
lock and commits all matching account/user/workflow buckets in one ledger.
Current signed policy selects the limits; native frozen input supplies volume
and account binding. User/workflow bindings must come from an authenticated
worker registry. This component does not authenticate supplied actor bindings,
create an execution grant or publish an RPC.

The ledger is content-addressed, private and bounded to 4 MiB of active data,
without a separate action-count cap. Storage exhaustion refuses with a storage
capacity error; policy maxima are permission limits, not storage guarantees. Its
root and last observed time live in a purpose-separated platform secure account
in production. Only tests use a private anchor file. Missing, changed or rolled
back ledger data refuses, and existing history cannot bootstrap after losing
its protected anchor. Ledger and immutable replay-index bytes are durable before
the protected root commits; persistence failure returns no reservation. Before
creating the first immutable files, an authenticated empty anchor is committed.
Retries can ignore uncommitted orphans using this anchor; deleting an anchor
over existing history still refuses rather than resetting usage.

Every matching chunk counts actions, recipients, records and bytes. Dropping a
reservation, including after an uncertain provider outcome, does not refund
usage. Changed windows or limits preserve bucket identity. Volume older than
the maximum supported window can leave the active ledger, while replay
tombstones remain in the existing immutable index. After a protected commit,
superseded ledger files are removed on a best-effort basis; replay-index nodes
and failed-write orphans remain. Administrative retention remains unfinished.

Reservations currently require Unix directory synchronization. Windows and
other unsupported platforms refuse before accessing reservation state with
`native_business_budget_durability_unavailable`. Their directory-entry durability
and crash-recovery protocol remain unfinished; a non-Unix sync no-op is never
used as a reservation durability barrier.

There is no connected worker caller, actor registry or Cloud allocation
authority yet. Budget-bearing business actions remain refused by native review
production. These are local counters, not a global multi-device guarantee or
an offline allocation protocol. Strict credential custody, reusable accounts,
approval/dispatch integration and all business acceptance journeys remain
unqualified. No provider request was made.
