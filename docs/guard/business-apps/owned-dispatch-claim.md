# Owned business dispatch claim

An exact provider operation cannot use the generic workspace-review retry RPC.
That RPC returns bindings for a command retry and permits recovery of a lost
response. A provider send must retain frozen input and refuse a second attempt
even when the first outcome was lost.

The existing decision envelope has a distinct signed delivery mode,
`owned_business_dispatch`. The generic native verifier still accepts only
`validated_retry_only`; changing the mode invalidates the signature. Neither a
retry-only decision nor a replayed owned-dispatch decision supplies a new
business claim.

The private native `claim_owned_business_request` path selects the existing
request by ID, loads its authenticated private business snapshot, rechecks the
current policy and native origin, and derives workspace/scope from the installed
native authority. Under the existing transition lock it verifies the signed
decision and records its durable semantic claim before returning the owned
input. Only an explicit signed allow can enter this path. The returned input
has no Clone, Debug or serialization implementation; later private-file changes
cannot change its retained bytes.
The size cap applies before either decision is decoded. Verification obtains a
fresh timestamp after snapshot loading. Owned-input release rechecks time after
durable storage against both decision and policy expiry; expiry or a clock
rollback leaves the attempt consumed but releases no input.
The owned API accepts original decision bytes and shares the generic strict
decoder: duplicate keys, nesting/collection limits and canonical byte equality
are checked before typed decision validation. A parsed browser/model object is
not a substitute for the original signed delivery bytes.

The generic resident RPC still refuses all business snapshots before consuming
a claim. There is no RPC that exports this owned input or turns the new mode
into a command grant. The new worker-only function is not routed yet. Cloud
currently signs retry-only envelopes and does not advertise this new mode.
Worker/provider identity, isolated credentials, authenticated input production,
provider dispatch and durable confirmed-outcome reporting remain separate
unfinished integrations. A durable claim proves at most one admitted attempt,
not that the provider accepted an operation. Lost outcomes must remain unknown;
this claim path deliberately cannot authorize a blind retry.

Tests use synthetic signed authorities and real private native storage. They
check mode/signature separation, durable replay refusal, concurrent lock
contention with one admitted attempt, and owned bytes after private-file mutation.
They do not enroll a real account, send mail, prove isolation or qualify an agent
or business acceptance scenario.
