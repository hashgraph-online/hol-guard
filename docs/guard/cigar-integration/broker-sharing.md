# Native broker sharing

The native library drives an actual CIGAR 0.14.1 `LocalContextBroker` and independently supervised CPython clients. The product selects one graph or broker per granted scope, binds separate paired MCP connections, and exposes explicit shared-note permissions and operator review. The native product path and the installed React/MCP workflow pass actual-worker acceptance on the local macOS arm64 candidate. [Installed sharing evidence](evidence/receipts.json) records the qualified package and limits.

## Ownership

| Component | Responsibility |
| --- | --- |
| `VerifiedRuntime` | Actual interpreter/package/worker verification, broker activation, private transports, cancellation and cleanup |
| Native broker registry | Opaque domain/client capabilities, source catalog, exact revisions, scopes, leases, budgets, retained tickets and proposal state |
| Host SDK bridge | Mechanical calls to public broker ingestion, grant, inspection, admission and revocation APIs |
| Independent client bridge | Mechanical calls to public client compilation, explanation, proposal and forgetting APIs |
| Guard product integration | Current native app/workspace/source permission, source I/O, native facts, operator proof and post-operation policy fences |

Python performs no source reads, secret scanning, policy evaluation, identity selection or proposal admission decision. The native supervisor launches isolated `-I -S -B` Python with a sanitized environment and owned pipes/process groups. The existing runtime gate applies before any broker is created. Independent sharing also requires enabled sharing and agent-context preferences. Background activation additionally compiles and explains synthetic evidence through an actual independent broker client before returning shared readiness. An explicit off-state recheck can run that synthetic check without granting user sources or retaining a runtime. Optional [private persistence](private-persistence.md) has its own storage permission and actual-worker qualification.

The host broker channel remains separate from client channels. Rust transfers each SDK grant from the host's private pipe to a new client's private pipe. Grant material is absent from public handles, briefs, proposal responses, argv, environment and diagnostics. Public handles have no deserialization constructor. A domain handle also binds the actual broker epoch, so reopening the same domain name cannot revive an earlier handle. Rechecks span broker handshake and client import/initialization.

These are same-host API scopes and mutual grant proofs over explicit loopback. They do not attest an AI application's executable or provide hostile-tenant OS isolation.

## Sources, contexts and proposals

Native host source replacement uses exact SDK compare-and-swap revisions. Versions remain canonical decimal strings, including values beyond JavaScript's exact integer range. The returned revision is authoritative for the next operation: admitting provenance can advance a revision even when its document collection is empty.

Native document admission rejects invalid identifiers, duplicate IDs, control bytes, oversized material and scanner matches before forwarding text. The scan deadline covers the whole admitted batch. Selected file reads and app/workspace permission remain the product caller's responsibility through existing protected source admission. The broker library accepts admitted text rather than opening a file locator.

Each client reads only its assigned sources. A writable client may propose changes only to the dedicated `guard:notes` source; it cannot write selected project files or native policy/action facts. Source dependencies must also be inside its readable scope. A grant issued before a note acquired new dependencies cannot compile that note through a narrower scope afterward.

Compilation enforces native budgets and required-source membership, then validates the actual SDK result against the host's document catalog, domain, view, policy revision and citations. SDK tickets remain private. Retained observations have unique native IDs even when the SDK returns the same snapshot repeatedly. Eviction explicitly forgets the old SDK ticket, keeping both native and SDK retention bounded. Explanation checks source versions and the SDK ticket again.

Proposals require a still-current retained context. The client supplies an idempotency key, expected note-source revision and bounded candidate documents. Rust fixes the destination and records the cited source basis. A reused key with changed material or basis conflicts. Nothing becomes visible in a compiled context before host admission.

Host inspection compares the SDK's quarantined proposal with the native copy. Admission rescans the material, checks its original basis, and uses the SDK's source compare-and-swap. Competing proposals can share the same expected revision; only one can be admitted against it. A changed upstream basis is stale. Known conflicts preserve the runtime so the operator can inspect and reject the losing proposal.

Admitted notes retain their upstream provenance. A proposal based on an earlier note inherits that note's original dependencies. Carrying earlier note documents into a replacement also preserves their dependencies when the new snapshot did not render those notes; foreign or stale dependencies refuse the proposal. Subsequent upstream changes invalidate dependent SDK context. `broker_context_sources` exposes the cited dependency closure, and native history retains the corresponding file-access checks even when only a derived note was rendered.

Client status and forgetting are scoped to that client's proposal keys. Admission and rejection are host-only SDK operations. Admission uses the existing authenticated, proof-protected workspace-grant route; the read and access-reduction routes cannot admit a proposal. Rejection and clearing use the authenticated access-reduction route. Admitting evidence grants no command approval or execution permission.

## Product controls and lifecycle

Settings → Protection offers a separate sharing choice after Context for AI apps. Saving a preference change stops the old generation; activating sharing requires the broker check, followed by new source grants and pairing. Global sharing creates no implicit file or note permission. Each app/workspace grant separately chooses shared-note reading and proposals; both default off, and proposals require reading.

Ordinary graph mode keeps its one-connection-per-scope rule. Shared mode permits separately paired connections for the same app/workspace. Human pairing prepares the connection's distinct SDK client within its finite five-minute native session, including client import and artifact checks. Capacity refusal removes both the logical view and native session before returning, so an apparently authorized connection cannot defer a capacity failure to its first compile. Existing client, queue and deadline limits remain unchanged. SDK grants are delivered only over private native-owned pipes. A connection's ordinary planning snapshots are retained separately. This release does not silently renew expired pairing: restart Guard's MCP connection in the app and pair its new public code to continue after expiry. Operator views and the separately enabled private execution client also consume the shared eight-client capacity; eight is not a promise of eight simultaneous agent connections.

Allowed connections discover `propose_guard_context_note`, `get_guard_context_proposal_status` and `forget_guard_context_proposal`. A note proposal uses a snapshot from `get_guard_context`, a stable request key, and at most 4 KiB of UTF-8 text. It appends a bounded candidate note collection, never edits a selected file. Changed material under a retained key conflicts. After an uncertain outcome, inspect status; there is no automatic mutation retry.

Workspace context access loads proposal metadata without text. Opening a proposal performs protected basis-file checks twice and displays added/changed text, the prior note collection when its revision still matches, source state and exact revision strings. Unsafe sources withhold both collections. Changed readable sources allow inspection but prevent admission. Conflicts require rejection or a new current proposal. The proof dialog confirms evidence admission separately from command approval.

Source refresh preserves historical observations but clears notes derived from changed sources and revokes affected SDK views. Explicit shared-note clearing removes notes, proposals, current contexts and that scope's context history. Withdrawal narrows views; connection/workspace revocation and global opt-out terminate their authority. Native maintenance expires sessions, notes and historical observations. Restart restores no grants, contexts or proposal authority. Unchanged source material avoids redundant SDK replacements; this is an implemented reuse behavior, not a measured speed claim.

## Bounds and failure behavior

| Resource | Implemented bound |
| --- | --- |
| Domains | Configured active-workspace limit, maximum eight |
| Independent clients | Eight across one verified runtime |
| Client lease | At most five minutes; native expiry includes grant delivery and import time |
| Retained contexts | Eight tickets per client, explicitly forgotten on eviction |
| Proposals | Four retained records per client; 32 per domain; at most 32 documents / 16 KiB per proposal |
| Proposal lifetime | At most five minutes, bounded by the client's native lease |
| Source data | 128 sources, 1,024 graph documents, 64 KiB per document, 4 MiB text per domain |
| SDK dispatch | Two shared agent jobs; one job / 512 KiB per client; 500 ms maximum queue wait |
| Native IPC | Existing 1 MiB request / 4 MiB response limits, four-second broker RPC deadline |
| Broker transport | Explicit bounded connection/byte/deadline settings; no discovery or public bind |

The host and clients remain under native cancellation. Unknown transport/deadline outcomes close the optional generation and do not trigger an automatic mutation retry. Explicit revocation removes the client capability; closing/reopening a domain creates a fresh SDK epoch. Runtime shutdown reaps live clients and the host process group. Default graph mode creates no broker or listener.

Encoded history sizes and these capacity bounds do not measure RSS, latency benefit or task usefulness. The observed shutdown timing in the native test is a local sample, not a complete lifecycle SLO.

## Qualification and remaining integration

The actual-worker test uses the unchanged approved final CPython 3.14.7/CIGAR 0.14.1 candidate. It exercises separate client processes, source/context isolation, read-only refusal, quarantine, exact host inspection, inherited provenance, competing source CAS, finite leases, quotas, repeated-ticket eviction, revocation, fresh epochs and cleanup with live children. Unit checks cover decimal revisions and unsafe material. Existing graph/actor/interpreter tests and Guard's native assistance regression profile remain required alongside it. [Native evidence](evidence/receipts.json) records the exact qualification and any failed attempts.

The native product acceptance covers actual broker qualification, two paired connections in one scope, snapshot isolation, conditional tools, quarantine/idempotency, operator metadata/detail, admission-route separation, CAS conflicts, private proposal status, note citations, inherited history dependencies, unsafe-source withholding, refresh invalidation, read-only cached-tool refusal, clear, revoke, withdrawal, off and explicit off-state recheck without restored access.

Installed package `4925f440` passes 52 backend tests and the expanded real browser flow. The browser uses two actual MCP stdio processes, independently pairs both to one scope, proposes and reviews note text, requires separate admission proof, retrieves the admitted note through the other connection, rejects a later proposal, invalidates notes after a file update, clears, revokes and turns off. Keyboard review and mobile rejection pass. The ordinary source/history/native-review journey also passes, with both existing approval choices available. This does not exercise a real command executor. The first installed attempt exposed a missing exact-field Python status projection; the repair and both failed reports are retained in the evidence.

The native library also opens an explicit private SQLite store through an opaque directory capability and rebuilds its validation catalog only from freshly readmitted documents matching saved provenance. Actual-worker restart, fresh epochs, rejected old handles, withheld unadmitted text and corrupt-store refusal pass. The product now includes its Guard-owned cache coordinator, retention/removal controls and installed acceptance; see [private persistence](private-persistence.md). The `95657b30` installed qualification repeats all three real browser journeys and 69 backend/executor/SDK cases, plus the additional five-client/source-update/twelve-attempt MCP scenario. [Pairing evidence](evidence/receipts.json) binds that product and preserves its earlier failures. Six connections are authorized when the operator and private execution client consume the other two SDK slots; this is not twelve simultaneous grants.

The current `ed5011ac` [installed suite](evidence/receipts.json) passes actual MCP/Pi/OMP SDK delivery, bounded paired-client/source-update/revocation, persistence restart and supported native execution association, alongside the three browser flows. The matching [complete SLO/fixed cohort](evidence/receipts.json) passes its original resource and latency gates. [Local acceptance](ACCEPTANCE.md) distinguishes these current checks from the older broker/CAS/retention receipts through source equivalence. Interactive external apps/models, other platforms/full Desktop/public release, twelve simultaneously authorized agents, long-term memory stability and model/human savings remain unqualified.
