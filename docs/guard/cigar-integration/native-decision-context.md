# Native decision context

Context assistance can prepare a cited brief for a recent native Guard evaluation. The host resolves a decision selector against its own bounded, authenticated native-origin data. The brief includes mandatory decision and policy documents, plus relevant files from the independently approved app/workspace scope. It remains optional supporting data.

## Review screen

A review with an attached native-origin receipt shows **Optional decision context** below its existing decision controls. **Prepare decision context** explicitly checks runtime readiness and the dashboard's workspace grant before compiling. Opening a review does not start, verify, scan, or call the SDK. Loading, refusal and context failures have separate state and never disable the existing approval controls.

The panel shows plain-text excerpts, source lines and document digests. **Verify context sources** rechecks the retained selection against native origin, source, workspace policy and current native policy fences. **Refresh decision context** prepares a replacement; a successful replacement permits comparison with the earlier, explicitly historical brief. Failed checks discard both disclosures. Status and scope polling also clear disclosures when effective access changes. **Manage context access** opens Protection.

The **Native decision association** drawer states what the binding establishes. It identifies the attached native evaluation, its action class, operation and policy generation. It does **not** authenticate a mutable queue row's current command, prove current executable bytes, or supply an executor handoff. Queue deduplication identities are not used as that authority. Supported Allow once and Always allow behavior, native command hashes, retry bindings and saved approvals are untouched.

## MCP

An authorized paired MCP scope with **Native policy and decision facts** enabled gains `explain_guard_action`. Its arguments are:

| Argument | Meaning |
| --- | --- |
| `decision_id` | The opaque digest of a recent native decision; a selector, not authority |
| `snapshot_id` | Optional retained snapshot from this connection, to recheck and explain its selection; omitted or null prepares a new brief |

There are no caller-selected app, workspace, source, query, policy, credential or runtime arguments. Rust derives the app/workspace from the authenticated connection, rejects extra fields, and checks the same native policy and source fences before and after SDK work. Generic `explain_guard_context` cannot explain an action snapshot through a weaker path. Another connection cannot use it. Discovery and cached calls remain subject to effective access.

The response's association has `binding: authenticated_native_decision`, `execution_binding: unqualified`, `approval_grant: false` and `data_role: true`. `current` means that the checked native decision and authorized context sources matched when prepared. It is not a current-byte, approval, execution or truth assertion. App executable attestation and actual harness-route qualification remain separate requirements.

## Native ownership and limits

The existing native evaluator publishes the small typed action classification immediately after native origin authentication. The producer performs no SDK call, source/file read or blocking lock acquisition. No origin store or new SDK work is allocated on the default off path. Permission changes and shutdown close the generation.

Only fixed action/operation enums, allowlisted decision/action values, booleans, a decision digest and policy generation become SDK text. Raw commands, prompts, reasons, workspace paths, receipt authenticators, execution intent digests, credentials and approval tokens are excluded. The latter native bindings remain private for replacement checks. Native decision facts do not assert evidence persistence or execution acknowledgement; the independent recorded-receipt stream retains its existing post-persistence ordering.

The native decision store holds at most **64 origins for five minutes**. Missing, evicted, expired, replaced, pre-activation or foreign origins are refused. Native policy generation, digest and runtime identity must match the current admitted snapshot; a changed native policy refuses the earlier origin. Both service generation and workspace/source policy are fenced after work. Unknown outcomes and timeout retain existing native supervisor behavior.

There is one action view and one retained action context per source scope. It includes only authorized sources. The ordinary view excludes action documents. Replacing an action source discards generic contexts invalidated by its graph change. Retained contexts remain bounded by eight per scope overall. Withdrawal, refresh, revoke, clear and generation shutdown invalidate relevant contexts; clear also forgets native-origin and pending optional receipt data and removes paired sessions. Subsequent native events may collect new metadata while assistance stays enabled, but source and connection access require new explicit grants.

Prepared observations also appear in explicitly loaded [Evidence history](history-and-repair.md), independently of the current review context. This path supplements the existing native review reason and selected documents. Exact queue/action associations, qualified executable-byte handoff, persistence, broker sharing, app-route acceptance and measured system benefit remain work in the [full execution goal](EXECUTION_GOAL.md).
