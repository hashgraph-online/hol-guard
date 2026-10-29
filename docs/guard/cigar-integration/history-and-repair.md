# Context history and repair

Evidence offers explicitly loaded prepared context history, both across authorized workspace/app grants and within an action detail carrying a native decision selector. Loading history does not compile context or activate the SDK. A receipt selector filters existing historical observations; it is not execution authority.

## What is retained

Rust retains only previously validated briefs, their citations, cited file revisions, preparation time, SDK/worker identity and optional native decision association. Queries and raw SDK traces are not retained. Each grant holds at most eight entries and 512 KiB of encoded payload; an entry larger than 256 KiB is omitted. Limits can omit observations without failing context preparation. Identical snapshot/association observations replace their earlier copy. Counts describe encoded history payload, not process memory.

History lives in memory and expires under the configured retention period. Refreshing source contents invalidates current contexts but preserves historical copies. Withdrawal, effective policy revocation, grant revocation, clear and runtime shutdown remove relevant history. Recovered or restarted runtimes restore no prepared history, source grants or app connections. Optional [saved evidence](private-persistence.md) retains a separate bounded SDK evidence store; it does not persist these historical briefs.

Preparation does not confirm delivery, approval, execution, source truth or current policy. A stored native association describes the recorded evaluation and remains explicitly unqualified for execution. No history operation changes Guard approval choices or durable evidence acknowledgements.

## Disclosure and comparisons

History lists expose bounded metadata before any excerpt is opened. Opening an entry requires an active, currently permitted app/workspace grant. Rust checks effective policy and safely reads the cited paths before and after disclosure preparation. Missing grant membership refuses the request. An unsafe or unreadable current source withholds the entire retained brief. A readable changed source permits the historical brief with an explicit changed-source state; it never makes the old context current.

The screen marks source checks as observations made when opened. A user can compare two opened historical snapshots and inspect their citations and revision digests. Generation/access polling removes disclosed entries when permission or retention changes; metadata polling does not renew the native idle lifetime. React renders excerpts as text. No arbitrary file links or SDK HTML are rendered.

The native request shapes are `history {scope_id, decision_id?}` and `history_detail {scope_id, history_id}` on the existing authenticated read route. The native service derives file access and scope state. The dashboard validates the history schema, scope identity, citations, associations, bounds and historical/current flags before displaying text.

## Data & repair

Settings → Data & repair contains **Context data and repair**. Its native summary reports active grants, selected files, current contexts, history entries, encoded history bytes and app connections without paths or excerpts. Actions are independent:

| Action | Effect |
| --- | --- |
| Clear context history | Forgets historical briefs; preserves current contexts, source grants and app connections |
| Remove saved evidence | Ends current context access and removes Guard-owned saved stores, including inactive stores; does not change the enable preference |
| Clear all context data | Closes graphs and forgets contexts, native context origins, source grants and app connections; fresh grants are required |
| Recheck context runtime | Ends the current generation and verifies the enrolled runtime; an enabled preference may start a fresh generation |
| Turn off context assistance | Saves opt-out and stops the optional runtime; the parent settings state receives the saved preference |
| Export context diagnostics | Downloads an explicitly allowlisted local JSON report; performs no external send |

Destructive context actions have a confirmation describing their precise scope. Guard approvals and durable Guard receipts remain unchanged. The read route cannot issue `forget_history` or `forget_saved`; those mutations require the authenticated access route. Metadata inspection, historical clearing and saved-data repair remain available while assistance is off or its configuration cannot activate a runtime. These repair operations do not probe or start the SDK. Recheck and off retain the existing native availability and cancellation rules.

Diagnostics include readiness, versions, fingerprints, settings mode and counters. They omit source text, queries, workspace/executable paths, runtime selectors, credentials, receipt authenticators and approval tokens. Unknown diagnostic/restriction strings are redacted. Exported status is labelled as the last successful refresh, rather than a live system assertion.

## Qualification

The native actual-worker test uses the independently selected final CPython 3.14.7/CIGAR 0.14.1 candidate. It checks historical retention, metadata privacy, changed/unsafe source handling, refresh, read-only mutation refusal, separate forget/clear behavior, withdrawal and opt-out. Native bounds/deduplication/expiry tests and frontend projection/redaction/lazy-disclosure checks supplement it. [Development evidence](evidence/history-development-verification.json) records that scope.

[Installed browser evidence](evidence/history-installed-browser-verification.json) qualifies the immutable `2a9d72db` local macOS arm64 package with locked Guard CPython 3.12.13/MCP 1.30.0 and the independently qualified CIGAR runtime. The actual browser/MCP flow passes in 40.486 seconds (60.144 including setup), with no SDK/daemon mocks. It covers native-derived receipt history, cited changed/unsafe source behavior, historical comparison, diagnostic redaction, separate history/data clearing, cached refusal, opt-out and restart without restored grants. Both existing review approval choices remain enabled. Forty-nine backend regressions pass on the first history package with unchanged native/context transport code. Exact report/artifact/test hashes and two failed attempts remain in the evidence.

Receipt workspace locators may be privacy-redacted and are display metadata. History therefore selects from authenticated native grants and filters their recorded native decision associations. CIGAR may select only mandatory facts when a document is unrelated to the action query; authorization does not guarantee selection. The browser fixture explicitly proves that its relevant guidance was cited before asserting historical file states. Its native-derived Evidence fixture records evaluation only and does not acknowledge execution.

Later sharing and private persistence checkpoints are recorded separately in the [execution log](EXECUTION_LOG.md). Exact native action/current-byte handoff, real harness-route qualification, Desktop/other platforms and measured hook SLO/all-worker RSS/useful reuse remain in the [full execution goal](EXECUTION_GOAL.md).
