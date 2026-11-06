# Local business review details

The Core review detail view can show metadata from an existing frozen native
business request: service, operation, audience, counts and sensitivity labels.
It reads `/v1/requests/{request_id}/business-summary` through the existing local
dashboard session. The endpoint is not a hosted dashboard API and responses
use `Cache-Control: no-store`.

The adapter requires the native summary capability. It passes only the request
ID to the authenticated resident transport; it does not stage a new request or
read private snapshot files. Both the adapter and browser reject unknown fields,
mismatched request IDs, invalid counts and unsupported presentation values.
Account-currentness and execution fields must retain their explicit uncertainty.
This validation is a presentation boundary, not a policy evaluator.

The view reports loading and transport/schema failures, with a bounded refresh
action. An available but incompatible runtime, or transport/schema failure,
returns a finite 503 error for summary reads. An unavailable runtime, missing capability or an
explicit native no-summary/missing-request response returns 404
and omits the panel; omission does not establish safety.
The summary does not include message content, exact recipients, attachments,
account identifiers or binding digests in the visible UI. Unknown or unsupported
facts have a visible warning when metadata is available.

The existing review decision controls remain authoritative for review decisions.
This addition creates no execution grant, worker admission, provider operation,
Cloud upload or confirmation of an outcome. Exact private previews, current
account verification and a managed provider journey require further work.

## Native discovery boundary

The resident also exposes `workspace_review_local_queue`, requiring the
`native-local-business-review-queue-v1` capability and an empty request object.
It discovers hints published by the private native business producer, verifies
each against the existing native request loader and returns only the same finite
summary metadata. Each hint binds its selector to the saved request digest and
prepared-input binding; it is not an authority record. Cloud/SQL staging does
not populate this producer index, so accumulated generic history and staged SQL
business rows cannot become native queue candidates. Request ID
prefixes do not confer provenance. Corrupt records, private-file violations,
changed policy, more than 128 business items or a directory exceeding 4096
producer-index entries refuse the result instead of silently truncating it. The operation does
not occupy the exclusive mutation lock, save SQL rows or consume decisions.
It excludes approvals already consumed in the platform-secure replay state,
including consumption followed by expiry before input release. This does not
rewrite the request snapshot, prune replay evidence or authorize a retry.
Policy, selector membership and secure claim state are checked across the read.
The reader does not call authority reconciliation, which can write files.

The Python discovery adapter checks this presentation shape and uses only the
authenticated resident transport. Unavailable native support or a missing policy
returns optional absence; transport, schema or native verification failures
raise a finite read error. Local Core queue routes consume discovery without
persisting SQL rows. Selected native details use the per-ID summary operation;
other harnesses and resolved/nonfinal SQL pages without totals avoid discovery.
Totals requests still discover native pending membership. Existing SQL pagination runs first, followed by
bounded native pages with a membership/filter-bound cursor. Changed membership
requires a queue refresh. A collision with a SQL request ID refuses projection.
Hosted-origin requests retain the existing SQL-only routes.

Native discovery failures return the SQL page with a finite
`native_business_queue_error` field. The local view warns that the saved business
queue is incomplete, including when the SQL page is empty; it does not claim an
empty successful business queue. SQL detail reads remain available without
native discovery. An already-issued native cursor requires a refresh if
discovery fails. Native absence errors accept the resident's actual
`error`/boolean `retryable` envelope, while malformed or extra fields remain
read failures.

Only native display-only projections mount the summary panel. The summary route
refuses SQL-owned IDs without native contact, preventing cross-request details
and inapplicable failures on ordinary or hosted SQL reviews.
Projected native rows are explicitly display-only and show unassessed risk. The incumbent DTO uses its
conservative review action for compatibility; this is not a native policy
decision. The detail view labels the row read-only, explains that review and
execution are not connected, and offers no individual or bulk approval. Backend
decision routes still refuse these IDs because discovery creates no SQL approval
row. A saved pending snapshot is not evidence that its account or dispatch
authority remains current. Each candidate requires real producer-to-installed-
resident-to-Core selection qualification separately from mocked HTTP/browser
checks and provider/agent business-journey qualification.

Display-only details use the saved operation as their title. They omit the
generic stopped-command preview, risk carousel and counterfactual protection
claims: a frozen request is not evidence that Guard stopped a command. The
summary and read-only notice remain the presentation for this incomplete mode.

## Prototype migration and rollback

Producer discovery is an unreleased source migration. No authenticated production
worker route is enabled by this change. Earlier prototype snapshots are not
automatically indexed from the shared staging directory: eligibility must come
from the verified producer rather than SQL or filename inference. A future
worker must prepare a fresh request with current provider evidence when an older
prototype request needs review. Existing snapshot and claim formats remain intact;
the semantic replay digests are unchanged and retain both indexed and legacy
inline consumed evidence.

Rollback preserves private snapshots, frozen inputs, discovery hints and secure
claim state. Do not delete those records or restore an older secure anchor. An
older build may lack the corrected discovery semantics and cannot inherit the
new candidate's qualification. This display-only path remains separate from
provider execution, worker admission and live business support claims.
