# Local business review summary

The resident capability `native-local-business-review-summary-v1` exposes a
finite `workspace_review_local_summary` operation. Its request accepts only a
request ID; the caller cannot supply facts, paths, account identity or policy.
Use the existing authenticated resident transport and canonical JSON framing.

The operation loads the existing private workspace-review snapshot and checks
current policy before and after loading. Native origin authentication, frozen-input digest,
canonical encoding and current policy checks remain in the existing loader.
The response schema is `guard-native-local-business-review-summary.v1`.

The response contains service and operation, audience/inspection states,
counts, sensitivity labels and snapshot bindings. It excludes mail bodies,
subjects, attachment bytes, recipient addresses/domains, account/tenant
identifiers and resource details. This separate local response does not extend
the strict Cloud-upload context or authorize a new Cloud projection.

Snapshot integrity does not establish current provider identity, account lease
validity or credential custody. `account_currentness` is `not_asserted` and
`execution_state` is `not_checked`. A pending review is not proof that an action
was never dispatched; approval is not proof of a provider outcome. This reader
does not consume a decision, reserve an attempt or return an execution grant.

Older runtimes do not advertise this capability. The caller must treat an
unsupported operation, missing business snapshot, changed input or policy,
and invalid origin as unavailable summary data. This read does not occupy the
exclusive authority transition lock used for decision and enrollment mutations.

The local UI consumer, verified account presentation, private content preview
and business-worker enrollment remain separate work. This capability alone
does not qualify a business journey or any assistant mode.
