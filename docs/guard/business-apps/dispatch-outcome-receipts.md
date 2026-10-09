# Native business dispatch observations

The owned native dispatch result can project
`guard-native-business-dispatch-receipt.v1` through its `receipt()` method.
This is unsigned aggregate metadata from an existing consumed decision and
frozen input. It is not an approval, an executor admission proof, or a token
that can restore a spent handle. The existing pre-dispatch hook decision
receipt keeps its original meaning and identity.

| Field | Meaning |
| --- | --- |
| `decision_binding` | Digest of the exact consumed decision envelope. |
| `input_binding` | Digest of the owned frozen input. No content is included. |
| `attempt` | `api_accepted` means the fixed SDK observed an API acknowledgement; `outcome_unknown` means the provider effect is uncertain. |
| `acknowledgement_binding` | Opaque digest when the API acknowledged the request; null for an unknown outcome. No raw provider identifier is included. |
| `journal` | `recorded` or `unconfirmed`, independently of the transport observation. A failed journal write does not turn a possible effect into a safe refusal. |
| `provider_effect` | Always `not_checked`. API acceptance does not prove delivery, audience visibility or an independently inspected provider effect. |
| `retry_authority` | Always `none`. Neither a receipt nor a missing receipt grants permission to send again. |

The Rust decoder `parse_native_business_dispatch_receipt` accepts original bytes
and caps them at 1,024 bytes before JSON decoding or string allocation. The public
receipt has no generic Deserialize implementation that could skip this bound.
It checks schema/version, lowercase digest shape and
acknowledgement/attempt consistency. Unknown fields and invented confirmed-effect
or retry-authority values are rejected. A parsed receipt remains untrusted
metadata; it must never enter an authorization evaluator as a grant. Consumers
must keep actual admission, provider-oracle evidence and receipt authenticity
separate. Serialization consumers must validate caller-constructed values.

Projection failure leaves the original native transport observation intact.
It cannot be relabeled as a pre-I/O refusal or used to trigger a resend.
Pre-I/O error paths retain their existing errors and private journal behavior;
this receipt is produced only for returned SDK attempt observations.

Portable vectors live in
`contracts/business-policy/dispatch-receipt-v1-fixtures.json`. Native regressions
exercise acknowledgement, uncertain outcome and journal failure alongside
exactly-one-call counters. They use synthetic adapters, not provider accounts.

No resident RPC, worker admission, Cloud ingestion, retry operation or protected
mode is added here. The production worker admission type remains uninhabited.
There is no automatic migration of private attempt records or rewrite of
existing decision receipts. Removing this optional projection leaves the
existing native journal, replay tombstones and dispatch refusal behavior intact.
