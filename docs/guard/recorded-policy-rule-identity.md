# Recorded policy rules

When an authenticated canonical rule changes a review decision, the recorded
decision may include three diagnostic fields:

| Field | Recorded value |
| --- | --- |
| `policyId` | The canonical document identifier. |
| `ruleId` | The identifier of the rule that was selected. |
| `policyVersion` | The canonical document revision, written as a decimal string. |

Both identifiers use 1–128 ASCII letters, digits, periods, underscores, colons,
or hyphens, beginning with a letter or digit. The complete triple is retained
with the original review and included in its claim hash. A delivery revision
may differ from the canonical document revision.

Older reviews and decisions without an attributable canonical rule omit the
identifiers. Incomplete or malformed identifiers are omitted together. A
stronger decision or a new approval does not inherit the identity of an input
that it replaced. These fields describe the recorded decision and grant no
permission.

Historical inspection uses the recorded triple and its retained publication.
It must report unavailable evidence when that publication is no longer
available. Looking at the currently edited policy cannot establish what caused
an earlier review.
