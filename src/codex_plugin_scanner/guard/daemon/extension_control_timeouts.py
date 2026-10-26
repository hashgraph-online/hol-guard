"""How long the daemon client waits for an extension-control preview or apply.

The daemon answers only after the resident calls it makes have answered, so the
client must outwait every one of them. A client that gives up first reports
failure for an apply the daemon then commits. Each budget below is the sum of
the deadlines of the resident calls the request can make in turn; a normal
request finishes in milliseconds, and the sum only bounds the worst case.

This is a leaf module, imported by the light daemon client, so it names the
budgets it adds up as literals. ``tests/test_guard_extension_control_preview_shape.py``
pins each one to the module that grants it, so raising a resident budget fails
there until the client waits for it.
"""

from __future__ import annotations

from typing import Final

# One authority round trip (``native_extension_control_authority``), and the
# most one authority read makes (``store_extension_control_authority_reads``).
AUTHORITY_ROUND_TIMEOUT_S: Final = 10.0
AUTHORITY_READ_ROUNDS: Final = 6
AUTHORITY_READ_TIMEOUT_S: Final = AUTHORITY_ROUND_TIMEOUT_S * AUTHORITY_READ_ROUNDS
# The layer composition and the semantic preview the resident computes
# (``native_extension_control``).
COMPOSE_TIMEOUT_S: Final = 5.0
SEMANTIC_PREVIEW_TIMEOUT_S: Final = 15.0
# One mutation ask (``native_extension_control``): a preview makes five in turn,
# for the draft's bounds, the nonce binding its prepared candidate, its validation,
# what the prepared candidate lets it change and the digest of its request. An
# apply asks once, for the digest of the request it repeats.
MUTATION_TIMEOUT_S: Final = 5.0
PREVIEW_MUTATION_ASKS: Final = 5
APPLY_MUTATION_ASKS: Final = 1
# The most rounds one commit plans (``store_extension_control_authority_commit``).
COMMIT_PLAN_ROUNDS: Final = 4
# Loopback transport, the daemon's own work and the answer.
TRANSPORT_MARGIN_S: Final = 10.0

# A preview reads the authority twice (the snapshot it builds on, and the read
# that confirms nothing moved), asks the resident to judge the draft, composes
# the proposed layers and previews them.
PREVIEW_REQUEST_TIMEOUT_S: Final = (
    2 * AUTHORITY_READ_TIMEOUT_S
    + PREVIEW_MUTATION_ASKS * MUTATION_TIMEOUT_S
    + COMPOSE_TIMEOUT_S
    + SEMANTIC_PREVIEW_TIMEOUT_S
    + TRANSPORT_MARGIN_S
)
# An apply reads the authority for its snapshot, for the managed binding and for
# the current layers inside the commit, and for the composed view after it; it
# asks the resident for the digest of its request and for the audit projection of
# the change (the semantic preview's budget), and plans up to four commit rounds.
APPLY_AUTHORITY_READS: Final = 4
APPLY_REQUEST_TIMEOUT_S: Final = (
    APPLY_AUTHORITY_READS * AUTHORITY_READ_TIMEOUT_S
    + APPLY_MUTATION_ASKS * MUTATION_TIMEOUT_S
    + SEMANTIC_PREVIEW_TIMEOUT_S
    + COMMIT_PLAN_ROUNDS * AUTHORITY_ROUND_TIMEOUT_S
    + TRANSPORT_MARGIN_S
)
