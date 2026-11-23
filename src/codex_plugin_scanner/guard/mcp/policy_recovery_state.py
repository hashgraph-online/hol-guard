"""Durable denial metadata for policy requests imported through recovery.

This never authorizes a source or provider action. Native source/approval owners
remain authoritative. The resident records the marker in the recovery's own
transaction (`recover_business_policy_source`); this module only reads it.
"""


def request_recovery_recorded(store, request_id):
    with store._connect() as connection:
        return (
            connection.execute("select 1 from sync_state where state_key = ?", (_key(request_id),)).fetchone()
            is not None
        )


def _key(request_id):
    return "business_policy_request_recovered_v1/" + request_id
