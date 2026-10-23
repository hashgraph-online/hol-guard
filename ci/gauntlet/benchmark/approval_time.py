"""Versioned approval phase inputs, without predicting a future commit time.

Version one remains readable for recorded deterministic logical-clock tests.
Version two freezes scope before issuance; a controller-signed durable claim
supplies application time after the actual provider transaction commits.
"""
from __future__ import annotations

import copy

PHASE_ARGUMENTS_SCHEMA = 'gauntlet-approval-phase-arguments.v2'


def validate_phase_arguments(arguments: dict) -> str:
    """Accept only the exact historical v1 or current v2 phase interface."""
    if type(arguments) is not dict:
        raise ValueError('frozen approval phase arguments must be an object')
    if set(arguments) == {'provider_args', 'operation_id', 'applied_at'}:
        if type(arguments['applied_at']) is not int or arguments['applied_at'] < 0:
            raise ValueError('logical v1 application time must be a nonnegative integer')
        version = 'v1'
    elif (set(arguments) == {'schema', 'provider_args', 'operation_id'}
          and arguments['schema'] == PHASE_ARGUMENTS_SCHEMA):
        version = 'v2'
    else:
        raise ValueError('frozen approval phase arguments have unknown version or fields')
    if type(arguments['provider_args']) is not dict:
        raise ValueError('frozen provider arguments must be an object')
    if type(arguments['operation_id']) is not str or not arguments['operation_id']:
        raise ValueError('frozen operation ID must be a nonempty string')
    return version


def approval_phase_arguments(provider_args: dict, operation_id: str) -> dict:
    """Freeze exact scope now; never accept an agent-supplied effect timestamp."""
    arguments = {'schema': PHASE_ARGUMENTS_SCHEMA, 'provider_args': copy.deepcopy(provider_args),
                 'operation_id': operation_id}
    validate_phase_arguments(arguments)
    return arguments


def decision_verification_time(arguments: dict, grant: dict) -> int:
    """Time for preliminary historical decision authentication, not effect proof.

The v2 issued_at value is authenticated by verify_decision at the call site.
Actual terminal authorization must separately use the signed durable claim's
applied_at. Authenticating issuance alone does not prove timely application.
"""
    if validate_phase_arguments(arguments) == 'v1':
        return arguments['applied_at']
    issued_at = grant['record']['issued_at']
    if type(issued_at) is not int or issued_at < 0:
        raise ValueError('controller decision issue time is malformed')
    return issued_at
