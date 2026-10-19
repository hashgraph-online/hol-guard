"""Exact business values across explicitly supported public string encodings.

No tolerance, rounding, coercion of JSON numbers, or candidate execution occurs.
Only designated amount and UTC timestamp fields have representation equivalence.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from decimal import Decimal

DECIMAL_FIELDS = frozenset({'annual_price', 'calculated_total', 'amount'})
UTC_FIELDS = frozenset({'start', 'end', 'sla_due'})
_DECIMAL = re.compile(r'[+-]?[0-9]+(?:\.[0-9]+)?')
_UTC = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'
                  r'(?:\.[0-9]{1,6})?(?:Z|\+00:00)')


def scalar_matches(field: str, actual, expected) -> bool:
    """Fail closed on malformed strings and precision our parser cannot preserve."""
    if type(actual) is not str or type(expected) is not str:
        return False
    if field in DECIMAL_FIELDS:
        if any(len(value) > 128 or _DECIMAL.fullmatch(value) is None
               for value in (actual, expected)):
            return False
        return Decimal(actual) == Decimal(expected)
    if field in UTC_FIELDS:
        if any(_UTC.fullmatch(value) is None for value in (actual, expected)):
            return False
        try:
            left, right = (datetime.fromisoformat(value.replace('Z', '+00:00'))
                           for value in (actual, expected))
        except ValueError:
            return False
        return left.utcoffset() == right.utcoffset() == timedelta(0) and left == right
    raise ValueError('representation comparison requires a declared scalar field')
