"""Row readers for the local CLI tables Python still writes."""

from __future__ import annotations

import sqlite3
from typing import cast


def _row_values(row: object, count: int) -> tuple[object, ...]:
    if isinstance(row, sqlite3.Row):
        values = tuple(cast(object, row[index]) for index in range(count))
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    if isinstance(row, tuple):
        values = cast(tuple[object, ...], row)
        if len(values) != count:
            raise ValueError("invalid local CLI row")
        return values
    raise ValueError("invalid local CLI row")


def _row_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("invalid local CLI row")
    return value
