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


def local_cli_rules_exist(connection: sqlite3.Connection, *, blocks_only: bool) -> bool:
    """Whether a device grant or per-command state exists; only blocks if asked."""

    if blocks_only:
        query = (
            "select exists(select 1 from local_cli_grant where state = 'blocked')"
            " or exists(select 1 from local_cli_command_grant where state = 'block')"
        )
    else:
        query = "select exists(select 1 from local_cli_grant) or exists(select 1 from local_cli_command_grant)"
    row = connection.execute(query).fetchone()
    return bool(row and row[0])
