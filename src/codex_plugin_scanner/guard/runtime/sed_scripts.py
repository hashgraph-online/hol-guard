"""Safe sed script classifiers used by Guard runtime checks."""

from __future__ import annotations


def sed_script_is_bounded_print(script: str) -> bool:
    stripped = script.strip()
    if not stripped.endswith("p"):
        return False

    body = stripped[:-1].strip()
    if not body:
        return True
    parts = body.split(",")
    if len(parts) > 2:
        return False
    return all(sed_address_is_bounded(part) for part in parts)


def sed_address_is_bounded(value: str) -> bool:
    address = value.strip()
    if address == "$":
        return True
    return address.isdecimal() and 1 <= len(address) <= 6
