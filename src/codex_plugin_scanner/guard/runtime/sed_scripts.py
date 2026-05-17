"""Safe sed script classifiers used by Guard runtime checks."""

from __future__ import annotations


def sed_script_is_bounded_print(script: str) -> bool:
    stripped = script.strip()
    if not stripped:
        return False

    commands = [part.strip() for part in stripped.split(";")]
    return bool(commands) and all(sed_print_command_is_bounded(command) for command in commands)


def sed_print_command_is_bounded(command: str) -> bool:
    if not command.endswith("p"):
        return False

    body = command[:-1].strip()
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
