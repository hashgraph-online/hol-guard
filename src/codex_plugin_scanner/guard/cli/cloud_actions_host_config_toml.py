"""TOML edits for the Cloud actions settings entry, keeping comments and layout.

Only the named entry changes; cloud_actions_host_config checks the result reads
back the same apart from it before anything is written.
"""

from __future__ import annotations

from collections.abc import Mapping


class UnreadableSettingsError(Exception):
    pass


def render_toml_edit(table: str, server_name: str, text: str, fields: Mapping[str, object]) -> str:
    """`text` with the `server_name` entry under `table` set to `fields`, all else kept."""

    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    try:
        document = tomlkit.parse(text)
        servers = document.get(table)
        if servers is None:
            servers = tomlkit.table(is_super_table=True)
            document[table] = servers
        existing = servers.get(server_name)
        if existing is not None:
            for key in [key for key in existing if key not in fields]:
                del existing[key]
            for key, value in fields.items():
                existing[key] = value
        else:
            entry = tomlkit.table()
            for key, value in fields.items():
                entry[key] = value
            entry.add(tomlkit.nl())
            servers[server_name] = entry
        rendered = tomlkit.dumps(document)
        if rendered.endswith("\n\n") and not text.endswith("\n\n"):
            rendered = rendered.rstrip("\n") + "\n"
        return rendered
    except (TOMLKitError, TypeError, ValueError, AttributeError):
        raise UnreadableSettingsError(
            "Guard could not edit the settings file without changing other settings."
        ) from None


def render_toml_removal(table: str, server_name: str, text: str, *, drop_empty_table: bool) -> str:
    """`text` without the `server_name` entry under `table`, all else kept."""

    import tomlkit
    from tomlkit.exceptions import TOMLKitError

    try:
        document = tomlkit.parse(text)
        servers = document[table]
        del servers[server_name]
        if not servers and drop_empty_table:
            del document[table]
        rendered = tomlkit.dumps(document)
        if rendered.endswith("\n\n") and not text.endswith("\n\n"):
            rendered = rendered.rstrip("\n") + "\n"
        return rendered
    except (TOMLKitError, TypeError, ValueError, AttributeError, KeyError):
        raise UnreadableSettingsError(
            "Guard could not edit the settings file without changing other settings."
        ) from None
