"""The extension-control schema check, read by the native store.

The resident answers whether the authority schema is there and carries a
marker this release knows, using the same marker test its writer ops apply.
Only a store that has lost the schema tables or the marker row opens a
connection here, to create them before the read the way store
initialization does.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

from .runtime.extension_control_authority import ExtensionControlAuthorityError
from .store_extension_control_authority_schema import ensure_extension_control_authority_schema

_METHOD: Final = "extension_control_schema_state"
_INCOMPATIBLE: Final = "unsupported or invalid extension control schema"


def extension_control_schema_compatible(store: Any, *, require_compatible: bool = True) -> bool:
    """``require_compatible_extension_control_schema`` through the native store.

    Answers whether the stored marker is one this release reads. An unknown
    marker raises when ``require_compatible`` is set and answers ``False``
    otherwise.
    """

    answer = store._native_store_call(_METHOD, {})
    state = answer.get("state") if isinstance(answer, dict) and set(answer) == {"state"} else None
    if state == "missing":
        with store._connect() as connection:
            return ensure_extension_control_authority_schema(connection, require_compatible=require_compatible)
    if state == "compatible":
        return True
    if state != "incompatible":
        raise sqlite3.DatabaseError(f"native {_METHOD} returned no answer")
    if require_compatible:
        raise ExtensionControlAuthorityError(_INCOMPATIBLE)
    return False
