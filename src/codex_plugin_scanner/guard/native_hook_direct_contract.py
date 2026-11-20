"""Wire validation for the Rust direct-hook resident operation."""

from __future__ import annotations

from collections.abc import Mapping

DIRECT_RESULT_SCHEMA = "guard-hook-direct-result.v1"


def is_valid_direct_result(decoded: Mapping[str, object]) -> bool:
    """Whether a resident reply is the exact direct-hook answer/defer union."""

    if decoded.get("schema") != DIRECT_RESULT_SCHEMA:
        return False
    if set(decoded) == {"schema", "outcome", "edge"}:
        return decoded.get("outcome") == "answer" and isinstance(decoded.get("edge"), dict)
    return (
        set(decoded) == {"schema", "outcome", "reason"}
        and decoded.get("outcome") == "defer"
        and isinstance(decoded.get("reason"), str)
    )


__all__ = ["DIRECT_RESULT_SCHEMA", "is_valid_direct_result"]
