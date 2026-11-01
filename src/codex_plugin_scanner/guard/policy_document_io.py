"""Trusted policy file I/O and backwards-compatible policy adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Final, final

from .policy_document import GuardPolicyDocument
from .policy_document_compile import (
    build_policy_document_from_rows,
    compile_policy_bundle_document,
    compile_policy_document,
)
from .policy_document_diff import diff_policy_documents
from .policy_document_types import CompiledPolicyRow, PolicyCompilationError, PolicyDocumentDiff
from .policy_document_yaml import (
    MAX_POLICY_BYTES,
    parse_policy_document_yaml,
)

_FEATURE: Final = "native-policy-file-io-v1"
_SCHEMA: Final = "policy-file-io.v1"
_TIMEOUT_SECONDS: Final = 30.0
# One policy file, JSON-escaped, with room for the envelope.
_OUTPUT_LIMIT: Final = 8 * 1024 * 1024
_PARENT_CODES: Final = frozenset(
    {
        "policy_parent_insecure_mode",
        "policy_parent_not_directory",
        "policy_parent_not_owned",
        "policy_parent_unavailable",
    }
)


@final
class PolicyFileTrustError(ValueError):
    """Raised when a policy path cannot be trusted for local I/O."""

    def __init__(self, code: str, path: Path) -> None:
        self.code = code
        self.path = path
        super().__init__(code)


def _policy_file_io(op: str, path: Path, content: str | None = None) -> dict[str, object]:
    """Ask the native runtime (`policy-file-io --stdin`) to read or write one policy file.

    The runtime walks to the file without following a link and refuses a file or
    folder that another user owns or may write, or a file with more than one link.
    """

    from .mdm.runtime_request import runtime_answer

    candidate = path.expanduser().absolute()
    request: dict[str, object] = {"schema": _SCHEMA, "op": op, "path": str(candidate)}
    if content is not None:
        request["content"] = content
    answer = runtime_answer(
        _FEATURE, "policy-file-io", request, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS
    )
    if answer is None:
        raise PolicyFileTrustError("policy_file_io_unavailable", candidate)
    failure = answer.get("failure")
    if failure is not None:
        code = failure if isinstance(failure, str) else "policy_file_io_unavailable"
        raise PolicyFileTrustError(code, candidate.parent if code in _PARENT_CODES else candidate)
    return answer


def read_trusted_policy_text(path: Path) -> str:
    """Read one bounded, owner-only, UTF-8 regular file without following links."""

    text = _policy_file_io("read", path).get("text")
    if not isinstance(text, str):
        raise PolicyFileTrustError("policy_file_io_unavailable", path.expanduser().absolute())
    return text


def write_private_policy_text(path: Path, content: str) -> None:
    """Atomically replace an owner-only policy file inside a private directory."""

    if len(content.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyFileTrustError("policy_output_too_large", path.expanduser().absolute())
    if _policy_file_io("write", path, content).get("written") is not True:
        raise PolicyFileTrustError("policy_file_io_unavailable", path.expanduser().absolute())


def load_trusted_policy_document(path: Path) -> GuardPolicyDocument:
    return parse_policy_document_yaml(read_trusted_policy_text(path))


__all__ = (
    "CompiledPolicyRow",
    "PolicyCompilationError",
    "PolicyDocumentDiff",
    "PolicyFileTrustError",
    "build_policy_document_from_rows",
    "compile_policy_bundle_document",
    "compile_policy_document",
    "diff_policy_documents",
    "load_trusted_policy_document",
    "read_trusted_policy_text",
    "write_private_policy_text",
)
