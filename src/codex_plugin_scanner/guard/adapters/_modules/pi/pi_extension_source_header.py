"""Active Pi extension source header variant."""

from __future__ import annotations

import json

from ...pi_extension_runtime_ownership import PiExtensionRuntimeOwnership
from .pi_extension_content_source import CONTENT_REVIEW_HELPERS_SOURCE
from .pi_extension_native_hook import native_hook_runtime_source
from .pi_extension_source_header_shared_v1 import make_source_header_builder_v1

_build_shared_source_header = make_source_header_builder_v1(
    content_review_helpers_source=CONTENT_REVIEW_HELPERS_SOURCE,
    structured_constants_source=(
        "// Python JSON responses can escape one astral character as two Unicode escapes.\n"
        "const GUARD_MAX_SERIALIZED_RESPONSE_CHARS =\n"
        "  12 * GUARD_TEXT_LIMIT_CHARS + GUARD_MAX_SERIALIZED_PAYLOAD_CHARS;\n"
        "const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;\n"
        "const GUARD_STRUCTURED_MAX_DEPTH = 8;\n"
        "const GUARD_STRUCTURED_MAX_NODES = 128;\n"
        "const GUARD_STRUCTURED_MAX_FIELDS = 64;\n"
    ),
    structured_response_fields_source=(
        "  structured_content_mediation?: StructuredContentMediation;\n"
        "};\n"
        "type StructuredContentMediation = {\n"
        '  schema: "guard-structured-content-mediation.v1";\n'
        '  action: "forward" | "withhold";\n'
        "  reason_code: string;\n"
        "  native_decision_id?: string;\n"
        "  content_sha256?: string;\n"
    ),
)


def build_extension_source_header(
    *, guard_home_json: str, runtime: PiExtensionRuntimeOwnership, **fields: object
) -> str:
    # The frozen shared header has no native runtime; only current extensions
    # name the runtime that answers their hooks.
    return (
        _build_shared_source_header(guard_home_json=guard_home_json, runtime=runtime, **fields)
        + native_hook_runtime_source(guard_home_json)
        + f"const GUARD_CONTAINED_SINK_COMMAND: string[] = {json.dumps(list(runtime.contained_sink_command))};\n"
        + f"const GUARD_CONTAINED_REQUEST_ROOT = {json.dumps(runtime.contained_request_root)};\n"
    )
