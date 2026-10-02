"""Frozen previous Pi extension source header variant."""

from __future__ import annotations

from .pi_extension_previous_content_source import CONTENT_REVIEW_HELPERS_SOURCE
from .pi_extension_source_header_shared_v1 import make_source_header_builder_v1

build_previous_source_header = make_source_header_builder_v1(
    content_review_helpers_source=CONTENT_REVIEW_HELPERS_SOURCE,
    structured_constants_source="",
    structured_response_fields_source="",
)
