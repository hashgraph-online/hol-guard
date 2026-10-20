"""Compose the generated Pi content-review helpers."""

from __future__ import annotations

from .pi_extension_content_bounds_source import CONTENT_BOUNDING_HELPERS_SOURCE
from .pi_extension_content_encoding_source import CONTENT_ENCODING_HELPERS_SOURCE
from .pi_extension_content_reference_source import CONTENT_REFERENCE_HELPERS_SOURCE

CONTENT_REVIEW_HELPERS_SOURCE = (
    CONTENT_ENCODING_HELPERS_SOURCE + CONTENT_REFERENCE_HELPERS_SOURCE + CONTENT_BOUNDING_HELPERS_SOURCE
)
