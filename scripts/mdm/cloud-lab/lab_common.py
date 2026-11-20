#!/usr/bin/env python3
"""Compatibility facade for the provider-neutral MDM Cloud lab."""

from cloud_control import ContractError
from lab_server import CloudServer
from lab_store import Store
from lab_support import (
    ADMIN,
    ADMIN_HEADER,
    MAX,
    MAX_BODY_BYTES,
    NATIVE,
    NATIVE_CERTIFICATION_GATES,
    atomic,
    decode_json_object,
    http,
    http_request,
    jbytes,
    json_bytes,
    read_json,
)

__all__ = [
    "ADMIN",
    "ADMIN_HEADER",
    "MAX",
    "MAX_BODY_BYTES",
    "NATIVE",
    "NATIVE_CERTIFICATION_GATES",
    "CloudServer",
    "ContractError",
    "Store",
    "atomic",
    "decode_json_object",
    "http",
    "http_request",
    "jbytes",
    "json_bytes",
    "read_json",
]
