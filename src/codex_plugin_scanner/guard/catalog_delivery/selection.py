"""Validate advisory pointers independently of publisher authentication.

The runtime owns the selector contract. A selector names a root; it never
authenticates one.
"""

from __future__ import annotations

import re

from .transport_native import decide

SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
BRANCH = "extension-distribution-current"
FILE = "extension-distribution-current.json"


def validate(value):
    decide("selector", invalid="delivery selector contract invalid", value=value)
    return value


def root_tag(source, publication):
    return decide(
        "root_tag", invalid="release source or publication identity invalid", source=source, publication=publication
    )["tag"]
