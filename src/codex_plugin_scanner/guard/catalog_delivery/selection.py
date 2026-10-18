"""Validate advisory pointers independently of publisher authentication."""

from __future__ import annotations

import re

PUBLICATION = re.compile(r"[0-9]{1,20}\.[0-9]{1,10}")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
BRANCH = "extension-distribution-current"
FILE = "extension-distribution-current.json"


def validate(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "source_sha", "publication_id", "root_sha256"}
        or value["schema"] != "guard.extension-distribution-selector.v2"
    ):
        raise ValueError("delivery selector contract invalid")
    for key, pattern in (("source_sha", SHA), ("publication_id", PUBLICATION), ("root_sha256", DIGEST)):
        if not isinstance(value[key], str) or pattern.fullmatch(value[key]) is None:
            raise ValueError("delivery selector identity invalid")
    if tuple(map(int, value["publication_id"].split("."))) == (0, 0):
        raise ValueError("local publication cannot become selected")
    return value


def root_tag(source, publication):
    if (
        not isinstance(source, str)
        or SHA.fullmatch(source) is None
        or not isinstance(publication, str)
        or PUBLICATION.fullmatch(publication) is None
    ):
        raise ValueError("release source or publication identity invalid")
    return f"extension-distribution-{source}-{publication}"
