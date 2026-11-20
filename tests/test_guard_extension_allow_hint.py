"""The daemon shape-checks an allow hint before it stores or shows one.

The resident computes the hint (``extension_allow_hint_op.rs`` and
``hook_direct_review_hint_op.rs``, whose tests pin which permissions each
command names); this file pins the validator the daemon applies to its answer.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    EXTENSION_ALLOW_HINT_SCHEMA,
    validated_extension_allow_hint,
)


def test_validated_hint_rejects_malformed_values() -> None:
    digest = "a" * 64
    good = {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": ["command.git.permission.add"],
        "rule_ids": ["command.git.add"],
        "extension_ids": ["command.git"],
        "catalog_digest": digest,
    }

    assert validated_extension_allow_hint(good) == {**good, "relied_permission_ids": []}
    relied = {**good, "relied_permission_ids": ["command.git.permission.commit"]}
    assert validated_extension_allow_hint(relied) == relied
    assert validated_extension_allow_hint({**good, "relied_permission_ids": ["rm -rf /"]}) is None
    assert validated_extension_allow_hint({**good, "relied_permission_ids": "command.git"}) is None
    assert validated_extension_allow_hint({**good, "schema": "other"}) is None
    assert validated_extension_allow_hint({**good, "permission_ids": []}) is None
    assert validated_extension_allow_hint({**good, "permission_ids": ["rm -rf /"]}) is None
    assert validated_extension_allow_hint({**good, "catalog_digest": "short"}) is None
    assert validated_extension_allow_hint(None) is None
