"""Policy inspection uses authenticated complete source, with provenance redaction."""

from dataclasses import replace

from .policy_document import GuardPolicyDocument, PolicyProvenance
from .policy_document_types import PolicyCompilationError


def without_provenance(document: GuardPolicyDocument) -> GuardPolicyDocument:
    rules = []
    for rule in document.rules:
        if rule.match.to_mapping().get("workspaces"):
            raise PolicyCompilationError("sensitive_local_policy_requires_provenance", rule.id)
        rules.append(
            replace(
                rule,
                description=None,
                extensions=(),
                match=replace(
                    rule.match, extensions=tuple(item for item in rule.match.extensions if item[0] == "business")
                ),
                lifetime=replace(rule.lifetime, extensions=()),
                provenance=PolicyProvenance(source="local", created_at="1970-01-01T00:00:00Z"),
            )
        )
    # Schema requires a source enum and timestamp. These are synthetic display
    # placeholders; the CLI explicitly marks provenance as redacted. Do not use
    # the legacy export-redacted value, which is invalid in the portable schema.
    return replace(
        document,
        metadata=replace(document.metadata, name="Business policy", labels=(), extensions=()),
        defaults=replace(document.defaults, extensions=()),
        rules=tuple(rules),
        extensions=(),
        spec_extensions=(),
    )
