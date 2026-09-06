"""Source adapters feed one normalized contract; discovery never executes targets."""

from __future__ import annotations

from pathlib import Path

from .errors import BuilderError
from .io import parse_json, read_bytes, sha256
from .models import Discovery, Metadata, load_discovery, make_discovery, validate_metadata
from .source_cli import cli_surface, help_surface
from .source_click import click_surface
from .source_mcp import mcp_surface
from .source_oclif import oclif_surface


def discover(
    adapter: str,
    source: Path,
    metadata: Metadata | None = None,
    *,
    topic_separator: str | None = None,
) -> Discovery:
    if adapter == "snapshot":
        if metadata is not None or topic_separator is not None:
            raise BuilderError("snapshot_override", "Snapshot replay does not accept identity or adapter overrides.")
        return load_discovery(parse_json(read_bytes(source)))
    if metadata is None:
        raise BuilderError("missing_metadata", "Source discovery requires explicit publisher and target metadata.")
    validate_metadata(metadata)
    if topic_separator is not None and adapter != "oclif":
        raise BuilderError("adapter_option", "A topic separator applies only to oclif manifest input.")
    content = read_bytes(source)
    if adapter == "help":
        operations, limitations = help_surface(content)
    elif adapter == "cli":
        operations, limitations = cli_surface(parse_json(content))
    elif adapter == "click":
        operations, limitations = click_surface(parse_json(content))
    elif adapter == "oclif":
        operations, limitations = oclif_surface(parse_json(content), topic_separator=topic_separator or "colon")
    elif adapter == "mcp":
        operations, limitations = mcp_surface(parse_json(content))
    else:
        raise BuilderError("unknown_adapter", "Unsupported offline source adapter.")
    common = ("metadata-is-not-semantics",)
    if metadata.kind == "cli":
        common += ("unknown-cli-operations-review",)
    return make_discovery(metadata, adapter, sha256(content), operations, (*common, *limitations))
