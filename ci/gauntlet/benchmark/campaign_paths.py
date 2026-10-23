"""Versioned retained-attempt paths with bounded Unix transport headroom."""

from __future__ import annotations

import os
from pathlib import Path

from .contracts import digest

LEGACY = "gauntlet-local-campaign.v1"
COMPACT = "gauntlet-local-campaign.v2"


def validate_layout(config):
    schema = config.get("schema")
    if schema == LEGACY and "attempt_layout" not in config:
        return "legacy-v1"
    if schema == COMPACT and config.get("attempt_layout") == "compact-v1":
        return "compact-v1"
    raise ValueError("explicit supported local campaign path layout required")


def _component(episode_id, attempt):
    return "e" + digest({"episode_id": episode_id})[:16] + "." + str(attempt)


def configure_layout(config, layout):
    if layout == "legacy-v1":
        return
    if layout != "compact-v1":
        raise ValueError("unknown local campaign attempt layout")
    names = [
        _component(cell["id"], attempt)
        for cell in config["cells"]
        for attempt in range(config["campaign"]["budgets"]["max_retries"] + 1)
    ]
    if len(names) != len(set(names)):
        raise ValueError("compact attempt identity collision; no execution permitted")
    config.update(schema=COMPACT, attempt_layout="compact-v1")


def attempt_directory(config):
    return "a" if validate_layout(config) == "compact-v1" else "attempts"


def attempt_path(root, config, episode_id, attempt):
    if type(attempt) is not int or not 0 <= attempt <= config["campaign"]["budgets"]["max_retries"]:
        raise ValueError("attempt index differs from frozen retry bounds")
    if episode_id not in {cell["id"] for cell in config["cells"]}:
        raise ValueError("attempt is outside frozen selection")
    compact = validate_layout(config) == "compact-v1"
    name = _component(episode_id, attempt) if compact else f"{episode_id}.attempt-{attempt}"
    return Path(root) / attempt_directory(config) / name


def validate_ci_state_root(root):
    # With compact components, this leaves room for the longest approval phase,
    # frontend family name, model bridge and required peer-authenticated sockets.
    if len(os.fsencode(root)) > 27:
        raise ValueError(
            "compact CI state root exceeds 27 bytes; use a fresh short private root such as /opt/hg-001"
        )


def validate_private_cell_state_root(root):
    """Preserve the executor's literal provider-mount location contract.

    Product task mounts permit synthetic provider destinations only under /home
    or /opt (product_cell_task_mounts.validate). Check the future backing path
    before creating state; ordinary ownership/ancestry checks still apply.
    """
    root = Path(root)
    if not root.is_absolute() or len(root.parts) < 3 or root.parts[1] not in {'home', 'opt'}:
        raise ValueError('private-cell provider backing paths require state below /home or /opt')
