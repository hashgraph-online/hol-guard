"""Shared readiness condition for Cloud Review upload and decision workers."""

from __future__ import annotations

from collections.abc import Mapping


def cloud_review_workers_ready(worker: Mapping[str, object]) -> bool:
    return worker.get("running") is True and worker.get("sync_running") is True
