"""Compatibility facade for the append-only Guard Review event outbox."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .store_review_event_outbox import StoreReviewEventOutboxMixin
from .store_review_event_outbox_binding import bind_review_events_for_request
from .store_review_event_outbox_binding import live_request_oauth_subject_hash as _subject_hash
from .store_review_event_outbox_schema import ensure_review_event_outbox_schema
from .store_review_event_outbox_writes import requeue_pending_request_events

StoreLiveRequestOutboxMixin = StoreReviewEventOutboxMixin
bind_live_request_outbox_for_request = bind_review_events_for_request
live_request_oauth_subject_hash = _subject_hash
_requeue_pending_live_requests = requeue_pending_request_events


def ensure_live_request_outbox_schema(connection: sqlite3.Connection) -> None:
    ensure_review_event_outbox_schema(connection, datetime.now(timezone.utc).isoformat())


def seed_live_request_outbox(connection: sqlite3.Connection, now: str) -> None:
    del connection, now
