"""Transactional outbox for cloud live-request projection."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import json
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from hashlib import sha256

_LIVE_REQUEST_OUTBOX_SEED_KEY = "guard_live_request_outbox_seeded_v1"


def live_request_outbox_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists guard_live_request_outbox (
          sequence integer primary key autoincrement,
          local_request_id text not null,
          changed_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text,
          attempt_count integer not null default 0,
          next_attempt_at text,
          last_error text
        )
        """,
        """
        create index if not exists idx_guard_live_request_outbox_ready
        on guard_live_request_outbox (
          oauth_source,
          oauth_subject_hash,
          workspace_id,
          machine_id,
          machine_installation_id,
          next_attempt_at,
          sequence
        )
        """,
        """
        create index if not exists idx_guard_live_request_outbox_newest_ready
        on guard_live_request_outbox (
          oauth_source,
          oauth_subject_hash,
          workspace_id,
          machine_id,
          machine_installation_id,
          next_attempt_at,
          changed_at desc,
          sequence desc
        )
        """,
        """
        create index if not exists idx_guard_live_request_outbox_request
        on guard_live_request_outbox (local_request_id, oauth_source, sequence)
        """,
        """
        create trigger if not exists guard_approval_oauth_source_immutable
        before update of oauth_source on approval_requests
        when old.oauth_source is not null and new.oauth_source is not old.oauth_source
        begin
          select raise(abort, 'approval OAuth source is immutable');
        end
        """,
        "drop trigger if exists guard_live_request_outbox_after_insert",
        """
        create trigger if not exists guard_live_request_outbox_after_insert
        after insert on approval_requests
        begin
          delete from guard_live_request_outbox
          where local_request_id = new.request_id;
          insert into guard_live_request_outbox (local_request_id, changed_at, oauth_source)
          values (
            new.request_id,
            coalesce(new.last_seen_at, new.created_at),
            new.oauth_source
          );
        end
        """,
        "drop trigger if exists guard_live_request_outbox_after_update",
        """
        create trigger if not exists guard_live_request_outbox_after_update
        after update on approval_requests
        begin
          insert into guard_live_request_outbox (
            local_request_id,
            changed_at,
            oauth_source,
            oauth_subject_hash,
            workspace_id,
            machine_id,
            machine_installation_id,
            attempt_count,
            next_attempt_at,
            last_error
          )
          values (
            new.request_id,
            coalesce(new.resolved_at, new.last_seen_at, new.created_at),
            coalesce((
              select oauth_source
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ), new.oauth_source),
            (
              select oauth_subject_hash
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            (
              select workspace_id
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            (
              select machine_id
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            (
              select machine_installation_id
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            coalesce((
              select attempt_count
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ), 0),
            (
              select next_attempt_at
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            (
              select last_error
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            )
          );
          delete from guard_live_request_outbox
          where local_request_id = new.request_id
            and sequence <> last_insert_rowid();
        end
        """,
        "drop trigger if exists guard_live_request_outbox_before_delete",
    )


def ensure_live_request_outbox_schema(connection: sqlite3.Connection) -> None:
    statements = live_request_outbox_schema_statements()
    connection.execute(statements[0])
    columns = {
        str(row["name"]) for row in connection.execute("pragma table_info(guard_live_request_outbox)").fetchall()
    }
    added_identity_column = False
    if "workspace_id" not in columns:
        connection.execute("alter table guard_live_request_outbox add column workspace_id text")
        added_identity_column = True
    identity_columns = {
        "oauth_source": "text",
        "oauth_subject_hash": "text",
        "machine_id": "text",
        "machine_installation_id": "text",
    }
    for column_name, column_type in identity_columns.items():
        if column_name not in columns:
            connection.execute(f"alter table guard_live_request_outbox add column {column_name} {column_type}")
            added_identity_column = True
    if added_identity_column:
        # Existing rows were stamped by a source-unaware trigger. Their workspace
        # or account binding cannot be trusted until an explicit adoption.
        connection.execute(
            """
            update guard_live_request_outbox
            set oauth_subject_hash = null,
                workspace_id = null,
                machine_id = null,
                machine_installation_id = null
            """
        )
        connection.execute("drop index if exists idx_guard_live_request_outbox_ready")
        connection.execute("drop index if exists idx_guard_live_request_outbox_newest_ready")
        connection.execute("drop index if exists idx_guard_live_request_outbox_request")
    for statement in statements[1:]:
        connection.execute(statement)


def seed_live_request_outbox(connection: sqlite3.Connection, now: str) -> None:
    row = connection.execute(
        "select 1 from sync_state where state_key = ?",
        (_LIVE_REQUEST_OUTBOX_SEED_KEY,),
    ).fetchone()
    if row is not None:
        return
    connection.execute(
        """
        insert into guard_live_request_outbox (local_request_id, changed_at, oauth_source)
        select
          request_id,
          coalesce(resolved_at, last_seen_at, created_at),
          oauth_source
        from approval_requests
        order by coalesce(resolved_at, last_seen_at, created_at), request_id
        """
    )
    connection.execute(
        """
        insert into sync_state (state_key, payload_json, updated_at)
        values (?, '{"seeded":true}', ?)
        """,
        (_LIVE_REQUEST_OUTBOX_SEED_KEY, now),
    )


def _retry_at(now: str, attempt_count: int) -> str:
    try:
        base = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        base = datetime.now(timezone.utc)
    delay_seconds = min(300.0, 0.5 * (2 ** min(attempt_count, 10)))
    return (base + timedelta(seconds=delay_seconds)).isoformat()


def live_request_oauth_subject_hash(grant_id: str | None) -> str | None:
    """Return a non-reversible account binding for an OAuth grant subject."""
    normalized = grant_id.strip() if isinstance(grant_id, str) else ""
    return sha256(normalized.encode("utf-8")).hexdigest() if normalized else None


def _oauth_binding_state_key(source: str) -> str:
    return "oauth_local_credentials" if source == "default" else f"oauth_local_credentials:{source}"


def _live_request_oauth_binding(
    connection: sqlite3.Connection,
    source: str,
) -> dict[str, str] | None:
    row = connection.execute(
        "select payload_json from sync_state where state_key = ?",
        (_oauth_binding_state_key(source),),
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(str(row["payload_json"]))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    subject_hash = live_request_oauth_subject_hash(payload.get("grant_id"))
    workspace_id = payload.get("workspace_id")
    machine_id = payload.get("machine_id")
    device = connection.execute(
        "select installation_id from guard_devices where device_key = 'local-device'"
    ).fetchone()
    machine_installation_id = device["installation_id"] if device is not None else None
    values = (subject_hash, workspace_id, machine_id, machine_installation_id)
    if not all(isinstance(value, str) and value.strip() for value in values):
        return None
    return {
        "oauth_source": source,
        "oauth_subject_hash": str(subject_hash),
        "workspace_id": str(workspace_id).strip(),
        "machine_id": str(machine_id).strip(),
        "machine_installation_id": str(machine_installation_id).strip(),
    }


def bind_live_request_outbox_for_request(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    oauth_source: str,
) -> bool:
    """Bind a newly inserted event to OAuth metadata in its write transaction."""
    binding = _live_request_oauth_binding(connection, oauth_source)
    if binding is None:
        return False
    cursor = connection.execute(
        """
        update guard_live_request_outbox
        set oauth_subject_hash = ?, workspace_id = ?, machine_id = ?, machine_installation_id = ?
        where local_request_id = ?
          and oauth_source = ?
          and oauth_subject_hash is null
          and workspace_id is null
          and machine_id is null
          and machine_installation_id is null
        """,
        (
            binding["oauth_subject_hash"],
            binding["workspace_id"],
            binding["machine_id"],
            binding["machine_installation_id"],
            request_id,
            oauth_source,
        ),
    )
    return bool(cursor.rowcount)


def _normalized_delivery_binding(
    *,
    oauth_subject_hash: str,
    workspace_id: str,
    machine_id: str,
    machine_installation_id: str,
) -> tuple[str, str, str, str]:
    values = (
        oauth_subject_hash.strip(),
        workspace_id.strip(),
        machine_id.strip(),
        machine_installation_id.strip(),
    )
    if not all(values):
        raise ValueError("complete live-request OAuth binding is required")
    return values


class StoreLiveRequestOutboxMixin:
    def get_live_request_oauth_binding(self) -> dict[str, str] | None:
        """Return the complete non-secret binding for this store source."""
        with self._connect() as connection:
            binding = _live_request_oauth_binding(connection, self._guard_source)
        return dict(binding) if binding is not None else None

    def claim_unowned_live_request_outbox(
        self,
        workspace_id: str,
        *,
        oauth_subject_hash: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        subject, workspace, machine, installation = _normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            source = self._guard_source
            explicit_unowned = connection.execute(
                """
                select count(*) as total
                from guard_live_request_outbox
                where oauth_source = ?
                  and oauth_subject_hash is null
                  and workspace_id is null
                  and machine_id is null
                  and machine_installation_id is null
                """,
                (source,),
            ).fetchone()
            claimed = int(explicit_unowned["total"] if explicit_unowned is not None else 0)
            cursor = connection.execute(
                """
                update guard_live_request_outbox
                set oauth_subject_hash = ?, workspace_id = ?, machine_id = ?, machine_installation_id = ?
                where oauth_source = ?
                  and oauth_subject_hash is null
                  and workspace_id is null
                  and machine_id is null
                  and machine_installation_id is null
                """,
                (subject, workspace, machine, installation, source),
            )
            if cursor.rowcount is not None:
                claimed = max(claimed, int(cursor.rowcount))
            return claimed

    def reassign_quarantined_live_request_outbox(
        self,
        *,
        approved_source: str,
        approved_workspace_id: str,
    ) -> int:
        """Explicitly bind legacy ambiguous rows after operator confirmation."""
        if approved_source.strip() != self._guard_source:
            raise ValueError("approved source does not match the active Guard connection source")
        with self._connect() as connection:
            binding = _live_request_oauth_binding(connection, self._guard_source)
            if binding is None:
                raise ValueError("active OAuth source does not have a complete live-request binding")
            if approved_workspace_id.strip() != binding["workspace_id"]:
                raise ValueError("approved workspace does not match the active OAuth workspace")
            connection.execute(
                """
                create temporary table if not exists guard_quarantined_live_request_ids (
                  local_request_id text primary key
                )
                """
            )
            connection.execute("delete from guard_quarantined_live_request_ids")
            connection.execute(
                """
                insert or ignore into guard_quarantined_live_request_ids (local_request_id)
                select request_id
                from approval_requests
                where oauth_source is null
                  and request_id not in (
                    select local_request_id
                    from guard_live_request_outbox
                    where oauth_source is not null
                  )
                union
                select local_request_id from guard_live_request_outbox where oauth_source is null
                """
            )
            row = connection.execute("select count(*) as total from guard_quarantined_live_request_ids").fetchone()
            reassigned = int(row["total"] if row is not None else 0)
            connection.execute(
                """
                update guard_live_request_outbox
                set oauth_source = ?, oauth_subject_hash = ?, workspace_id = ?,
                    machine_id = ?, machine_installation_id = ?
                where local_request_id in (select local_request_id from guard_quarantined_live_request_ids)
                  and oauth_source is null
                """,
                (
                    self._guard_source,
                    binding["oauth_subject_hash"],
                    binding["workspace_id"],
                    binding["machine_id"],
                    binding["machine_installation_id"],
                ),
            )
            connection.execute(
                """
                update approval_requests
                set oauth_source = ?
                where request_id in (select local_request_id from guard_quarantined_live_request_ids)
                  and oauth_source is null
                """,
                (self._guard_source,),
            )
            connection.execute("drop table guard_quarantined_live_request_ids")
            return reassigned

    def list_ready_live_request_outbox(
        self,
        *,
        now: str,
        limit: int,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, object]]:
        """List ready events in explicit newest-first or fairness order."""
        query = """
            select sequence, local_request_id, changed_at, oauth_source, oauth_subject_hash,
                   workspace_id, machine_id, machine_installation_id, attempt_count
            from guard_live_request_outbox
            where oauth_source = ?
              and (next_attempt_at is null or next_attempt_at <= ?)
        """
        parameters: list[object] = [self._guard_source, now]
        delivery_values = (oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
        if any(value is not None for value in delivery_values):
            if not all(isinstance(value, str) for value in delivery_values):
                raise ValueError("complete live-request OAuth binding is required")
            subject, workspace, machine, installation = _normalized_delivery_binding(
                oauth_subject_hash=str(oauth_subject_hash),
                workspace_id=str(workspace_id),
                machine_id=str(machine_id),
                machine_installation_id=str(machine_installation_id),
            )
            query += """
              and oauth_subject_hash = ?
              and workspace_id = ?
              and machine_id = ?
              and machine_installation_id = ?
            """
            parameters.extend((subject, workspace, machine, installation))
        if newest_first:
            query += " order by changed_at desc, sequence desc limit ?"
        else:
            query += " order by sequence asc limit ?"
        parameters.append(max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            {
                "sequence": int(row["sequence"]),
                "local_request_id": str(row["local_request_id"]),
                "changed_at": str(row["changed_at"]),
                "oauth_source": str(row["oauth_source"]),
                "oauth_subject_hash": row["oauth_subject_hash"],
                "workspace_id": row["workspace_id"],
                "machine_id": row["machine_id"],
                "machine_installation_id": row["machine_installation_id"],
                "attempt_count": int(row["attempt_count"]),
            }
            for row in rows
        ]

    def acknowledge_live_request_outbox(
        self,
        sequences: Sequence[int],
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        normalized = tuple(sorted({int(sequence) for sequence in sequences if int(sequence) > 0}))
        if not normalized:
            return 0
        subject, workspace, machine, installation = _normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        placeholders = ",".join("?" for _ in normalized)
        with self._connect() as connection:
            cursor = connection.execute(
                f"""
                delete from guard_live_request_outbox
                where oauth_source = ?
                  and oauth_subject_hash = ?
                  and workspace_id = ?
                  and machine_id = ?
                  and machine_installation_id = ?
                  and sequence in ({placeholders})
                """,
                (self._guard_source, subject, workspace, machine, installation, *normalized),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def retry_live_request_outbox(
        self,
        sequences: Sequence[int],
        *,
        now: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        normalized = tuple(sorted({int(sequence) for sequence in sequences if int(sequence) > 0}))
        if not normalized:
            return 0
        subject, workspace, machine, installation = _normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        placeholders = ",".join("?" for _ in normalized)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                select sequence, attempt_count
                from guard_live_request_outbox
                where oauth_source = ?
                  and oauth_subject_hash = ?
                  and workspace_id = ?
                  and machine_id = ?
                  and machine_installation_id = ?
                  and sequence in ({placeholders})
                """,
                (self._guard_source, subject, workspace, machine, installation, *normalized),
            ).fetchall()
            updated = 0
            for row in rows:
                attempt_count = int(row["attempt_count"]) + 1
                cursor = connection.execute(
                    """
                    update guard_live_request_outbox
                    set attempt_count = ?, next_attempt_at = ?, last_error = ?
                    where oauth_source = ?
                      and oauth_subject_hash = ?
                      and workspace_id = ?
                      and machine_id = ?
                      and machine_installation_id = ?
                      and sequence = ?
                    """,
                    (
                        attempt_count,
                        _retry_at(now, attempt_count),
                        error[:512],
                        self._guard_source,
                        subject,
                        workspace,
                        machine,
                        installation,
                        int(row["sequence"]),
                    ),
                )
                updated += int(cursor.rowcount if cursor.rowcount is not None else 0)
            return updated

    def live_request_outbox_status(
        self,
        *,
        now: str,
        workspace_id: str | None = None,
        oauth_subject_hash: str | None = None,
        machine_id: str | None = None,
        machine_installation_id: str | None = None,
    ) -> dict[str, object]:
        query = """
            select count(*) as depth,
                   min(changed_at) as oldest_changed_at,
                   max(attempt_count) as max_attempt_count,
                   max(last_error) as last_error
            from guard_live_request_outbox
            where oauth_source = ?
        """
        parameters: list[object] = [self._guard_source]
        provided_identity = (oauth_subject_hash, machine_id, machine_installation_id)
        complete_binding: tuple[str, str, str, str] | None = None
        if any(value is not None for value in provided_identity):
            if workspace_id is None or not all(isinstance(value, str) for value in provided_identity):
                raise ValueError("complete live-request OAuth binding is required")
            complete_binding = _normalized_delivery_binding(
                oauth_subject_hash=str(oauth_subject_hash),
                workspace_id=workspace_id,
                machine_id=str(machine_id),
                machine_installation_id=str(machine_installation_id),
            )
            query += """
              and oauth_subject_hash = ?
              and workspace_id = ?
              and machine_id = ?
              and machine_installation_id = ?
            """
            parameters.extend(complete_binding)
        elif workspace_id is not None:
            query += " and workspace_id = ?"
            parameters.append(workspace_id)
        with self._connect() as connection:
            row = connection.execute(query, parameters).fetchone()
            diagnostic_row = connection.execute(
                """
                select
                  sum(case
                    when oauth_source = ?
                      and oauth_subject_hash is null
                      and workspace_id is null
                      and machine_id is null
                      and machine_installation_id is null
                    then 1 else 0
                  end) as unbound_depth,
                  sum(case
                    when ? is not null
                      and oauth_source = ?
                      and workspace_id is not null
                      and workspace_id <> ?
                    then 1
                    else 0
                  end) as other_workspace_depth,
                  sum(case
                    when ? is not null
                      and oauth_source = ?
                      and workspace_id = ?
                      and (
                        oauth_subject_hash is not ?
                        or machine_id is not ?
                        or machine_installation_id is not ?
                      )
                    then 1
                    else 0
                  end) as identity_mismatch_depth,
                  sum(case when oauth_source is null then 1 else 0 end) as legacy_unbound_depth
                from guard_live_request_outbox
                """,
                (
                    self._guard_source,
                    workspace_id,
                    self._guard_source,
                    workspace_id,
                    complete_binding[0] if complete_binding is not None else None,
                    self._guard_source,
                    workspace_id,
                    complete_binding[0] if complete_binding is not None else None,
                    complete_binding[2] if complete_binding is not None else None,
                    complete_binding[3] if complete_binding is not None else None,
                ),
            ).fetchone()
        unbound_depth = int(diagnostic_row["unbound_depth"] or 0) if diagnostic_row is not None else 0
        other_workspace_depth = int(diagnostic_row["other_workspace_depth"] or 0) if diagnostic_row is not None else 0
        legacy_unbound_depth = int(diagnostic_row["legacy_unbound_depth"] or 0) if diagnostic_row is not None else 0
        identity_mismatch_depth = (
            int(diagnostic_row["identity_mismatch_depth"] or 0) if diagnostic_row is not None else 0
        )
        if legacy_unbound_depth:
            binding_state = "legacy_ambiguous"
            binding_hint = "Legacy live-request events need one unambiguous connection before sync."
        elif identity_mismatch_depth:
            binding_state = "identity_mismatch"
            binding_hint = "Some events belong to different OAuth or machine identity metadata."
        elif other_workspace_depth:
            binding_state = "workspace_mismatch"
            binding_hint = "Some events remain bound to a previous workspace and were not reassigned."
        elif unbound_depth:
            binding_state = "awaiting_workspace_claim"
            binding_hint = "Events are waiting for this source to claim its connected workspace."
        else:
            binding_state = "healthy"
            binding_hint = None
        return {
            "oauth_source": self._guard_source,
            "oauth_subject_hash": complete_binding[0] if complete_binding is not None else None,
            "binding_state": binding_state,
            "binding_hint": binding_hint,
            "depth": int(row["depth"] if row is not None else 0),
            "oldest_changed_at": row["oldest_changed_at"] if row is not None else None,
            "max_attempt_count": int(row["max_attempt_count"] or 0) if row is not None else 0,
            "last_error": row["last_error"] if row is not None else None,
            "unbound_depth": unbound_depth,
            "other_workspace_depth": other_workspace_depth,
            "identity_mismatch_depth": identity_mismatch_depth,
            "legacy_unbound_depth": legacy_unbound_depth,
            "checked_at": now,
        }
