"""GuardStore domain mixin extracted from store.py."""

from __future__ import annotations

# ruff: noqa: F403,F405
from .store_base import *


def _set_private_mode_compat(path: Path, mode: int) -> None:
    store_module = sys.modules.get("codex_plugin_scanner.guard.store")
    setter = (
        getattr(store_module, "_set_private_mode", _set_private_mode)
        if store_module is not None
        else _set_private_mode
    )
    setter(path, mode)


class StorePolicyIntegrityAdminMixin:
    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        query = """
            select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
                   action, reason, owner, source, expires_at, updated_at, integrity_version,
                   integrity_generation,
                   payload_hash, payload_mac, integrity_key_id, signed_at
            from policy_decisions
        """
        params: tuple[object, ...] = (_APPROVAL_GATE_POLICY_SOURCE,)
        conditions = ["not (source = ? and expires_at is not null)"]
        if harness is not None:
            conditions.append("harness = ?")
            params = (_APPROVAL_GATE_POLICY_SOURCE, harness)
        query += " where " + " and ".join(conditions)
        query += " order by updated_at desc"
        with self._connect() as connection:
            state = self._refresh_policy_integrity_state(connection, now=_now(), create_key=True)
            key, key_id = self._policy_integrity_secret_material(create=True)
            rows = connection.execute(query, params).fetchall()
            lookup_items = [
                (
                    str(row["harness"]),
                    str(row["artifact_id"]) if row["artifact_id"] is not None else None,
                    str(row["artifact_hash"]) if row["artifact_hash"] is not None else None,
                )
                for row in rows
            ]
            source_context_index = build_policy_source_context_index(connection, items=lookup_items)
            items: list[dict[str, object]] = []
            for row in rows:
                payload = self._policy_decision_dict_from_row(
                    connection,
                    row,
                    source_context_index=source_context_index,
                )
                if not is_remote_policy_source(str(row["source"])):
                    trusted_generation = _mapping_int(state, "generation")
                    integrity_result = self._policy_integrity_result_for_row(
                        row,
                        mode=str(state.get("mode") or "degraded"),
                        key=key,
                        key_id=key_id,
                        trusted_generation=trusted_generation,
                    )
                    payload["integrity_status"] = integrity_result.status
                    payload["integrity_message"] = integrity_result.message
                    payload["integrity_mode"] = state.get("mode")
                    payload["integrity_enforcement"] = state.get("enforcement")
                items.append(payload)
            return items

    def get_policy_decision(self, decision_id: int) -> dict[str, object] | None:
        from .store_policy_decision import get_policy_decision_payload

        return get_policy_decision_payload(
            self,
            decision_id=decision_id,
            approval_gate_policy_source=_APPROVAL_GATE_POLICY_SOURCE,
            now=_now(),
        )

    @staticmethod
    def _policy_decision_dict_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        source_context_index: PolicySourceContextIndex | None = None,
    ) -> dict[str, object]:
        harness = str(row["harness"])
        artifact_id = row["artifact_id"]
        artifact_hash = row["artifact_hash"]
        workspace = row["workspace"]
        if source_context_index is not None:
            source_context = lookup_policy_source_context(
                source_context_index,
                harness=harness,
                artifact_id=str(artifact_id) if artifact_id is not None else None,
                artifact_hash=str(artifact_hash) if artifact_hash is not None else None,
                workspace=str(workspace) if workspace is not None else None,
                reason=str(row["reason"]) if row["reason"] is not None else None,
            )
        else:
            from .store_policy_source_context import find_policy_source_context

            source_context = find_policy_source_context(
                connection,
                harness=harness,
                artifact_id=str(artifact_id) if artifact_id is not None else None,
                artifact_hash=str(artifact_hash) if artifact_hash is not None else None,
                workspace=str(workspace) if workspace is not None else None,
                reason=str(row["reason"]) if row["reason"] is not None else None,
            )
        payload: dict[str, object] = {
            "decision_id": int(row["decision_id"]),
            "harness": harness,
            "scope": str(row["scope"]),
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "workspace": workspace,
            "publisher": row["publisher"],
            "action": str(row["action"]),
            "reason": row["reason"],
            "owner": row["owner"],
            "source": str(row["source"]),
            "expires_at": row["expires_at"],
            "updated_at": str(row["updated_at"]),
        }
        if row["integrity_version"] is not None:
            payload["integrity_version"] = int(row["integrity_version"])
        if row["integrity_generation"] is not None:
            payload["integrity_generation"] = int(row["integrity_generation"])
        if row["integrity_key_id"] is not None:
            payload["integrity_key_id"] = str(row["integrity_key_id"])
        if row["signed_at"] is not None:
            payload["signed_at"] = str(row["signed_at"])
        if source_context is not None:
            payload.update(source_context)
        return payload

    @staticmethod
    def _load_local_policy_rows(
        connection: sqlite3.Connection,
        *,
        harness: str | None = None,
    ) -> list[sqlite3.Row]:
        query = f"""
            select decision_id, harness, scope, artifact_id, artifact_hash, workspace, publisher,
                   action, reason, owner, source, expires_at, updated_at, integrity_version,
                   integrity_generation,
                   payload_hash, payload_mac, integrity_key_id, signed_at
            from policy_decisions
            where source not in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}
        """
        params: tuple[object, ...] = _REMOTE_POLICY_SOURCE_PARAMS
        if harness is not None:
            query += " and harness = ?"
            params = (*params, harness)
        query += " order by updated_at desc"
        return connection.execute(query, params).fetchall()

    def _policy_integrity_scan(
        self,
        connection: sqlite3.Connection,
        *,
        now: str,
        harness: str | None = None,
        create_key: bool,
        include_items: bool,
    ) -> tuple[dict[str, object], dict[str, int], list[dict[str, object]]]:
        state = self._refresh_policy_integrity_state(connection, now=now, create_key=create_key)
        key, key_id = self._policy_integrity_secret_material(create=create_key)
        counts = {status: 0 for status in _POLICY_INTEGRITY_STATUSES}
        items: list[dict[str, object]] = []
        for row in self._load_local_policy_rows(connection, harness=harness):
            trusted_generation = _mapping_int(state, "generation")
            integrity_result = self._policy_integrity_result_for_row(
                row,
                mode=str(state.get("mode") or "degraded"),
                key=key,
                key_id=key_id,
                trusted_generation=trusted_generation,
            )
            counts[integrity_result.status] += 1
            if not include_items:
                continue
            item = self._policy_decision_dict_from_row(connection, row)
            item["integrity_status"] = integrity_result.status
            item["integrity_message"] = integrity_result.message
            item["integrity_mode"] = state.get("mode")
            item["integrity_enforcement"] = state.get("enforcement")
            items.append(item)
        return state, counts, items

    def _backup_policy_database(self, connection: sqlite3.Connection, *, now: str) -> str:
        timestamp = "".join(ch if ch.isalnum() else "-" for ch in now).strip("-") or "backup"
        backup_path = self.guard_home / f"guard.db.pre-integrity-{timestamp}"
        backup_connection = sqlite3.connect(backup_path)
        try:
            connection.backup(backup_connection)
        finally:
            backup_connection.close()
            if backup_path.exists():
                _set_private_mode_compat(backup_path, _GUARD_STORE_PRIVATE_FILE_MODE)
        return str(backup_path)

    def get_policy_integrity_status(self, harness: str | None = None) -> dict[str, object]:
        now = _now()
        with self._connect() as connection:
            state, counts, _items = self._policy_integrity_scan(
                connection,
                now=now,
                harness=harness,
                create_key=False,
                include_items=False,
            )
        return {
            "generated_at": now,
            "harness": harness,
            "backend": state.get("backend"),
            "cutover_complete": state.get("cutover_complete"),
            "mode": state.get("mode"),
            "enforcement": state.get("enforcement"),
            "generation": state.get("generation"),
            "key_id": state.get("key_id"),
            "degraded_reasons": state.get("degraded_reasons", []),
            "trust_status": TrustStatus.from_policy_integrity_state(state).to_dict(),
            "counts": counts,
            "local_rows_scanned": sum(counts.values()),
        }

    def get_cached_policy_trust_status(self) -> dict[str, object]:
        with self._connect() as connection:
            state = self._load_policy_integrity_state(connection) or {}
        return TrustStatus.from_policy_integrity_state(state).to_dict()

    def verify_policy_integrity(self, harness: str | None = None) -> dict[str, object]:
        now = _now()
        with self._connect() as connection:
            state, counts, items = self._policy_integrity_scan(
                connection,
                now=now,
                harness=harness,
                create_key=False,
                include_items=True,
            )
        invalid_items = [item for item in items if item.get("integrity_status") != "valid"]
        return {
            "generated_at": now,
            "harness": harness,
            "backend": state.get("backend"),
            "cutover_complete": state.get("cutover_complete"),
            "mode": state.get("mode"),
            "enforcement": state.get("enforcement"),
            "generation": state.get("generation"),
            "key_id": state.get("key_id"),
            "degraded_reasons": state.get("degraded_reasons", []),
            "trust_status": TrustStatus.from_policy_integrity_state(state).to_dict(),
            "counts": counts,
            "local_rows_scanned": sum(counts.values()),
            "items": invalid_items,
        }

    def ensure_policy_integrity_ready_for_write(
        self,
        *,
        harness: str | None = None,
        approval_gate_grant: ApprovalGateGrant | None = None,
        now: str | None = None,
    ) -> dict[str, object]:
        current_time = now or _now()
        before = self.get_policy_integrity_status(harness=harness)
        if _policy_integrity_ready_for_local_write(before):
            before["autorepair"] = {"attempted": False, "cleared": 0}
            return before

        attempts: list[dict[str, object]] = []
        try:
            setup = self.setup_policy_integrity(harness=harness, now=current_time)
            attempts.append({"step": "setup", "mode": setup.get("mode"), "counts": setup.get("counts")})
            if _policy_integrity_ready_for_local_write(setup):
                setup["autorepair"] = {"attempted": True, "cleared": 0, "steps": attempts}
                self.add_event("policy_integrity.autorepaired", {"steps": attempts}, current_time)
                return setup
        except Exception as error:  # pragma: no cover - exercised through final degraded status assertions.
            attempts.append({"step": "setup", "error": type(error).__name__})

        try:
            repair = self.repair_policy_integrity(
                clear_invalid=True,
                harness=harness,
                approval_gate_grant=approval_gate_grant,
                now=current_time,
            )
            attempts.append(
                {
                    "step": "clear_invalid",
                    "cleared": repair.get("cleared"),
                    "mode": repair.get("mode"),
                    "counts": repair.get("counts"),
                }
            )
            if _policy_integrity_ready_for_local_write(repair):
                repair["autorepair"] = {
                    "attempted": True,
                    "cleared": repair.get("cleared", 0),
                    "steps": attempts,
                }
                self.add_event("policy_integrity.autorepaired", {"steps": attempts}, current_time)
                return repair
        except Exception as error:
            attempts.append({"step": "clear_invalid", "error": type(error).__name__})

        final = self.get_policy_integrity_status(harness=harness)
        final["autorepair"] = {"attempted": True, "cleared": 0, "steps": attempts}
        self.add_event("policy_integrity.autorepair_failed", {"steps": attempts}, current_time)
        return final

    def repair_policy_integrity(
        self,
        *,
        clear_invalid: bool,
        harness: str | None = None,
        approval_gate_grant: ApprovalGateGrant | None = None,
        now: str | None = None,
    ) -> dict[str, object]:
        current_time = now or _now()
        if clear_invalid:
            require_policy_clear(self.guard_home, approval_gate_grant=approval_gate_grant, now=current_time)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            state, _counts, items = self._policy_integrity_scan(
                connection,
                now=current_time,
                harness=harness,
                create_key=True,
                include_items=True,
            )
            invalid_ids = [
                decision_id
                for item in items
                if item.get("integrity_status") != "valid"
                and (decision_id := _int_value(item.get("decision_id"))) is not None
            ]
            cleared = 0
            if clear_invalid and invalid_ids:
                for chunk in _chunks(invalid_ids, _SQLITE_ID_BATCH_SIZE):
                    placeholders = ",".join("?" for _ in chunk)
                    cursor = connection.execute(
                        f"delete from policy_decisions where decision_id in ({placeholders})",
                        tuple(chunk),
                    )
                    cleared += int(cursor.rowcount if cursor.rowcount is not None else 0)
                if cleared > 0 and state.get("mode") == "protected":
                    key, key_id = self._policy_integrity_secret_material(create=True)
                    trusted_state = self._load_policy_integrity_control_state(create=True)
                    if key is not None and key_id is not None and trusted_state is not None:
                        next_control_state = self._advance_policy_integrity_generation(
                            connection,
                            now=current_time,
                            key=key,
                            key_id=key_id,
                            trusted_state=trusted_state,
                        )
                        connection.commit()
            if next_control_state is not None:
                self._finalize_policy_integrity_control_state(next_control_state)
            state, counts, remaining_items = self._policy_integrity_scan(
                connection,
                now=current_time,
                harness=harness,
                create_key=True,
                include_items=True,
            )
        return {
            "generated_at": current_time,
            "harness": harness,
            "backend": state.get("backend"),
            "cutover_complete": state.get("cutover_complete"),
            "mode": state.get("mode"),
            "enforcement": state.get("enforcement"),
            "generation": state.get("generation"),
            "key_id": state.get("key_id"),
            "degraded_reasons": state.get("degraded_reasons", []),
            "trust_status": TrustStatus.from_policy_integrity_state(state).to_dict(),
            "counts": counts,
            "local_rows_scanned": sum(counts.values()),
            "cleared": cleared,
            "clear_invalid": clear_invalid,
            "items": [item for item in remaining_items if item.get("integrity_status") != "valid"],
        }

    def migrate_local_policy_integrity(
        self,
        *,
        preserve_decision_ids: set[int],
        clear_unselected: bool,
        harness: str | None = None,
        approval_gate_grant: ApprovalGateGrant | None = None,
        now: str,
    ) -> dict[str, object]:
        require_policy_clear(self.guard_home, approval_gate_grant=approval_gate_grant, now=now)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            backup_path = self._backup_policy_database(connection, now=now)
            state = self._refresh_policy_integrity_state(
                connection,
                now=now,
                create_key=True,
                allow_cutover_resign=False,
            )
            if state.get("mode") != "protected":
                raise RuntimeError("Guard policy integrity migration requires a protected system keyring backend.")
            key, key_id = self._policy_integrity_secret_material(create=True)
            if key is None or key_id is None:
                raise RuntimeError("Guard could not access the policy integrity key.")
            trusted_state = self._load_policy_integrity_control_state(create=True)
            if trusted_state is None:
                raise RuntimeError("Guard could not access the policy integrity control state.")
            rows = self._load_local_policy_rows(connection, harness=harness)
            preserved = 0
            cleared = 0
            legacy_ids: list[int] = []
            unknown_key_ids: list[int] = []
            rollback_row_ids: list[int] = []
            blocked_preserve_row_ids: list[int] = []
            selected_preserved_ids: set[int] = set()
            for row in rows:
                decision_id = int(row["decision_id"])
                integrity_result = verify_local_policy_row(
                    _row_mapping(row),
                    key=key,
                    key_id=key_id,
                    degraded_mode=False,
                    trusted_generation=_mapping_int(trusted_state, "generation"),
                )
                if integrity_result.status not in _POLICY_INTEGRITY_MIGRATION_ELIGIBLE_STATUSES:
                    if integrity_result.status == "rollback_detected":
                        rollback_row_ids.append(decision_id)
                        if decision_id in preserve_decision_ids:
                            blocked_preserve_row_ids.append(decision_id)
                        elif clear_unselected:
                            cursor = connection.execute(
                                "delete from policy_decisions where decision_id = ?",
                                (decision_id,),
                            )
                            cleared += int(cursor.rowcount if cursor.rowcount is not None else 0)
                    continue
                if integrity_result.status == "missing_integrity":
                    legacy_ids.append(decision_id)
                else:
                    unknown_key_ids.append(decision_id)
                if decision_id in preserve_decision_ids:
                    selected_preserved_ids.add(decision_id)
                    preserved += 1
                elif clear_unselected:
                    cursor = connection.execute(
                        "delete from policy_decisions where decision_id = ?",
                        (decision_id,),
                    )
                    cleared += int(cursor.rowcount if cursor.rowcount is not None else 0)
            next_control_state = self._advance_policy_integrity_generation(
                connection,
                now=now,
                key=key,
                key_id=key_id,
                trusted_state=trusted_state,
                force_sign_decision_ids=selected_preserved_ids,
            )
            connection.commit()
            if next_control_state is not None:
                self._finalize_policy_integrity_control_state(next_control_state)
            final_state, counts, items = self._policy_integrity_scan(
                connection,
                now=now,
                harness=harness,
                create_key=True,
                include_items=True,
            )
        return {
            "generated_at": now,
            "harness": harness,
            "backup_path": backup_path,
            "backend": final_state.get("backend"),
            "cutover_complete": final_state.get("cutover_complete"),
            "mode": final_state.get("mode"),
            "enforcement": final_state.get("enforcement"),
            "generation": final_state.get("generation"),
            "key_id": final_state.get("key_id"),
            "degraded_reasons": final_state.get("degraded_reasons", []),
            "trust_status": TrustStatus.from_policy_integrity_state(final_state).to_dict(),
            "legacy_row_ids": legacy_ids,
            "rollback_row_ids": rollback_row_ids,
            "unknown_key_row_ids": unknown_key_ids,
            "blocked_preserve_row_ids": blocked_preserve_row_ids,
            "preserved": preserved,
            "cleared": cleared,
            "counts": counts,
            "local_rows_scanned": sum(counts.values()),
            "items": [item for item in items if item.get("integrity_status") != "valid"],
        }

    def setup_policy_integrity(
        self,
        *,
        harness: str | None = None,
        now: str,
    ) -> dict[str, object]:
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            state = self._refresh_policy_integrity_state(
                connection,
                now=now,
                create_key=True,
                allow_cutover_resign=False,
            )
            key, key_id = self._policy_integrity_secret_material(create=True)
            trusted_state = self._load_policy_integrity_control_state(create=True)
            if not (
                state.get("mode") == "protected"
                and key is not None
                and key_id is not None
                and trusted_state is not None
            ):
                connection.rollback()
            else:
                local_ids = {
                    int(row["decision_id"]) for row in self._load_local_policy_rows(connection, harness=harness)
                }
                next_control_state = self._advance_policy_integrity_generation(
                    connection,
                    now=now,
                    key=key,
                    key_id=key_id,
                    trusted_state=trusted_state,
                    force_sign_decision_ids=local_ids,
                    harness=harness,
                )
                connection.commit()
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)
        return self.verify_policy_integrity(harness=harness)

    def reset_policy_integrity(
        self,
        *,
        harness: str | None = None,
        now: str,
    ) -> dict[str, object]:
        secret_store = self._policy_integrity_secret_store
        if secret_store is not None:
            secret_store.delete_secret(self._policy_integrity_key_ref)
            secret_store.delete_secret(self._policy_integrity_control_ref)
        self._clear_policy_integrity_cache()
        with self._connect() as connection:
            self._refresh_policy_integrity_state(
                connection,
                now=now,
                create_key=False,
                allow_cutover_resign=False,
            )
        return self.verify_policy_integrity(harness=harness)

    def clear_policy_decisions(
        self,
        harness: str | None = None,
        source: str | None = None,
        *,
        scope: str | None = None,
        artifact_id: str | None = None,
        artifact_hash: str | None = None,
        artifact_id_is_null: bool = False,
        artifact_hash_is_null: bool = False,
        workspace: str | None = None,
        publisher: str | None = None,
        approval_gate_grant: ApprovalGateGrant | None = None,
    ) -> int:
        require_policy_clear(self.guard_home, approval_gate_grant=approval_gate_grant)
        current_time = _now()
        conditions: list[str] = []
        params: list[object] = []
        if harness is not None:
            conditions.append("harness = ?")
            params.append(harness)
        if source is not None:
            conditions.append("source = ?")
            params.append(source)
        if scope is not None:
            if scope not in _POLICY_SCOPES:
                msg = f"Invalid policy scope: {scope}"
                raise ValueError(msg)
            conditions.append("scope = ?")
            params.append(scope)
        if artifact_id is not None:
            conditions.append("artifact_id = ?")
            params.append(artifact_id)
        elif artifact_id_is_null:
            conditions.append("artifact_id is null")
        if artifact_hash is not None:
            conditions.append("artifact_hash = ?")
            params.append(artifact_hash)
        elif artifact_hash_is_null:
            conditions.append("artifact_hash is null")
        if workspace is not None:
            conditions.append("(workspace = ? or workspace = ?)")
            params.extend((_stored_workspace_policy_key(workspace), _normalized_workspace_path(workspace)))
        if publisher is not None:
            conditions.append("publisher = ?")
            params.append(publisher)
        query = "delete from policy_decisions"
        if conditions:
            query += " where " + " and ".join(conditions)
        next_control_state: dict[str, object] | None = None
        with self._connect() as connection:
            local_query = (
                f"select decision_id from policy_decisions where source not in {_REMOTE_POLICY_SOURCE_PLACEHOLDERS}"
            )
            local_params: list[object] = list(_REMOTE_POLICY_SOURCE_PARAMS)
            if conditions:
                local_query += " and " + " and ".join(conditions)
                local_params.extend(params)
            local_ids = {
                int(row["decision_id"]) for row in connection.execute(local_query, tuple(local_params)).fetchall()
            }
            state = self._refresh_policy_integrity_state(
                connection,
                now=current_time,
                create_key=True,
                allow_cutover_resign=False,
            )
            cursor = connection.execute(query, tuple(params))
            cleared = int(cursor.rowcount if cursor.rowcount is not None else 0)
            if local_ids and state.get("mode") == "protected":
                key, key_id = self._policy_integrity_secret_material(create=True)
                trusted_state = self._load_policy_integrity_control_state(create=True)
                if key is not None and key_id is not None and trusted_state is not None:
                    next_control_state = self._advance_policy_integrity_generation(
                        connection,
                        now=current_time,
                        key=key,
                        key_id=key_id,
                        trusted_state=trusted_state,
                    )
                    connection.commit()
        if next_control_state is not None:
            self._finalize_policy_integrity_control_state(next_control_state)
        return cleared

    def get_latest_diff(self, harness: str, artifact_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select artifact_id, harness, changed_fields_json, previous_hash, current_hash, recorded_at
                from artifact_diffs
                where harness = ? and artifact_id = ?
                order by diff_id desc
                limit 1
                """,
                (harness, artifact_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "artifact_id": str(row["artifact_id"]),
            "harness": str(row["harness"]),
            "changed_fields": json.loads(str(row["changed_fields_json"])),
            "previous_hash": row["previous_hash"],
            "current_hash": str(row["current_hash"]),
            "recorded_at": str(row["recorded_at"]),
        }
