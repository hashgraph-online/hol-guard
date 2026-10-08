"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Callable, Sequence

# ruff: noqa: F403,F405
from .store_base import *


class StoreManagedInstallsMixin:
    def set_managed_install(
        self,
        harness: str,
        active: bool,
        workspace: str | None,
        manifest: dict[str, object],
        now: str,
    ) -> None:
        from .codex_install_transaction import codex_install_transaction
        from .runtime_transition import assert_transition_mutation_allowed

        with codex_install_transaction(self.guard_home, self.path, actor="managed-install-record"):
            assert_transition_mutation_allowed(self.guard_home)
            self._set_managed_install_owned(harness, active, workspace, manifest, now)

    def _set_managed_install_owned(
        self, harness: str, active: bool, workspace: str | None, manifest: dict[str, object], now: str
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                values (?, ?, ?, ?, ?)
                on conflict(harness) do update set
                  active = excluded.active,
                  workspace = excluded.workspace,
                  manifest_json = excluded.manifest_json,
                  updated_at = excluded.updated_at
                """,
                (harness, 1 if active else 0, workspace, json.dumps(manifest), now),
            )

    def compare_and_set_managed_installs(
        self,
        changes: Sequence[tuple[str, tuple[dict[str, object] | None, ...], dict[str, object] | None]],
        *,
        before_mutation: Callable[[], None],
    ) -> bool:
        """Compare every row before invoking the file inverse; commit rows together.

        A crash during the callback rolls SQLite back. The signed file plan
        can then recover its independently durable before/after byte states.
        """
        from .codex_install_transaction import require_codex_install_owner

        require_codex_install_owner(self.guard_home)
        harnesses = [change[0] for change in changes]
        if len(harnesses) != len(set(harnesses)):
            raise ValueError("Duplicate managed-install transition target")
        with self._connect() as connection:
            # These rows participate in the durable file inverse. Preserve
            # them across power loss as well as process interruption.
            connection.execute("pragma synchronous=FULL")
            connection.execute("begin immediate")
            for harness, allowed, replacement in changes:
                if not allowed or (replacement is not None and replacement.get("harness") != harness):
                    raise ValueError("Invalid managed-install transition target")
                row = connection.execute(
                    "select harness, active, workspace, manifest_json, updated_at "
                    "from managed_installs where harness = ?",
                    (harness,),
                ).fetchone()
                current = (
                    None
                    if row is None
                    else {
                        "harness": str(row["harness"]),
                        "active": bool(row["active"]),
                        "workspace": row["workspace"],
                        "manifest": json.loads(str(row["manifest_json"])),
                        "updated_at": str(row["updated_at"]),
                    }
                )
                if current not in allowed:
                    return False
            before_mutation()
            for harness, _allowed, replacement in changes:
                if replacement is None:
                    connection.execute("delete from managed_installs where harness = ?", (harness,))
                else:
                    connection.execute(
                        """insert into managed_installs (harness, active, workspace, manifest_json, updated_at)
                        values (?, ?, ?, ?, ?) on conflict(harness) do update set
                        active = excluded.active, workspace = excluded.workspace,
                        manifest_json = excluded.manifest_json, updated_at = excluded.updated_at""",
                        (
                            harness,
                            1 if replacement["active"] else 0,
                            replacement["workspace"],
                            json.dumps(replacement["manifest"]),
                            replacement["updated_at"],
                        ),
                    )
        return True

    def get_managed_install(self, harness: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select harness, active, workspace, manifest_json, updated_at from managed_installs where harness = ?",
                (harness,),
            ).fetchone()
        if row is None:
            return None
        return {
            "harness": str(row["harness"]),
            "active": bool(row["active"]),
            "workspace": row["workspace"],
            "manifest": json.loads(str(row["manifest_json"])),
            "updated_at": str(row["updated_at"]),
        }

    def list_managed_installs(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                select harness, active, workspace, manifest_json, updated_at
                from managed_installs
                order by harness asc
                """
            ).fetchall()
        return [
            {
                "harness": str(row["harness"]),
                "active": bool(row["active"]),
                "workspace": row["workspace"],
                "manifest": json.loads(str(row["manifest_json"])),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]
