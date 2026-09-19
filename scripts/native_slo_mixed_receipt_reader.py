"""Explicit installed-arm receipt readback; candidate never falls back."""

from __future__ import annotations

import re
from typing import Any


class InstalledReceiptReader:
    def __init__(self, store: Any, *, profile: str = "candidate") -> None:
        if profile not in {"candidate", "baseline_2e672d2"}:
            raise ValueError("mixed receipt profile unsupported")
        self.store, self.profile = store, profile
        self.getter = getattr(store, "get_native_decision_receipt", None)
        self.legacy = not callable(self.getter)
        if self.legacy and profile != "baseline_2e672d2":
            raise RuntimeError("candidate binding-aware receipt getter unavailable")
        if self.legacy:
            with store._connect() as connection:
                columns = connection.execute("pragma table_info(native_hook_decision_receipts)").fetchmany(65)
            if not columns or len(columns) >= 65 or any(row["name"] == "command_extensions_json" for row in columns):
                raise RuntimeError("installed schema does not match pinned legacy receipt arm")

    def read(self, identity: str) -> dict[str, object] | None:
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            return None
        if not self.legacy:
            assert callable(self.getter)
            result = self.getter(identity)
            return result if isinstance(result, dict) else None
        from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt

        with self.store._connect() as connection:
            row = connection.execute(
                "select * from native_hook_decision_receipts where decision_id = ?", (identity,)
            ).fetchone()
        if row is None:
            return None
        receipt = dict(row)
        receipt.pop("recorded_at", None)
        # Reject schema drift rather than stripping a candidate's new binding.
        if "command_extensions_json" in receipt or "command_extensions" in receipt:
            return None
        for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
            if receipt.get(field) not in (0, 1):
                return None
            receipt[field] = bool(receipt[field])
        return validate_native_decision_receipt(receipt)
