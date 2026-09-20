"""Shared presentation copy for package evaluation results."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SupplyChainUserCopy:
    title: str
    summary: str
    next_step: str | None
    dashboard_url: str | None
    harness_message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "title": self.title,
            "summary": self.summary,
            "next_step": self.next_step,
            "dashboard_url": self.dashboard_url,
            "harness_message": self.harness_message,
        }
