"""Deterministic registry for verified network mediation backends."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.runtime.network_capability_contract import (
    CapabilityRequirement,
    PlatformCapabilityProfile,
    PlatformFamily,
    enforcement_grade_rank,
    negotiate_capability,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import EnforcementGrade


@dataclass(frozen=True, slots=True)
class BackendSelection:
    profile: PlatformCapabilityProfile
    achieved_grade: EnforcementGrade


class NetworkBackendRegistry:
    def __init__(self, profiles: tuple[PlatformCapabilityProfile, ...] = ()) -> None:
        self._profiles: dict[str, PlatformCapabilityProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: PlatformCapabilityProfile) -> None:
        existing = self._profiles.get(profile.backend_id)
        if existing is not None and existing != profile:
            raise ValueError(f"backend profile conflict: {profile.backend_id}")
        self._profiles[profile.backend_id] = profile

    def profiles(self, platform: PlatformFamily | None = None) -> tuple[PlatformCapabilityProfile, ...]:
        return tuple(
            sorted(
                (profile for profile in self._profiles.values() if platform is None or profile.platform is platform),
                key=lambda profile: profile.backend_id,
            )
        )

    def select(
        self,
        *,
        platform: PlatformFamily,
        requirement: CapabilityRequirement,
    ) -> BackendSelection | None:
        selections = tuple(
            BackendSelection(profile, grade)
            for profile in self.profiles(platform)
            if (grade := negotiate_capability(profile, requirement)) is not EnforcementGrade.UNAVAILABLE
        )
        if not selections:
            return None
        return min(
            selections,
            key=lambda selection: (-enforcement_grade_rank(selection.achieved_grade), selection.profile.backend_id),
        )
