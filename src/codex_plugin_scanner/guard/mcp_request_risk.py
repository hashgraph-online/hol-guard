"""Private one-invocation category sharing for already bound MCP requests.

This carries pure facts only. It cannot authorize policy, consume approvals, or
supply a request frame. The historical prepared-facts adapters remain separate.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import get_ident
from typing import cast

from .mcp_approval_risk import BoundApprovalRiskAnalysis, issue_approval_risk_analysis
from .mcp_authority_binding import AuthorityCheck
from .mcp_risk_dependencies import ReviewedRiskHelpers as ReviewedRiskHelpers
from .models import GuardArtifact

_OWNER: ContextVar[InvocationRiskFacts | None] = ContextVar("guard_mcp_risk_pair_owner", default=None)


@dataclass(slots=True, repr=False)
class InvocationRiskFacts:
    """Opaque expiring facts; supplied only to the two supported consumers."""

    artifact: GuardArtifact | None
    arguments: object
    authority_check: AuthorityCheck | None
    support_check: Callable[[], bool] | None
    _thread: int = field(default_factory=get_ident)
    _phase: str = "new"
    _categories: tuple[str, ...] | None = None
    _signals: tuple[str, ...] | None = None
    _closed: bool = False

    def supported(self) -> bool:
        if self._closed or self._thread != get_ident() or _OWNER.get() is not self:
            self.close()
            return False
        if self.support_check is None or not self.support_check():
            self.close()
            return False
        return True

    def categories(
        self,
        artifact: GuardArtifact,
        arguments: object,
        *,
        consumer: str,
        derive: Callable[[GuardArtifact, object], tuple[str, ...]],
    ) -> tuple[str, ...]:
        if not self.supported() or artifact is not self.artifact or arguments is not self.arguments:
            self.close()
            return derive(artifact, arguments)
        authority_check = self.authority_check
        if authority_check is None:
            self.close()
            return derive(artifact, arguments)
        authority_check()
        # The authority callback can itself reach supported helper interfaces.
        # Recheck after it returns before using or storing a derived value.
        if not self.supported() or artifact is not self.artifact or arguments is not self.arguments:
            self.close()
            return derive(artifact, arguments)
        if consumer == "hash" and self._phase == "new":
            self._phase = "deriving"
            categories = derive(artifact, arguments)
            authority_check()
            if self.supported():
                self._categories = categories
                self._phase = "current"
            return categories
        if consumer == "current" and self._phase == "current" and self._categories is not None:
            self._phase = "consumed"
            return self._categories
        self.close()
        return derive(artifact, arguments)

    def record_signals(
        self,
        artifact: GuardArtifact,
        arguments: object,
        categories: tuple[str, ...],
        signals: tuple[str, ...],
    ) -> None:
        # Called only at the original source-default pure signal derivation.
        if (
            self.supported()
            and self._phase == "consumed"
            and artifact is self.artifact
            and arguments is self.arguments
            and categories is self._categories
            and type(signals) is tuple
            and all(type(signal) is str for signal in signals)
        ):
            self._signals = signals

    def export_analysis(
        self, *, observation_supported: Callable[[], bool], owner_check: Callable[[], bool]
    ) -> BoundApprovalRiskAnalysis | None:
        if (
            not self.supported()
            or self._phase != "consumed"
            or self._categories is None
            or self._signals is None
            or self.artifact is None
            or self.authority_check is None
            or self.support_check is None
            or not observation_supported()
            or not owner_check()
        ):
            return None
        pair_supported = self.support_check
        # Capture independent guards, not self.supported: the pair token closes
        # in finally while this private diagnostic projection owns its own life.
        return issue_approval_risk_analysis(
            self,
            supported=lambda: pair_supported() and observation_supported(),
            owner_check=owner_check,
        )

    def close(self) -> None:
        self._closed = True
        self._categories = None
        self._signals = None
        self.artifact = None
        self.arguments = None
        self.authority_check = None
        self.support_check = None


@contextmanager
def invocation_risk_facts(
    *,
    artifact: GuardArtifact,
    arguments: object,
    authority_check: AuthorityCheck | None,
    support_check: Callable[[], bool],
    admitted: bool,
) -> Iterator[InvocationRiskFacts | None]:
    """Never share a token across nested, concurrent, or later invocations."""
    parent = _OWNER.get()
    if parent is not None:
        parent.close()
    facts = None
    if parent is None and admitted and authority_check is not None and support_check():
        authority_check()
        facts = InvocationRiskFacts(artifact, arguments, authority_check, support_check)
    token = _OWNER.set(facts)
    try:
        yield facts
    finally:
        if facts is not None:
            facts.close()
        _OWNER.reset(token)


def invocation_categories(
    facts: object,
    artifact: GuardArtifact,
    arguments: object,
    *,
    consumer: str,
    derive: Callable[[GuardArtifact, object], tuple[str, ...]],
) -> tuple[str, ...] | None:
    if type(facts) is not InvocationRiskFacts or not cast(InvocationRiskFacts, facts).supported():
        return None
    return cast(InvocationRiskFacts, facts).categories(artifact, arguments, consumer=consumer, derive=derive)
