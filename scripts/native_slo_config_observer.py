"""Observe the owned publisher's original caught exception in CI only."""

from __future__ import annotations

import hashlib
import sys
import threading
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import cast, final
from unittest.mock import patch

from scripts import native_slo_failure
from scripts.native_slo_contract import assert_privacy_safe


def _caught_config_failure(error: BaseException | None) -> dict[str, object] | None:
    if not isinstance(error, Exception):
        return None
    detail = native_slo_failure._configuration_failure_metadata(error)
    if not detail:
        return None
    return assert_privacy_safe(
        {"category": "GuardConfigSourceError", **native_slo_failure._location(error), **detail}
    )


@final
class PublisherConfigObserver:
    """Bind optional cause data to a stable error-record interval on one instance.

    The production recorder runs once with its original arguments. No exception
    object survives that call. A concurrent or unobserved record is unavailable,
    and later cases may only reuse the still-current observed publisher error.
    """

    def __init__(self, publisher: object) -> None:
        self.publisher = publisher
        self._lock = threading.Lock()
        self._generation = 0
        self._active = 0
        self._detail: dict[str, object] | None = None
        self._patch: AbstractContextManager[object] | None = None
        self.identity: dict[str, object] = {
            "schema": "hol-guard.publisher-config-observer.v1",
            "installed": False,
        }

    def __enter__(self) -> PublisherConfigObserver:
        original = getattr(self.publisher, "_record_error", None)
        if not callable(original):
            return self
        try:
            self.identity.update(
                observer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                exporter_sha256=hashlib.sha256(Path(native_slo_failure.__file__).read_bytes()).hexdigest(),
            )
        except OSError:
            return self

        recorder = cast(Callable[..., object], original)

        def record(*args: object, **kwargs: object) -> object:
            caught = sys.exc_info()[1]
            with self._lock:
                self._generation += 1
                started = self._generation
                self._active += 1
                self._detail = None
            detail = None
            try:
                code = None
                if len(args) == 1 and not kwargs:
                    code = args[0]
                elif not args:
                    code = kwargs.get("error")
                if type(code) is str and code.strip().lower() == "guardconfigsourceerror":
                    detail = _caught_config_failure(caught)
            except Exception:
                # Diagnostic serialization cannot replace the publisher error.
                detail = None
            del caught
            recorded = False
            try:
                result = recorder(*args, **kwargs)
                recorded = True
                return result
            finally:
                with self._lock:
                    self._active -= 1
                    self._generation += 1
                    if recorded and self._active == 0 and self._generation == started + 1:
                        self._detail = detail

        self._patch = patch.object(self.publisher, "_record_error", record)
        self._patch.__enter__()
        self.identity["installed"] = True
        return self

    def stamp(self) -> int | None:
        with self._lock:
            return self._generation if self._active == 0 and self._detail is not None else None

    def evidence(self, stamp: int | None, refusal: Mapping[str, object]) -> dict[str, object] | None:
        if stamp is None or refusal.get("publisher_error_value") != "guardconfigsourceerror":
            return None
        with self._lock:
            if self._active or stamp != self._generation or self._detail is None:
                return None
            return {
                **self._detail,
                "capture_context": "original_publisher_record_error",
                "observer_generation": self._generation,
                "observer": dict(self.identity),
            }

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._patch is not None:
            self._patch.__exit__(exception_type, exception, traceback)
        with self._lock:
            self._detail = None
            self._generation += 1
