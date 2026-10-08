from __future__ import annotations

import math
import time
import urllib.error
from collections.abc import Callable, Mapping
from typing import Final, TypeVar

if __package__:
    from .release_registry_types import Registry, RegistryVerificationError, ReleaseInspection
else:
    from release_registry_types import (  # pyright: ignore[reportImplicitRelativeImport]
        Registry,
        RegistryVerificationError,
        ReleaseInspection,
    )

REGISTRY_RETRY_ATTEMPTS: Final = 6
REGISTRY_RETRY_INITIAL_DELAY_SECONDS: Final = 2.0
REGISTRY_RETRY_MAX_DELAY_SECONDS: Final = 30.0
REGISTRY_RETRY_MAX_ATTEMPTS: Final = REGISTRY_RETRY_ATTEMPTS
REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS: Final = 60.0

Sleeper = Callable[[float], None]
Fetcher = Callable[[str], bytes]
_Result = TypeVar("_Result")


class _RetryableRegistryError(RegistryVerificationError):
    """A registry response may become valid during the bounded retry window."""


class _PendingRegistryError(_RetryableRegistryError):
    """A valid release response is visible before its distribution list propagates."""


def _fetch_payload(
    url: str,
    *,
    fetcher: Fetcher,
    allow_not_found: bool = False,
) -> bytes | None:
    try:
        return fetcher(url)
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        if exc.code == 404 or exc.code in {408, 425, 429} or 500 <= exc.code < 600:
            raise _RetryableRegistryError(f"Registry request failed with HTTP {exc.code}") from exc
        raise RegistryVerificationError(f"Registry request failed with HTTP {exc.code}") from exc
    except RegistryVerificationError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise _RetryableRegistryError("Registry request failed") from exc


def _compare_digest_sets(
    local_hashes: Mapping[str, str],
    remote_hashes: Mapping[str, str],
    *,
    registry: Registry,
) -> None:
    local_names = set(local_hashes)
    remote_names = set(remote_hashes)
    if local_names != remote_names:
        missing = sorted(local_names - remote_names)
        extra = sorted(remote_names - local_names)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        mismatch = RegistryVerificationError(
            f"{registry.value} distribution set does not match the local build ({'; '.join(details)})"
        )
        if _is_eventually_complete_distribution_set(local_hashes, remote_hashes):
            raise _RetryableRegistryError(str(mismatch))
        raise mismatch
    mismatched = sorted(filename for filename, digest in local_hashes.items() if remote_hashes[filename] != digest)
    if mismatched:
        raise RegistryVerificationError(f"{registry.value} distribution digest mismatch:{','.join(mismatched)}")


def _is_eventually_complete_distribution_set(
    local_hashes: Mapping[str, str],
    remote_hashes: Mapping[str, str],
) -> bool:
    """Return true only for a matching remote subset missing local artifacts."""

    local_names = set(local_hashes)
    remote_names = set(remote_hashes)
    return remote_names < local_names and all(
        local_hashes[filename] == remote_hashes[filename] for filename in remote_names
    )


def _retry_delay(attempt: int, *, initial: float, maximum: float) -> float:
    capped_attempt = min(attempt, REGISTRY_RETRY_MAX_ATTEMPTS - 1)
    return min(maximum, initial * (2**capped_attempt))


def _is_valid_retry_delay_value(delay: object) -> bool:
    if isinstance(delay, bool) or not isinstance(delay, (int, float)):
        return False
    return isinstance(delay, int) or math.isfinite(delay)


def _validate_retry_settings(
    attempts: int,
    initial_delay: float,
    maximum_delay: float,
) -> None:
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= REGISTRY_RETRY_MAX_ATTEMPTS:
        raise RegistryVerificationError(
            f"Registry retry attempts must be between one and {REGISTRY_RETRY_MAX_ATTEMPTS}"
        )
    if not all(_is_valid_retry_delay_value(delay) for delay in (initial_delay, maximum_delay)):
        raise RegistryVerificationError("Registry retry delays must be finite numbers")
    if initial_delay < 0 or maximum_delay < initial_delay:
        raise RegistryVerificationError("Registry retry delays must be non-negative and ordered")
    if maximum_delay > REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:
        raise RegistryVerificationError(
            f"Registry retry delay must not exceed {REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:g} seconds"
        )
    total_delay = sum(
        _retry_delay(attempt, initial=initial_delay, maximum=maximum_delay) for attempt in range(attempts - 1)
    )
    if total_delay > REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:
        raise RegistryVerificationError(
            f"Registry retry delay budget must not exceed {REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:g} seconds"
        )


def _wait_for_retry(
    attempt: int,
    *,
    attempts: int,
    initial_delay: float,
    maximum_delay: float,
    sleep: Sleeper,
) -> bool:
    if attempt == attempts - 1:
        return False
    sleep(_retry_delay(attempt, initial=initial_delay, maximum=maximum_delay))
    return True


def _retry_registry_operation(
    operation: Callable[[], _Result],
    *,
    retry_attempts: int = REGISTRY_RETRY_ATTEMPTS,
    retry_initial_delay_seconds: float = REGISTRY_RETRY_INITIAL_DELAY_SECONDS,
    retry_max_delay_seconds: float = REGISTRY_RETRY_MAX_DELAY_SECONDS,
    sleep: Sleeper | None = None,
) -> _Result:
    _validate_retry_settings(
        retry_attempts,
        retry_initial_delay_seconds,
        retry_max_delay_seconds,
    )
    sleep_fn = time.sleep if sleep is None else sleep

    for attempt in range(retry_attempts):
        try:
            return operation()
        except _RetryableRegistryError:
            if not _wait_for_retry(
                attempt,
                attempts=retry_attempts,
                initial_delay=retry_initial_delay_seconds,
                maximum_delay=retry_max_delay_seconds,
                sleep=sleep_fn,
            ):
                raise

    raise AssertionError("Registry operation exhausted without a result")


def _inspect_release_with_retry(
    registry: Registry,
    version_text: str,
    *,
    inspector: Callable[..., ReleaseInspection],
    project_name: str,
    fetcher: Callable[[str], bytes],
    retry_attempts: int = REGISTRY_RETRY_ATTEMPTS,
    retry_initial_delay_seconds: float = REGISTRY_RETRY_INITIAL_DELAY_SECONDS,
    retry_max_delay_seconds: float = REGISTRY_RETRY_MAX_DELAY_SECONDS,
    pending_on_incomplete: bool = False,
    sleep: Sleeper | None = None,
) -> ReleaseInspection | None:
    def inspect_once() -> ReleaseInspection | None:
        try:
            return inspector(registry, version_text, project_name=project_name, fetcher=fetcher)
        except _PendingRegistryError:
            if not pending_on_incomplete:
                raise
            return None

    return _retry_registry_operation(
        inspect_once,
        retry_attempts=retry_attempts,
        retry_initial_delay_seconds=retry_initial_delay_seconds,
        retry_max_delay_seconds=retry_max_delay_seconds,
        sleep=sleep,
    )
