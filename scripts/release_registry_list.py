from __future__ import annotations

from packaging.version import Version

if __package__:
    from . import release_registry_retry
    from .release_registry_retry import Sleeper
    from .release_registry_types import Registry, RegistryVerificationError
    from .verify_release_registry import (
        DEFAULT_PROJECT_NAME,
        Fetcher,
        _canonical_public_version,
        _decode_object,
        _project_url,
        stdlib_fetch,
    )
else:
    import release_registry_retry  # pyright: ignore[reportImplicitRelativeImport]
    from release_registry_retry import Sleeper  # pyright: ignore[reportImplicitRelativeImport]
    from release_registry_types import (  # pyright: ignore[reportImplicitRelativeImport]
        Registry,
        RegistryVerificationError,
    )
    from verify_release_registry import (  # pyright: ignore[reportImplicitRelativeImport]
        DEFAULT_PROJECT_NAME,
        Fetcher,
        _canonical_public_version,
        _decode_object,
        _project_url,
        stdlib_fetch,
    )


def list_registry_versions(
    registry: Registry,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    fetcher: Fetcher = stdlib_fetch,
    retry_attempts: int = release_registry_retry.REGISTRY_RETRY_ATTEMPTS,
    retry_initial_delay_seconds: float = release_registry_retry.REGISTRY_RETRY_INITIAL_DELAY_SECONDS,
    retry_max_delay_seconds: float = release_registry_retry.REGISTRY_RETRY_MAX_DELAY_SECONDS,
    sleep: Sleeper | None = None,
) -> tuple[str, ...]:
    def list_once() -> tuple[str, ...]:
        payload = release_registry_retry._fetch_payload(
            _project_url(registry, project_name),
            fetcher=fetcher,
            allow_not_found=True,
        )
        if payload is None:
            return ()
        document = _decode_object(payload, label="Registry project response")
        releases = document.get("releases")
        if not isinstance(releases, dict):
            raise RegistryVerificationError("Registry project response is missing the releases object")

        versions: list[Version] = []
        for version_text in releases:
            versions.append(_canonical_public_version(version_text, label="Registry version"))
        return tuple(str(version) for version in sorted(versions))

    return release_registry_retry._retry_registry_operation(
        list_once,
        retry_attempts=retry_attempts,
        retry_initial_delay_seconds=retry_initial_delay_seconds,
        retry_max_delay_seconds=retry_max_delay_seconds,
        sleep=sleep,
    )
