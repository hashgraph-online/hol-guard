"""Attach workspace observers before the real constructor starts its publisher."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch


@contextmanager
def prepare_owned_publisher(store: Any, prepare: Callable[[Any], None]) -> Iterator[list[Any]]:
    """Forward the production factory and prepare only this exact owned store."""
    from codex_plugin_scanner.guard.daemon import hook_worker

    original = hook_worker.get_native_policy_snapshot_publisher
    captured: list[Any] = []

    def observed(candidate: Any, *args: Any, **kwargs: Any) -> Any:
        publisher = original(candidate, *args, **kwargs)
        if candidate is store:
            if captured:
                raise RuntimeError("workspace construction requested its publisher twice")
            if publisher._thread is not None or publisher._started or publisher.current_snapshot_binding() is not None:
                raise RuntimeError("workspace construction publisher was already started")
            captured.append(publisher)
            prepare(publisher)
        return publisher

    try:
        with patch.object(hook_worker, "get_native_policy_snapshot_publisher", observed):
            yield captured
        if len(captured) != 1:
            raise RuntimeError("workspace construction publisher was not observed")
    except BaseException as error:
        cleanup_error = None
        for publisher in captured:
            try:
                publisher.close()
                if not publisher.closed or (publisher._thread is not None and publisher._thread.is_alive()):
                    raise RuntimeError("workspace constructor publisher containment incomplete")
            except Exception as failure:
                cleanup_error = failure
        if isinstance(error, Exception) and cleanup_error is not None:
            from scripts.native_slo_failure import failure_evidence
            from scripts.native_slo_observation_failure import contextual_failure

            raise contextual_failure(
                error, captured_publisher_contained=False, publisher_cleanup_failure=failure_evidence(cleanup_error)
            ) from error
        raise


def construct_workspace_session(
    runtime: Path,
    *,
    count: int,
    configuration: str | None,
    progress: Callable[[str], None],
    lifetime: ExitStack,
) -> tuple[Any, Any]:
    """Observe construction in the isolated helper without postponing startup."""
    from scripts import native_slo_session
    from scripts.native_slo_workspace_server import WorkspaceScenarioFixture

    original = native_slo_session.GuardDaemonServer
    prepared: list[Any] = []

    def construct(store: Any, *args: Any, **kwargs: Any) -> Any:
        def prepare(publisher: Any) -> None:
            if prepared:
                raise RuntimeError("workspace construction created multiple services")
            fixture = WorkspaceScenarioFixture.before_start(publisher, store.guard_home.parent / "workspace", count)
            prepared.append(fixture)
            lifetime.enter_context(fixture.observer)
            lifetime.callback(fixture.close)

        with prepare_owned_publisher(store, prepare):
            return original(store, *args, **kwargs)

    with patch.object(native_slo_session, "GuardDaemonServer", construct):
        adapter = native_slo_session.AdapterSession(runtime, configuration=configuration, progress=progress)
    try:
        if len(prepared) != 1:
            raise RuntimeError("workspace constructor observation missing")
        fixture = prepared[0]
        fixture.attach(adapter)
        return adapter, fixture
    except BaseException:
        adapter.close()
        raise
