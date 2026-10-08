from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest


def _resolve_native_hook_runtime() -> Path:
    """Resolve the caller-pinned runtime path used by native hook tests.

    A source-tree ``target/release`` or ``target/debug`` binary may belong to
    another checkout revision. Requiring the explicit CI/local override keeps
    stale native artifacts from being selected silently. The caller remains
    responsible for building and provenance-verifying the selected runtime.
    """

    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        pytest.fail(
            "HOL_GUARD_NATIVE_BINARY must explicitly name the compiled Rust runtime; "
            "native retirement proof cannot select a source-tree fallback"
        )
    runtime = Path(binary).expanduser()
    if not runtime.is_file():
        pytest.fail(f"HOL_GUARD_NATIVE_BINARY does not name an existing runtime file: {runtime}")
    try:
        return runtime.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        pytest.fail(f"HOL_GUARD_NATIVE_BINARY could not be resolved: {runtime} ({exc})")


@pytest.fixture
def native_hook_force(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Drive hook entrypoints through the compiled native runtime.

    Hook integration tests that assert real decisions (deny/review/allow)
    need the Rust authority: ``force`` makes ``HOL_GUARD_NATIVE_BINARY``
    authoritative, and the standalone CLI publishes its own policy snapshot.
    There is no Python fallback, so the runtime is required, not skipped.
    """

    runtime = _resolve_native_hook_runtime()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    return runtime


@pytest.fixture
def native_approval_reuse_runtime(native_hook_force: Path) -> Path:
    """Run approval reuse assertions with the caller-pinned native authority."""
    return native_hook_force


@pytest.fixture(scope="session")
def _native_context_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Session-shared guard home so the resident is spawned once per run."""

    from codex_plugin_scanner.guard.native_policy_snapshot import (
        provision_native_policy_verifier_key,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    guard_home = tmp_path_factory.mktemp("native-context-guard-home")
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    # The managed resident refuses to serve until the policy verifier key the
    # publisher would normally provision exists; seed a test key once.
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    # Pre-warm the capabilities cache and the persistent resident client pool
    # at session scope.  Tests that patch subprocess.Popen globally would
    # otherwise intercept the first probe/pool spawn mid-test and break the
    # digest path (the pool spawns once and is then reused).
    binary = _context_digest_runtime_binary()
    if binary is not None:
        from codex_plugin_scanner.guard import native_context

        previous_native = os.environ.get("HOL_GUARD_NATIVE")
        previous_binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
        previous_test_mode = os.environ.get("HOL_GUARD_TEST_MODE")
        previous_diagnostic = os.environ.get("HOL_GUARD_NATIVE_DIAGNOSTIC")
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(binary)
        # The resident pool captures its environment when the prewarm starts.
        os.environ["HOL_GUARD_TEST_MODE"] = "1"
        os.environ["HOL_GUARD_NATIVE_DIAGNOSTIC"] = "1"
        try:
            native_context.native_context_digest(
                "launch_argv_digest",
                {"argv": ["guard-context-warmup"]},
                guard_home=guard_home,
            )
        finally:
            if previous_native is None:
                os.environ.pop("HOL_GUARD_NATIVE", None)
            else:
                os.environ["HOL_GUARD_NATIVE"] = previous_native
            if previous_binary is None:
                os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
            else:
                os.environ["HOL_GUARD_NATIVE_BINARY"] = previous_binary
            if previous_test_mode is None:
                os.environ.pop("HOL_GUARD_TEST_MODE", None)
            else:
                os.environ["HOL_GUARD_TEST_MODE"] = previous_test_mode
            if previous_diagnostic is None:
                os.environ.pop("HOL_GUARD_NATIVE_DIAGNOSTIC", None)
            else:
                os.environ["HOL_GUARD_NATIVE_DIAGNOSTIC"] = previous_diagnostic
    yield guard_home
    close_native_residents(guard_home)


@pytest.fixture
def native_prompt_analysis(
    native_hook_force: Path,
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    from codex_plugin_scanner.guard import config

    monkeypatch.setattr(config, "resolve_guard_home", lambda: _native_context_home)
    return _native_context_home


@pytest.fixture
def native_mcp_probe(
    native_hook_force: Path,
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Callable[[Path], None]]:
    """Exercise MCP discovery through the real keyed native resident."""
    from codex_plugin_scanner.guard import config

    monkeypatch.setattr(
        config,
        "resolve_guard_home",
        lambda override=None: Path(override).expanduser() if override else _native_context_home,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
        provision_native_verifier_key_for_store,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.store import GuardStore

    homes: list[Path] = []

    def provision_home(home: Path) -> None:
        key_dir = home / "native-runtime"
        key_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        key_dir.chmod(0o700)
        # Provision the resident with this home's own GuardStore verifier
        # key, not an unrelated constant.  Approvals and policy decisions in
        # these tests are signed with the store's real key; keying the
        # resident with anything else makes authentic approvals unverifiable.
        provision_native_verifier_key_for_store(GuardStore(home))
        homes.append(home)

    yield provision_home
    for home in homes:
        close_native_residents(home)


def _context_digest_runtime_binary() -> Path | None:
    """Locate the compiled runtime for ambient digest calls."""

    override = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if override:
        return Path(override).expanduser()
    root = Path(__file__).resolve().parents[1]
    # Release only: the debug resident exceeds the 600ms startup budget.
    candidate = root / "rust" / "target" / "release" / "hol-guard-runtime"
    return candidate if candidate.is_file() else None


@pytest.fixture(autouse=True)
def _ambient_context_digest_home(
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Route ambient context-digest calls to the provisioned session resident.

    ``context_digest`` calls resolve their guard home either from the bound
    flow context or the default user home; both are pointed at the keyed
    session home.  Unit tests default to ``HOL_GUARD_NATIVE=off`` so the
    adapter's status probe is additionally re-evaluated under ``force`` —
    scoped to the ``native_context`` module only, leaving every other
    off-mode surface (hook eval, fail-safe denials) untouched.  With no
    resolvable runtime the probe is left alone and digests stay unavailable,
    preserving the no-binary behavior.
    """

    from codex_plugin_scanner.guard import native_context, native_runtime
    from codex_plugin_scanner.guard.runtime import approval_context

    real_status = native_runtime.native_runtime_status

    def _digest_status(*, deadline_monotonic: float | None = None) -> object:
        status = real_status(deadline_monotonic=deadline_monotonic)
        if status.mode != "off":
            return status
        binary = _context_digest_runtime_binary()
        if binary is None:
            return status
        previous_mode = os.environ.get("HOL_GUARD_NATIVE")
        previous_binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(binary)
        try:
            return real_status(deadline_monotonic=deadline_monotonic)
        finally:
            if previous_mode is None:
                os.environ.pop("HOL_GUARD_NATIVE", None)
            else:
                os.environ["HOL_GUARD_NATIVE"] = previous_mode
            if previous_binary is None:
                os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
            else:
                os.environ["HOL_GUARD_NATIVE_BINARY"] = previous_binary

    monkeypatch.setattr(native_context, "native_runtime_status", _digest_status)
    monkeypatch.setattr(native_context, "context_digest_guard_home", lambda: _native_context_home)
    monkeypatch.setattr(
        approval_context,
        "_context_digest_guard_home",
        lambda _home: _native_context_home,
    )


@pytest.fixture
def native_prompt_runtime(
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Exercise prompt behavior through the real authenticated native resident.

    The test suite's independent off-mode hooks stay unchanged. This fixture
    supplies only the prompt RPC's runtime and session transport directory;
    no prompt classification or result is mocked.
    """
    from codex_plugin_scanner.guard import native_context, native_execution, native_prompt
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NATIVE_POLICY_VERIFIER_KEY_NAME
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime import runner

    runtime: Path | None = None
    analyze = native_prompt.analyze
    provisioned: set[Path] = set()

    def invoke(subop: str, **kwargs):
        nonlocal runtime
        if runtime is None:
            runtime = _resolve_native_hook_runtime()
        home = kwargs.get("guard_home")
        if home is None:
            kwargs["guard_home"] = _native_context_home
        elif home != _native_context_home and home not in provisioned:
            home.mkdir(parents=True, mode=0o700, exist_ok=True)
            state_dir = home / "native-runtime"
            state_dir.mkdir(mode=0o700, exist_ok=True)
            # Never replace an existing test's authority or repair deliberately
            # invalid state. The native client validates existing keys itself.
            if not (state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME).exists():
                provision_native_policy_verifier_key(home, b"p" * 32)
            provisioned.add(home)
        with monkeypatch.context() as transport:
            transport.setattr(native_execution, "native_runtime_status", native_context.native_runtime_status)
            return analyze(subop, **kwargs)

    monkeypatch.setattr(native_prompt, "analyze", invoke)
    monkeypatch.setattr(runner, "_prompt_analyze_native", invoke)
    try:
        yield
    finally:
        for home in provisioned:
            close_native_residents(home)


@pytest.fixture
def native_context_digest(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Force the compiled runtime and return the isolated session resident home.

    Unlike ``native_hook_force`` this skips when no runtime binary is
    resolvable: environments like the cross-platform regressions job never
    build Rust artifacts, and the suite must stay runnable there.  Every job
    that sets ``HOL_GUARD_NATIVE_BINARY`` — or ships a release/debug build —
    still exercises the real resident, so native proof coverage is preserved
    where the binary exists.
    """

    binary = _context_digest_runtime_binary()
    if binary is None:
        pytest.skip("native context digest tests require the compiled Rust runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    return _native_context_home


@pytest.fixture
def package_intent_native(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Drive ``parse_package_intent`` through the compiled resident authority.

    The package-intent parser is resident-sole-authority: with no verified
    native transport it returns ``None``. This fixture provisions the shared
    enrolled guard home (verifier key seeded by ``_native_context_home``),
    forces the compiled runtime, and binds ``resolve_guard_home`` so the
    parser resolves the enrolled home. Missing runtime binaries fail this
    authoritative-parser suite rather than silently skipping its coverage.
    """

    from codex_plugin_scanner.guard import config

    binary = _resolve_native_hook_runtime()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    monkeypatch.setattr(
        config,
        "resolve_guard_home",
        lambda override=None: Path(override).expanduser() if override else _native_context_home,
    )
    return _native_context_home


@pytest.fixture
def native_approval_reuse_runtime(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Use the compiled approval authority with an enrolled isolated home."""
    from codex_plugin_scanner.guard import config

    binary = _resolve_native_hook_runtime()
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    monkeypatch.setattr(
        config,
        "resolve_guard_home",
        lambda override=None: Path(override).expanduser() if override else _native_context_home,
    )
    return _native_context_home


@pytest.fixture
def archive_package_intent_native(
    package_intent_native: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    """Use the archive test's actual enrolled home for native authority."""
    from codex_plugin_scanner.guard import config, native_context
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import (
        provision_native_verifier_key_for_store,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime import approval_context
    from codex_plugin_scanner.guard.store import GuardStore

    del package_intent_native
    home = tmp_path / "guard-home"
    home.mkdir(mode=0o700, exist_ok=True)
    provision_native_verifier_key_for_store(GuardStore(home))
    monkeypatch.setattr(
        config, "resolve_guard_home", lambda override=None: Path(override).expanduser() if override else home
    )
    monkeypatch.setattr(native_context, "context_digest_guard_home", lambda: home)
    monkeypatch.setattr(
        approval_context, "_context_digest_guard_home", lambda selected: Path(selected) if selected else home
    )
    try:
        yield home
    finally:
        close_native_residents(home)


@pytest.fixture
def native_command_artifact_reviews(monkeypatch: pytest.MonkeyPatch) -> None:
    """Supply actual native command evidence to legacy hook orchestration tests."""
    from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts
    from tests.native_command_test_support import real_native_command_evaluation

    def review(command: str, *, guard_home: Path, cwd: Path | None = None, home_dir: Path | None = None):
        del guard_home
        try:
            return real_native_command_evaluation(command, cwd=cwd, home_dir=home_dir)
        except Exception as exc:
            pytest.fail(f"Native command artifact fixture failed: {type(exc).__name__}: {exc}")

    monkeypatch.setattr(commands_support_runtime_artifacts, "review_command_native", review)


@pytest.fixture(autouse=True)
def _close_native_policy_publishers_before_monkeypatch_restore(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Join native snapshot publishers created by test-owned workers."""
    del monkeypatch
    from codex_plugin_scanner.guard import native_policy_snapshot

    with native_policy_snapshot._PUBLISHER_LOCK:
        existing_publishers = {
            id(publisher) for registered in native_policy_snapshot._PUBLISHERS.values() for publisher in registered
        }
    yield

    with native_policy_snapshot._PUBLISHER_LOCK:
        publishers = tuple(
            publisher
            for registered in native_policy_snapshot._PUBLISHERS.values()
            for publisher in registered
            if id(publisher) not in existing_publishers
        )
    live_publishers: list[str] = []
    for publisher in publishers:
        publisher.close(timeout_seconds=5.0)
        thread = getattr(publisher, "_thread", None)
        if isinstance(thread, threading.Thread) and thread.is_alive():
            with native_policy_snapshot._PUBLISHER_LOCK:
                native_policy_snapshot._PUBLISHERS.setdefault(
                    native_policy_snapshot._publisher_key(Path(publisher.guard_home)),
                    set(),
                ).add(publisher)
            live_publishers.append(f"{publisher.guard_home}:{thread.name}")
    if live_publishers:
        raise AssertionError("native policy publisher thread(s) survived test teardown: " + ", ".join(live_publishers))
