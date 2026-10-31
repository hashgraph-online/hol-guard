from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_hook_artifact_compose import native_hook_compose

from .mcp_policy_catalog_fixture import (  # noqa: F401
    mcp_policy_delivery,
    mcp_policy_inventory,
    native_mcp_catalog_admission,
)
from .mcp_policy_native_fixture import native_mcp_policy_admission  # noqa: F401


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
def live_hook_root(native_hook_force: Path, tmp_path: Path) -> Iterator[Path]:
    """A resolved temp root for a live hook review, with the native runtime forced.

    macOS pytest temp dirs sit under /private/var/folders, where no real home
    lives and where Guard reviews reads it allows under a real home. Root the
    fixture under /tmp there, as a Linux runner and real developer hosts do.
    """

    if sys.platform != "darwin":
        yield tmp_path.resolve()
        return
    root = Path(tempfile.mkdtemp(prefix="live-hook-", dir="/tmp")).resolve()
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="session")
def _native_context_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Session-shared guard home so the resident is spawned once per run."""

    from codex_plugin_scanner.guard.native_policy_snapshot import (
        provision_native_policy_verifier_key,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    guard_home = tmp_path_factory.mktemp("native-context-guard-home")
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    from .mcp_policy_native_fixture import _FIXTURE_KEYS

    # Seed the verifier key and pre-warm the capabilities cache and the
    # persistent resident client pool at session scope.  Tests that patch
    # subprocess.Popen globally would otherwise intercept the first probe/pool
    # spawn mid-test and break the digest path (the pool spawns once and is
    # then reused).
    binary = _context_digest_runtime_binary()
    if binary is not None:
        from codex_plugin_scanner.guard import native_context

        previous_native = os.environ.get("HOL_GUARD_NATIVE")
        previous_binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
        previous_test_mode = os.environ.get("HOL_GUARD_TEST_MODE")
        previous_diagnostic = os.environ.get("HOL_GUARD_NATIVE_DIAGNOSTIC")
        previous_seams = os.environ.get("HOL_GUARD_RESIDENT_TEST_SEAMS")
        os.environ["HOL_GUARD_NATIVE"] = "force"
        os.environ["HOL_GUARD_NATIVE_BINARY"] = str(binary)
        # The resident pool captures its environment when the prewarm starts.
        os.environ["HOL_GUARD_TEST_MODE"] = "1"
        os.environ["HOL_GUARD_NATIVE_DIAGNOSTIC"] = "1"
        os.environ["HOL_GUARD_RESIDENT_TEST_SEAMS"] = "1"
        try:
            # The managed resident refuses to serve until the policy verifier
            # key exists, and only the runtime can write it. With no runtime
            # there is no resident to key, so the no-binary suite is unchanged.
            try:
                provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
            except NativePolicySnapshotError as error:
                # A configured binary that is missing, stale, or built without
                # the provisioning feature is the same situation as no binary
                # at all, so leave ambient digests unavailable instead of
                # failing every test in the session. Any other code is a real
                # provisioning failure and must not be swallowed.
                if str(error) != "native_policy_verifier_runtime_unavailable":
                    raise
            else:
                _FIXTURE_KEYS[guard_home] = b"\x07" * 32
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
            if previous_seams is None:
                os.environ.pop("HOL_GUARD_RESIDENT_TEST_SEAMS", None)
            else:
                os.environ["HOL_GUARD_RESIDENT_TEST_SEAMS"] = previous_seams
    yield guard_home
    close_native_residents(guard_home)


@pytest.fixture
def native_bridge_render(native_hook_force: Path, _native_context_home: Path) -> Callable[..., tuple[str, str, int]]:
    """Render a daemon answer the way the bounded bridge prints it, through the resident."""

    from codex_plugin_scanner.guard.native_hook_render import native_cli_hook_emit

    def render(response: dict[str, object], *, harness: str, event_name: str) -> tuple[str, str, int]:
        rendered = native_cli_hook_emit(
            harness, response, event_name=event_name, guard_home=_native_context_home, bridge=True
        )
        assert rendered is not None
        return str(rendered["stdout"]), str(rendered["stderr"]), int(rendered["exit_code"])

    return render


@pytest.fixture
def native_signal_composition(
    native_hook_force: Path,
    _native_context_home: Path,
) -> Callable[[Sequence[object], object], SimpleNamespace]:
    """Calibrate a base action against detector signals in the resident.

    The composition rules live in the Rust runtime; this side only carries the
    signals the detector registry emitted and reads back the composed action,
    so tests that need a composition assert on the authority's answer rather
    than on a second copy of the rules.
    """

    def compose(signals: Sequence[object], base_action: object) -> SimpleNamespace:
        payload = native_hook_compose(
            "signal_composition",
            {
                "signals": [signal.to_dict() for signal in signals],
                "base_action": base_action,
            },
            guard_home=_native_context_home,
        )
        return SimpleNamespace(**payload)

    return compose


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


def patch_popen_past_native_runtime(
    monkeypatch: pytest.MonkeyPatch,
    replacement: Callable[..., object],
) -> None:
    """Stand ``replacement`` in for ``Popen`` while Guard's own runtime calls still run.

    ``subprocess.Popen`` is shared by every in-process spawn, so a fake meant
    for one spawn also intercepts the bounded runtime invocations Guard makes
    itself -- provisioning the resident verifier key, for instance -- and hands
    the hook launcher a stand-in with no pipes. Invocations of the native
    runtime binary keep reaching the real ``Popen``; everything else goes to
    ``replacement``. The runtime is probed first, because the probe spawns too.
    """

    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    real_popen = subprocess.Popen
    identity = native_runtime_status().identity
    native_argv0 = None if identity is None else str(identity.path)

    def popen(command: object, *args: object, **kwargs: object) -> object:
        if (
            native_argv0 is not None
            and isinstance(command, (list, tuple))
            and command
            and str(command[0]) == native_argv0
        ):
            return real_popen(command, *args, **kwargs)  # type: ignore[call-overload]
        return replacement(command, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", popen)


@pytest.fixture(autouse=True)
def _ambient_context_digest_home(
    _native_context_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Route ambient context-digest calls to the provisioned session resident.

    ``context_digest`` calls resolve their guard home either from the bound
    flow context or the default user home; both are pointed at the keyed
    session home.  Unit tests default
    to ``HOL_GUARD_NATIVE=off`` so the
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
    from codex_plugin_scanner.guard.runtime import guard_run_evaluation as runner

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
def native_command_capability_runtime(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Answer remote-command capability requests from the shared resident.

    The ``command_capability`` and ``command_envelope`` ops read every input
    off the wire, so the Guard home they are asked about only has to name a
    resident that is already keyed and warm.  Tests keep their own store home
    for Guard's Python persistence and borrow the session home for the runtime
    calls, which avoids spawning a resident per store.  Jobs that build no Rust
    artifact skip, like the other compiled-runtime fixtures.
    """

    from codex_plugin_scanner.guard import native_command_capability, native_command_envelope

    binary = _context_digest_runtime_binary()
    if binary is None:
        pytest.skip("command capability tests require the compiled Rust runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    for module in (native_command_capability, native_command_envelope):
        monkeypatch.setattr(
            module,
            "_resolve_digest_home",
            lambda guard_home=None: _native_context_home,
        )
    return _native_context_home


@pytest.fixture
def native_adapter_state_integrity_runtime(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Answer adapter-state authentication requests from the shared resident.

    The ``adapter_state_integrity`` op reads the manifest and the key off the
    wire, so the Guard home it is asked about only has to name a resident that
    is already keyed and warm.  Tests keep their own ``tmp_path`` guard home
    for the adapter state key file, which stays Python-side, and borrow the
    session home for the runtime call.
    """

    from codex_plugin_scanner.guard import native_adapter_state_integrity

    binary = _context_digest_runtime_binary()
    if binary is None:
        pytest.skip("adapter state integrity tests require the compiled Rust runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    monkeypatch.setattr(
        native_adapter_state_integrity,
        "_resolve_digest_home",
        lambda guard_home=None: _native_context_home,
    )
    return _native_context_home


@pytest.fixture
def package_workspace_scope_native(
    monkeypatch: pytest.MonkeyPatch,
    _native_context_home: Path,
) -> Path:
    """Derive package workspace approval scopes in the compiled resident.

    ``package_request_{portable,runtime}_workspace_scope`` are resident-sole-
    authority: the scope a saved package approval is stored and matched under
    has one derivation, and an unavailable resident raises rather than
    guessing a key.  The op reads every input off the wire, so the Guard home
    only has to name a resident that is already keyed and warm.
    """

    from codex_plugin_scanner.guard import native_package_workspace_scope

    binary = _context_digest_runtime_binary()
    if binary is None:
        pytest.skip("package workspace scope tests require the compiled Rust runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(binary.resolve()))
    monkeypatch.setattr(
        native_package_workspace_scope,
        "_resolve_digest_home",
        lambda guard_home=None: _native_context_home,
    )
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
def native_contained_wrapper_runtime(
    native_hook_force: Path, _native_context_home: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Serve the contained wrapper peel from the real resident.

    The sink's peel is the classifier's own answer now: the grammar lives in
    `contained_wrapper.rs` alone and this side only carries what it returns.
    There is no Python peel left to fall back to, so these suites ask the
    session resident rather than a second copy of the rules.
    """

    from codex_plugin_scanner.guard import native_contained_wrapper_plan

    monkeypatch.setattr(native_contained_wrapper_plan, "_resolve_digest_home", lambda _guard_home: _native_context_home)
    return _native_context_home


@pytest.fixture
def native_runtime_detectors_runtime(
    native_hook_force: Path, _native_context_home: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Serve the runtime detector run from the real resident; there is no Python fallback."""

    from codex_plugin_scanner.guard import native_runtime_detectors

    monkeypatch.setattr(native_runtime_detectors, "_resolve_digest_home", lambda _guard_home: _native_context_home)
    return _native_context_home


@pytest.fixture
def native_route_policy_with_hooks_off(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep daemon route/origin policy native while hook handling stays ``off``.

    The daemon's route and origin policy is owned by the resident and has no
    Python answer, so a test that sets ``HOL_GUARD_NATIVE=off`` to exercise
    the Python hook fallback would otherwise see every request fail closed.
    Only the route-policy transport call runs with the runtime pinned; hook
    handling in the same test still observes ``off``.
    """

    from codex_plugin_scanner.guard import (
        native_daemon_route,
        native_policy_snapshot_publisher,
        native_runtime,
    )

    runtime = _resolve_native_hook_runtime()
    real_request = native_daemon_route._resident_request
    real_mode = native_runtime.native_mode
    real_provision = native_policy_snapshot_publisher.provision_native_verifier_key_for_store
    pinned = threading.local()

    def pinned_mode():
        # Only the thread currently inside a route request sees ``force``;
        # concurrent hook workers keep reading the configured mode.
        return "force" if getattr(pinned, "active", False) else real_mode()

    def pinned_request(**kwargs):
        # The caller resolved its status before the pin applied; resolve it again
        # inside the pin so the request sees the pinned runtime.
        kwargs.pop("status", None)
        previous = getattr(pinned, "active", False)
        pinned.active = True
        try:
            return real_request(**kwargs)
        finally:
            pinned.active = previous

    def pinned_provision(store):
        # The resident's verifier key is derived by the native runtime, so this
        # prerequisite needs the same pinned runtime the route call gets. Without
        # the pin the override binary is invisible in ``auto``/``off`` mode and
        # the daemon answers every route request with a fail-closed 503.
        previous = getattr(pinned, "active", False)
        pinned.active = True
        try:
            return real_provision(store)
        finally:
            pinned.active = previous

    # The runtime path is only honoured for shadow/force, so naming it is
    # inert for hook handling that observes ``off``.
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    monkeypatch.setattr(native_runtime, "native_mode", pinned_mode)
    monkeypatch.setattr(native_daemon_route, "_resident_request", pinned_request)
    monkeypatch.setattr(
        native_policy_snapshot_publisher,
        "provision_native_verifier_key_for_store",
        pinned_provision,
    )
    return runtime
