from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import active_security, lifecycle

transport = lifecycle.transport


@pytest.fixture
def native(monkeypatch, tmp_path):
    calls = {"verify": 0, "copies": 0, "runs": 0}

    def verify_compiler(path, manifest):
        calls["verify"] += 1
        return b"runtime"

    @contextmanager
    def verified_executable(raw):
        calls["copies"] += 1
        yield Path(tmp_path / "runtime")

    def run_bounded(argv, request, timeout, limit=None):
        calls["runs"] += 1
        assert limit == transport._MAX_NATIVE_REQUEST_BYTES
        return 0, b"{}", b""

    monkeypatch.setattr(transport, "_verify_manifest", lambda path: {})
    monkeypatch.setattr(transport, "_verify_compiler", verify_compiler)
    monkeypatch.setattr(transport, "_verified_executable", verified_executable)
    monkeypatch.setattr(transport, "_run_bounded", run_bounded)
    monkeypatch.setattr(transport, "_decode_output", lambda stdout, returncode, stderr: {})
    return calls


def test_session_verifies_once_and_only_when_native_is_used(native):
    with lifecycle.session():
        pass
    assert native["verify"] == 0

    with lifecycle.session():
        lifecycle.invoke("offline", operation="one")
        with lifecycle.session():
            lifecycle.invoke("offline", operation="two")
    assert native == {"verify": 1, "copies": 1, "runs": 2}

    lifecycle.invoke("offline", operation="three")
    lifecycle.invoke("offline", operation="four")
    assert native == {"verify": 3, "copies": 3, "runs": 4}


def test_runtime_fingerprint_tracks_the_installed_files(monkeypatch, tmp_path):
    monkeypatch.setattr(transport, "_NATIVE_PACKAGE", tmp_path)
    with pytest.raises(OSError):
        lifecycle.runtime_fingerprint()
    (tmp_path / transport._MANIFEST_NAME).write_text("{}")
    (tmp_path / transport._COMPILER_NAME).write_bytes(b"one")
    first = lifecycle.runtime_fingerprint()
    (tmp_path / transport._COMPILER_NAME).write_bytes(b"three")
    assert lifecycle.runtime_fingerprint() != first


def test_installed_answers_are_reused_until_an_installed_file_changes(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.catalog_delivery import installed_bundle

    native = tmp_path / "_native"
    native.mkdir()
    (native / "runtime-manifest.json").write_text("{}")
    monkeypatch.setattr(installed_bundle, "_package", lambda: tmp_path)
    monkeypatch.setattr(transport, "_NATIVE_PACKAGE", native)
    answers = []

    def presence():
        answers.append("presence")
        if len(answers) == 3:
            raise ValueError("installed bundle metadata unavailable")
        return True

    monkeypatch.setattr(installed_bundle, "_advertised", presence)
    assert installed_bundle.advertised() and installed_bundle.advertised()
    assert answers == ["presence"]

    (native / "runtime-manifest.json").write_text('{"changed": true}')
    assert installed_bundle.advertised()
    (native / "hol-guard-runtime").write_bytes(b"new")
    with pytest.raises(ValueError, match="metadata unavailable"):
        installed_bundle.advertised()
    assert installed_bundle.advertised()
    assert len(answers) == 4


def test_a_discovery_preparation_verifies_the_runtime_once_for_its_whole_batch(native, monkeypatch):
    # A preparation asks for up to 64 members at a time, and every one of them
    # reaches the runtime. Without an outer session each fetch would verify and
    # copy the executable again.
    from codex_plugin_scanner.guard.catalog_delivery import discovery
    from codex_plugin_scanner.guard.catalog_delivery.authority import VerifiedDistribution

    monkeypatch.setattr(discovery, "_cached", None)
    monkeypatch.setattr(discovery, "_recheck_runtime", lambda: None)
    replies = [
        {"outcome": "fetch_batch", "session": "s", "fetches": [{"location": {}, "length": 1}] * 8},
        {"outcome": "complete", "handle": "h"},
    ]
    monkeypatch.setattr(discovery, "_native", lambda guard_home, action: replies.pop(0))

    def fetch(location, length):
        lifecycle.invoke("offline", operation="fetch")
        return b"x"

    authority = object.__new__(VerifiedDistribution)
    for field, value in {"data": b"{}", "source_sha": "s" * 40, "digest": "d" * 64, "expires_at": 1}.items():
        object.__setattr__(authority, field, value)

    discovery.prepare_discovery(Path("/guard"), authority, fetch=fetch)
    assert native == {"verify": 1, "copies": 1, "runs": 8}


def test_a_record_traversal_runs_inside_one_session(native, monkeypatch):
    # The distribution, each selection and executable page, and every registry
    # catalog is expanded by the runtime inside one read of the record, so the
    # whole traversal verifies and copies the executable once.
    from codex_plugin_scanner.guard.catalog_delivery import activation_record

    opened = {
        "value": {
            "program_digest": "p" * 64,
            "catalog_digest": "c" * 64,
            "trust_digest": "t" * 64,
            "engine": "engine",
            "source_sha": "s" * 40,
        },
        "selected": ["one"],
        "registry_ids": ["two"],
        "executables": ["three"],
        "registry": [{"kind": "data", "sha256": "r" * 64, "expanded_length": 1}],
    }

    def decode_output(stdout, returncode, stderr):
        assert lifecycle._SESSION.get() is not None
        return opened

    monkeypatch.setattr(transport, "_decode_output", decode_output)
    result = activation_record.open_record("{}", "d" * 64, "m", key=b"k", directory=Path("/cache"))
    assert result.engine == "engine"
    assert result.selected == frozenset({"one"}) and result.candidate_executables == ("three",)
    assert lifecycle._SESSION.get() is None
    assert native == {"verify": 1, "copies": 1, "runs": 1}


def test_a_record_the_request_cannot_carry_is_refused_by_name(native):
    # A record arriving as bytes never reaches the runtime, so it is refused
    # here rather than escaping as a serialisation error.
    from codex_plugin_scanner.guard.catalog_delivery import activation_record

    with pytest.raises(ValueError, match="pack_lifecycle_record_payload_invalid"):
        activation_record.verify_header(b"{}", "d" * 64, "m", key=b"k")
    assert native == {"verify": 0, "copies": 0, "runs": 0}


def test_a_security_preparation_runs_inside_one_session(native, monkeypatch):
    # Its begin/complete rounds and the located reads between them all answer
    # from the same verified runtime.
    from types import SimpleNamespace

    def invoke(operation, store, **fields):
        assert lifecycle._SESSION.get() is not None
        lifecycle.invoke("offline", operation=operation)
        raise ValueError("stop before the preparation rounds")

    monkeypatch.setattr(active_security, "invoke", invoke)
    monkeypatch.setattr(active_security, "lifecycle_store", SimpleNamespace(read=lambda store: None))
    with pytest.raises(ValueError, match="stop before"):
        active_security._prepare(object(), None, {}, "publication", None)
    assert native == {"verify": 1, "copies": 1, "runs": 1}


def test_a_preparation_reads_its_publication_once_inside_its_session(native, monkeypatch):
    # A committed publication is itself a native expansion, so reading it before
    # the session starts a second verified runtime for the same bytes.
    from codex_plugin_scanner.guard.catalog_delivery import preparation

    reads = []

    def publication(verified):
        reads.append(lifecycle._SESSION.get())
        raise ValueError("stop after the publication read")

    monkeypatch.setattr(preparation, "publication", publication)
    with pytest.raises(ValueError, match="stop after"):
        preparation.prepare(object(), (), Path("/cache"), engine="engine")
    assert len(reads) == 1 and reads[0] is not None


@pytest.fixture
def authoring(monkeypatch):
    # An installed authoring context whose every fetch is a native object read.
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.catalog_delivery import installed_bundle
    from codex_plugin_scanner.guard.extension_builder import bundle_baseline, metadata_index

    bundle = SimpleNamespace(
        digest="d" * 64,
        manifest=lambda: {"policy": {"root": "root", "transport": "transport"}},
        fetch=lambda location, length: lifecycle.invoke("object", operation="installed") and b"{}",
    )
    monkeypatch.setattr(installed_bundle, "load_installed_bundle", lambda: bundle)
    exchanged = []

    def exchange(compiler, operation, records, directory, *, fetch=None, archive=None):
        exchanged.append(operation)
        for index in range(3):
            fetch({"location": {"asset": str(index)}, "length": 2})
        return {"metadata_index": {}, "programs": []}

    monkeypatch.setattr(metadata_index, "exchange", exchange)
    return bundle_baseline, exchanged


def test_an_installed_authoring_context_reads_its_objects_through_one_runtime(native, authoring, tmp_path):
    # Every located object is checked by the runtime. Verifying and copying it
    # per object outlasted the compiler's deadline over a full authoring context.
    bundle_baseline, exchanged = authoring
    result = bundle_baseline.validation_base({}, Path("compiler"), installed=True, directory=tmp_path)
    assert result == {"metadata_index": {}, "programs": []}
    assert exchanged == ["authoring-context"]
    assert native == {"verify": 1, "copies": 1, "runs": 3}
    assert lifecycle._SESSION.get() is None


def test_an_authoring_refusal_keeps_its_code_through_the_session(native, authoring, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.extension_builder import metadata_index
    from codex_plugin_scanner.guard.extension_builder.native_source_compiler import NativeSourceCompilerError

    bundle_baseline, _ = authoring

    def refuse(*args, **kwargs):
        raise NativeSourceCompilerError("native authoring failed: refused", code="refused")

    monkeypatch.setattr(metadata_index, "exchange", refuse)
    with pytest.raises(NativeSourceCompilerError) as raised:
        bundle_baseline.validation_base({}, Path("compiler"), installed=True, directory=tmp_path)
    assert raised.value.code == "refused"
