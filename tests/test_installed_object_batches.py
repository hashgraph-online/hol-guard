"""Small installed objects share transport, while native checks remain mandatory."""

import base64

import pytest

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle, lifecycle, offline, preparation_authority


@pytest.fixture
def bundle(monkeypatch, tmp_path):
    authority = object.__new__(installed_bundle.VerifiedInstalledBundle)
    object.__setattr__(authority, "source_sha", "c" * 40)
    monkeypatch.setattr(installed_bundle, "_package", lambda: tmp_path)
    monkeypatch.setattr(installed_bundle, "_installation_root", lambda: tmp_path)
    (tmp_path / installed_bundle.ASSETS).mkdir(parents=True)
    return authority


def test_object_batches_bound_launch_count_and_preserve_every_answer(bundle, monkeypatch):
    calls = []
    references = [({"index": i}, 7) for i in range(131)]

    def native(operation, **fields):
        assert operation == "installed-batch"
        assert fields["source"] == bundle.source_sha
        calls.append(fields["items"])
        return {
            "items": [
                {"data": base64.b64encode(str(item["target"]["index"]).encode()).decode()} for item in fields["items"]
            ]
        }

    monkeypatch.setattr(installed_bundle, "call_object", native)
    assert list(bundle.fetch_objects(references)) == [str(i).encode() for i in range(131)]
    assert [len(items) for items in calls] == [64, 64, 3]
    assert [(item["target"], item["length"]) for items in calls for item in items] == references
    assert list(bundle.fetch_objects([])) == []
    assert len(calls) == 3


@pytest.mark.parametrize("fault", ["native", "container", "unavailable"])
def test_native_refusals_and_unavailability_never_fall_back(bundle, monkeypatch, fault):
    reason = installed_bundle.CONTAINER_STRUCTURE if fault == "container" else "native refusal"
    error = lifecycle.NativePackLifecycleUnavailableError(reason) if fault == "unavailable" else ValueError(reason)

    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr(installed_bundle, "call_object", refuse)
    monkeypatch.setattr(
        installed_bundle.VerifiedInstalledBundle, "fetch", lambda *args: pytest.fail("native check bypassed")
    )
    expected = "installed bundle container invalid" if fault == "container" else reason
    with pytest.raises(type(error), match=expected):
        list(bundle.fetch_objects([({"member": "object"}, 7)]))


@pytest.mark.parametrize("reply", [{"items": []}, {"items": [{"data": "!"}]}])
def test_missing_or_malformed_answers_fail_closed(bundle, monkeypatch, reply):
    monkeypatch.setattr(installed_bundle, "call_object", lambda *args, **kwargs: reply)
    with pytest.raises(ValueError):
        list(bundle.fetch_objects([({"member": "object"}, 7)]))


def test_whole_objects_keep_the_existing_checked_file_transport(bundle, monkeypatch):
    monkeypatch.setattr(installed_bundle, "call_object", lambda *args, **kwargs: {"items": [{"kind": "object"}]})
    calls = []

    def fetch(self, location, maximum):
        calls.append((location, maximum))
        return b"checked"

    monkeypatch.setattr(installed_bundle.VerifiedInstalledBundle, "fetch", fetch)
    assert list(bundle.fetch_objects([({"asset": "whole"}, 7)])) == [b"checked"]
    assert calls == [({"asset": "whole"}, 7)]


def test_offline_prefetch_batches_objects_and_retains_archive_transfer(bundle, monkeypatch, tmp_path):
    object_ref = {"sha256": "a" * 64, "location": {"member": "object"}, "length": 7}
    archive_ref = {"sha256": "b" * 64, "location": {"member": "pack"}, "length": 100}
    plans = iter(
        [
            {"needs": [{"kind": "object", "reference": object_ref}, {"kind": "archive", "reference": archive_ref}]},
            {"complete": True},
        ]
    )
    monkeypatch.setattr(offline, "_request", lambda *args: next(plans))
    monkeypatch.setattr(
        preparation_authority, "installed_bundle_type", lambda: installed_bundle.VerifiedInstalledBundle
    )
    fetched = []

    def fetch(self, location, maximum):
        fetched.append((location, maximum))
        return b"archive"

    monkeypatch.setattr(installed_bundle.VerifiedInstalledBundle, "fetch", fetch)
    monkeypatch.setattr(
        installed_bundle,
        "call_object",
        lambda *args, **kwargs: {"items": [{"data": base64.b64encode(b"object").decode()}]},
    )
    objects, archives = [], []
    monkeypatch.setattr(offline, "publish_object", lambda *args: objects.append(args[1:]))
    monkeypatch.setattr(offline, "write_once", lambda *args: archives.append(args))
    monkeypatch.setattr(lifecycle._Session, "executable", lambda self: pytest.fail("test transport should not spawn"))
    assert offline.prefetch(bundle, tmp_path / "cache") == {"complete": True}
    assert objects == [(object_ref["sha256"], b"object")]
    assert fetched == [(archive_ref["location"], archive_ref["length"])]
    assert len(archives) == 1 and archives[0][1] == b"archive"
