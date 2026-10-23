from __future__ import annotations

import os

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle, object_native


@pytest.fixture
def replies(monkeypatch, tmp_path):
    requests = []
    answers = {}
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((1, 2),))
    (tmp_path / "a.json").write_bytes(b"one")

    def native(**fields):
        requests.append(fields)
        return dict(answers.get(fields["reference"], {"data": "ZGF0YQ==", "reads": ["a"]}))

    monkeypatch.setattr(object_native, "_native", native)
    return requests, answers, tmp_path


def expand(directory, reference="r"):
    return object_native.addressed(
        "expand",
        sources=object_native.objects_read(directory),
        mode="pack",
        directory=str(directory),
        reference=reference,
        depth=0,
    )


def test_a_verified_answer_is_reused_for_the_same_request(replies, tmp_path_factory):
    requests, _answers, directory = replies
    first = expand(directory)
    first["reads"].append("changed")
    assert expand(directory) == {"data": "ZGF0YQ==", "reads": ["a"]}
    assert len(requests) == 1

    expand(directory, reference="other")
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    (elsewhere / "a.json").write_bytes(b"one")
    expand(elsewhere)
    assert len(requests) == 3


def test_rejections_and_partial_answers_are_asked_again(replies):
    requests, answers, directory = replies
    answers["bad"] = {"rejected": "delivery object integrity invalid"}
    answers["partial"] = {"need": [{"sha256": "s"}]}
    for _ in range(2):
        with pytest.raises(ValueError, match="integrity invalid"):
            expand(directory, reference="bad")
        assert "need" in expand(directory, reference="partial")
    assert len(requests) == 4


def test_a_replaced_or_missing_runtime_is_asked_again(replies, monkeypatch):
    requests, _answers, directory = replies
    expand(directory)
    monkeypatch.setattr(lifecycle, "runtime_fingerprint", lambda: ((3, 4),))
    expand(directory)
    assert len(requests) == 2

    def missing():
        raise FileNotFoundError

    monkeypatch.setattr(lifecycle, "runtime_fingerprint", missing)
    expand(directory)
    expand(directory)
    assert len(requests) == 4


def test_a_removed_or_replaced_object_is_asked_again(replies):
    requests, _answers, directory = replies
    expand(directory)
    expand(directory)
    assert len(requests) == 1

    (directory / "a.json").unlink()
    expand(directory)
    assert len(requests) == 2
    expand(directory)
    assert len(requests) == 3

    (directory / "a.json").write_bytes(b"one")
    expand(directory)
    expand(directory)
    assert len(requests) == 4
    replacement = directory / "replacement"
    replacement.write_bytes(b"two")
    os.replace(replacement, directory / "a.json")
    expand(directory)
    assert len(requests) == 5


def test_an_installed_member_follows_its_container(replies):
    requests, _answers, directory = replies
    container = directory / "objects-1.zip"
    container.write_bytes(b"zip")

    def member():
        return object_native.addressed("installed", sources=lambda _reply: [container], reference="m")

    member()
    member()
    assert len(requests) == 1
    container.unlink()
    member()
    assert len(requests) == 2


def test_answers_stay_within_their_byte_budget(replies, monkeypatch):
    requests, answers, directory = replies
    monkeypatch.setattr(object_native, "_ANSWERS_LIMIT", 200)
    monkeypatch.setattr(object_native, "_ANSWER_LIMIT", 100)
    answers["large"] = {"data": "x" * 120, "reads": []}
    expand(directory, reference="large")
    expand(directory, reference="large")
    assert len(requests) == 2

    for index in range(6):
        expand(directory, reference=str(index))
    assert sum(len(entry[0]) for entry in object_native._ANSWERS.values()) <= 200
    expand(directory, reference="5")
    assert len(requests) == 8
    expand(directory, reference="0")
    assert len(requests) == 9
