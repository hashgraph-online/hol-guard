"""Native launch projection reads only values it is allowed to forward."""

from collections.abc import Mapping

import pytest

from codex_plugin_scanner.guard import native_runtime


class SelectedValuesOnly(Mapping):
    def __init__(self):
        self.selected = {
            "HOME": "/synthetic/home",
            "Lang": "synthetic-locale",
            "LC_MESSAGES": "C",
            "lc_extra": "synthetic-extra",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "0",
            "USERPROFILE": "synthetic-profile",
        }
        self.keys = [*self.selected, "UNSELECTED_SECRET", "PATH", "PYTHONPATH"]
        self.reads = []

    def __iter__(self):
        return iter(self.keys)

    def __len__(self):
        return len(self.keys)

    def __getitem__(self, key):
        if key not in self.selected:
            raise AssertionError("unadmitted environment value was read")
        self.reads.append(key)
        return self.selected[key]


@pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows-dll-path"])
def test_projection_preserves_admitted_case_and_locale_without_reading_rejected_values(monkeypatch, windows):
    values = SelectedValuesOnly()
    with monkeypatch.context() as scoped:
        scoped.setattr(native_runtime.os, "environ", values)
        scoped.setattr(native_runtime.os, "name", "nt" if windows else "posix")
        scoped.setattr(
            native_runtime, "_windows_native_dll_directories", lambda: ["/qualified/runtime", "/qualified/python"]
        )
        result = native_runtime._isolated_environment()
    expected = dict(values.selected)
    if windows:
        expected["PATH"] = native_runtime.os.pathsep.join(["/qualified/runtime", "/qualified/python"])
    assert result == expected
    assert values.reads == list(values.selected)


def test_projection_observes_admitted_changes_on_each_call(monkeypatch):
    values = SelectedValuesOnly()
    with monkeypatch.context() as scoped:
        scoped.setattr(native_runtime.os, "environ", values)
        scoped.setattr(native_runtime.os, "name", "posix")
        first = native_runtime._isolated_environment()
        values.selected["HOME"] = "/synthetic/new-home"
        second = native_runtime._isolated_environment()
    assert first["HOME"] == "/synthetic/home" and second["HOME"] == "/synthetic/new-home"
    assert first is not second
