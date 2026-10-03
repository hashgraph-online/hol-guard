import pytest

from ci.native_runtime.probe_live_file_tools import assert_file_tools


def file_events():
    return [
        event
        for index, (name, args) in enumerate(
            [
                ("read", {"path": "seed.txt"}),
                ("write", {"path": "copy.txt", "content": "fixture-before\n"}),
                ("read", {"path": "copy.txt"}),
                ("edit", {"input": "[copy.txt#FAE4]\nPUT 1.=1:\n+fixture-after"}),
                ("read", {"path": "copy.txt"}),
            ]
        )
        for event in [
            {"type": "tool_execution_start", "toolName": name, "toolCallId": str(index), "args": args},
            {"type": "tool_execution_end", "toolCallId": str(index), "isError": False},
        ]
    ]


def prepare_workspace(tmp_path):
    (tmp_path / "seed.txt").write_text("fixture-before\n")
    (tmp_path / "copy.txt").write_text("fixture-after\n")
    return tmp_path


def test_actual_anchored_edit_format_is_required(tmp_path):
    workspace = prepare_workspace(tmp_path)
    events = file_events()
    assert_file_tools(events, workspace)
    for payload in [
        "[other.txt#FAE4]\nPUT 1.=1:\n+fixture-after",
        "[copy.txt#FAE4]\n[other.txt#FAE4]\nPUT 1.=1:\n+fixture-after",
    ]:
        events[6]["args"] = {"input": payload}
        with pytest.raises(AssertionError, match="target"):
            assert_file_tools(events, workspace)


def test_missing_failed_or_mismatched_file_calls_cannot_pass(tmp_path):
    workspace = prepare_workspace(tmp_path)
    with pytest.raises(AssertionError, match="omitted"):
        assert_file_tools(file_events()[:-2], workspace)
    events = file_events()
    events[7]["isError"] = True
    with pytest.raises(AssertionError, match="failed"):
        assert_file_tools(events, workspace)
    events[7]["isError"] = False
    events[7]["toolCallId"] = "wrong"
    with pytest.raises(AssertionError, match="identity"):
        assert_file_tools(events, workspace)


def test_model_claims_do_not_replace_write_edit_side_effects(tmp_path):
    workspace = prepare_workspace(tmp_path)
    (workspace / "copy.txt").write_text("fixture-before\n")
    with pytest.raises(AssertionError, match="side effects"):
        assert_file_tools(file_events(), workspace)


def test_outside_cwd_anchored_edit_uses_actual_host_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    workspace = tmp_path / "workspace"
    outside = tmp_path / "other"
    workspace.mkdir()
    outside.mkdir()
    prepare_workspace(outside)
    events = file_events()
    for event in events:
        if event.get("type") == "tool_execution_start" and "path" in event["args"]:
            event["args"]["path"] = str(outside / event["args"]["path"])
    events[6]["args"] = {"input": "[~/other/copy.txt#FAE4]\nPUT 1.=1:\n+fixture-after"}
    assert_file_tools(events, workspace, outside)
    events[6]["args"] = {"input": "[~/elsewhere/copy.txt#FAE4]\nPUT 1.=1:\n+fixture-after"}
    with pytest.raises(AssertionError, match="target"):
        assert_file_tools(events, workspace, outside)


@pytest.mark.parametrize("path_key", ("path", "file_path"))
def test_string_replacement_edit_validates_target_and_contents(tmp_path, path_key):
    workspace = prepare_workspace(tmp_path)
    events = file_events()
    events[6]["args"] = {
        path_key: "copy.txt", "old_string": "fixture-before", "new_string": "fixture-after"
    }
    assert_file_tools(events, workspace)
    events[6]["args"][path_key] = "other.txt"
    with pytest.raises(AssertionError, match="target"):
        assert_file_tools(events, workspace)
    events[6]["args"][path_key] = "copy.txt"
    events[6]["args"]["new_string"] = "unexpected"
    with pytest.raises(AssertionError, match="string-replacement"):
        assert_file_tools(events, workspace)
