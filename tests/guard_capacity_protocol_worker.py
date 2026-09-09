"""Small spawn target for the runner/scheduler capacity contract test."""

from __future__ import annotations

import os
from contextlib import suppress
from multiprocessing.connection import Connection
from typing import cast

from codex_plugin_scanner.guard import codex_hook_windows_job as windows_job_module
from codex_plugin_scanner.guard.daemon.hook_process_protocol import as_string_object_dict, is_pair


def capacity_protocol_worker_main(
    connection: Connection,
    _configured_guard_home: str | None,
) -> None:
    """Serve the capacity contract without importing the full test module."""

    windows_job: object | None = None
    try:
        if os.name == "nt":
            windows_job = cast(object | None, windows_job_module.assign_current_process_to_windows_hook_job())
            if windows_job is None:
                connection.send(("isolation_failed", None))
                return
        else:
            try:
                os.setsid()
            except OSError:
                connection.send(("isolation_failed", None))
                return
        connection.send(
            (
                "isolated",
                {
                    "process_group_id": os.getpid() if os.name != "nt" else None,
                    "windows_job_contained": windows_job is not None,
                },
            )
        )
        connection.send(("ready", None))
        while True:
            raw_message = cast(object, connection.recv())
            if is_pair(raw_message) and raw_message[0] == "stop":
                return
            if not is_pair(raw_message):
                connection.send(
                    (
                        "result",
                        {"payload": None, "reason_code": "daemon_hook_process_invalid_request"},
                    )
                )
                continue
            message_type, raw_request = raw_message
            if message_type != "review" or as_string_object_dict(raw_request) is None:
                connection.send(
                    (
                        "result",
                        {"payload": None, "reason_code": "daemon_hook_process_invalid_request"},
                    )
                )
                continue
            connection.send(
                (
                    "result",
                    {
                        "payload": {"decision": "allow", "test_worker": "capacity"},
                        "reason_code": None,
                    },
                )
            )
    except (BrokenPipeError, EOFError, OSError):
        return
    finally:
        with suppress(Exception):
            connection.close()
        _ = windows_job
