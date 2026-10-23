"""Trusted task limits must reach Guard privately and without model input."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci.gauntlet.benchmark.native_task_write_policy import (
    install_task_write_policy, task_write_policy,
)


class TaskWritePolicyTests(unittest.TestCase):
    def test_private_policy_carries_total_tool_and_source_limits(self):
        policy = task_write_policy(
            max_writes=4,
            read_only_tools=("crm.read", "mail.read"),
            reserved_record_ids=("lead-a", "contact-c"),
            required_source_ids=("contact-a", "contact-b", "contact-c"),
            tool_write_limits={"crm.update": 2, "mail.create_draft": 2},
        )
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            with patch("ci.gauntlet.benchmark.native_task_write_policy.os.chown") as chown:
                install_task_write_policy(home, os.getuid(), policy)
            path = home / "mcp-task-write-budget.json"
            chown.assert_called_once_with(path, os.getuid(), os.getuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text()), policy)

    def test_incomplete_or_unbounded_policy_is_rejected(self):
        options = dict(max_writes=4, read_only_tools=("crm.read",),
                       reserved_record_ids=(), required_source_ids=("contact-c",),
                       tool_write_limits={"crm.update": 1})
        with self.assertRaisesRegex(ValueError, "bounded"):
            task_write_policy(**options)
        options["tool_write_limits"] = {"crm.update": 2, "mail.create_draft": 2}
        options["reserved_record_ids"] = ("lead-a", "lead-a")
        with self.assertRaisesRegex(ValueError, "bounded"):
            task_write_policy(**options)
        options["reserved_record_ids"] = ("lead-a",)
        options["max_writes"] = None
        with self.assertRaisesRegex(ValueError, "bounded"):
            task_write_policy(**options)


if __name__ == "__main__":
    unittest.main()
