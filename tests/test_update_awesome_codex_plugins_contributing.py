"""Scanner release refreshes must preserve the catalog's listing policy."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/update_awesome_codex_plugins_contributing.py"
GUIDE = """# Contribution guide

### Step 2: Run the scanner locally and check your score

Listing eligibility requires a normalized centralized score of **75/100** or higher.

### Step 3: Verify your plugin repo has the required files

Keep the required catalog and review checks.

### Run the Scanner Locally

Old release commands.

### Required in Your Plugin Repo

Keep the license requirements.
"""


class ScannerGuideRefreshTests(unittest.TestCase):
    def refresh(self, guide: Path, version: str, digest: str) -> str:
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--path",
                str(guide),
                "--scanner-version",
                version,
                "--scanner-sha256",
                digest,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return guide.read_text(encoding="utf-8")

    def test_release_refresh_preserves_normalized_listing_policy(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            guide = Path(folder) / "CONTRIBUTING.md"
            guide.write_text(GUIDE, encoding="utf-8")
            updated = self.refresh(guide, "3.59.0", "a" * 64)
        self.assertIn("normalized centralized score of **75/100** or higher", updated)
        self.assertIn("Finding severities are advisory", updated)
        self.assertIn("required catalog checks and substantive review issues must also be clear", updated)
        self.assertNotIn("80/130", updated)
        self.assertNotIn("no critical or high severity findings", updated)
        self.assertEqual(updated.count("plugin-scanner==3.59.0"), 3)
        self.assertEqual(updated.count("a" * 64), 2)
        self.assertIn("Keep the required catalog and review checks.", updated)
        self.assertTrue(updated.endswith("Keep the license requirements.\n"))

    def test_next_release_refresh_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            guide = Path(folder) / "CONTRIBUTING.md"
            guide.write_text(GUIDE, encoding="utf-8")
            self.refresh(guide, "3.59.0", "a" * 64)
            updated = self.refresh(guide, "3.60.0", "b" * 64)
            self.assertEqual(updated, self.refresh(guide, "3.60.0", "b" * 64))
        self.assertIn("**75/100**", updated)
        self.assertNotIn("plugin-scanner==3.59.0", updated)
        self.assertNotIn("a" * 64, updated)


if __name__ == "__main__":
    unittest.main()
