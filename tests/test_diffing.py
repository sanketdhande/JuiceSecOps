from __future__ import annotations

import tempfile
import subprocess
import unittest

from juicesecops.diffing import collect_changes
from juicesecops.policy import Policy


def _run(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


class DiffingTests(unittest.TestCase):
    def test_collect_changes_reads_relevant_git_diff(self):
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            repo.mkdir()
            _run(repo, "init")
            _run(repo, "config", "user.email", "test@example.com")
            _run(repo, "config", "user.name", "Tester")

            tracked = repo / "routes"
            tracked.mkdir()
            target = tracked / "login.ts"
            target.write_text("export function login() { return true }\n", encoding="utf-8")
            _run(repo, "add", ".")
            _run(repo, "commit", "-m", "init")

            target.write_text(
                "export function login(next) {\n  return res.redirect(req.query.next)\n}\n",
                encoding="utf-8",
            )

            changes = collect_changes(repo, Policy())
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0].path, "routes/login.ts")
            self.assertIn("req.query.next", changes[0].diff)


if __name__ == "__main__":
    unittest.main()
