"""Tests for tools/release_notes.py: python tools/test_release_notes.py"""

from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from release_notes import notes  # noqa: E402

CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
SAMPLE = """# Changelog

## Unreleased

- Not released yet.

## 0.4.10 (2026-12-01)

- A later patch.

## 0.4.1 (2026-11-09)

- Fix one.
- Fix two,
  continued.

## 0.4.0 (2026-11-05)

Intro line.

- Feature.
"""
INSTALL = ("Install: [PyPI](https://pypi.org/project/open-action-consent/{v}/) or "
           "[npm](https://www.npmjs.com/package/open-action-consent/v/{v}).\n")


class Notes(unittest.TestCase):
    def test_section_with_its_date_and_install_links(self):
        self.assertEqual(notes("0.4.1", SAMPLE),
                         "Released 2026-11-09.\n\n- Fix one.\n- Fix two,\n  continued.\n\n" + INSTALL.format(v="0.4.1"))

    def test_last_section_runs_to_the_end_of_the_file(self):
        self.assertEqual(notes("0.4.0", SAMPLE),
                         "Released 2026-11-05.\n\nIntro line.\n\n- Feature.\n\n" + INSTALL.format(v="0.4.0"))

    def test_a_version_never_matches_a_longer_one(self):
        self.assertNotIn("A later patch", notes("0.4.1", SAMPLE))
        self.assertIn("A later patch", notes("0.4.10", SAMPLE))

    def test_missing_version_fails(self):
        with self.assertRaises(LookupError):
            notes("9.9.9", SAMPLE)

    def test_empty_section_fails(self):
        with self.assertRaises(LookupError):
            notes("0.5.0", "## 0.5.0 (2026-12-02)\n\n## 0.4.1 (2026-11-09)\n\n- Fix.\n")

    def test_only_version_numbers_are_accepted(self):
        for bad in ("Unreleased", "0.4", "v0.4.1", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                notes(bad, SAMPLE)

    def test_every_released_version_in_the_changelog_has_notes(self):
        versions = re.findall(r"^## (\d+\.\d+\.\d+) \(", CHANGELOG, re.M)
        self.assertIn("0.4.1", versions)
        for v in versions:
            with self.subTest(version=v):
                self.assertTrue(notes(v, CHANGELOG).endswith(INSTALL.format(v=v)))

    def test_the_sdk_version_has_a_dated_changelog_section(self):
        # the release workflow makes the GitHub release page from this section, so a version bump needs one
        pyproject = (ROOT / "sdk" / "python" / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
        self.assertTrue(notes(version, CHANGELOG).startswith("Released "))


class CommandLine(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(ROOT / "tools" / "release_notes.py"), *args], capture_output=True)

    def test_prints_the_notes_as_utf8(self):
        r = self.run_tool("0.1.0")  # this section has non-ASCII text
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode("utf-8"), notes("0.1.0", CHANGELOG))

    def test_missing_version_fails_with_nothing_on_stdout(self):
        r = self.run_tool("9.9.9")
        self.assertEqual((r.returncode, r.stdout), (1, b""))
        self.assertIn(b"9.9.9", r.stderr)

    def test_no_version_is_a_usage_error(self):
        self.assertEqual(self.run_tool().returncode, 2)


if __name__ == "__main__":
    unittest.main()
