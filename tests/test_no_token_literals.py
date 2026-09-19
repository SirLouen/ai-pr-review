"""No tracked file contains a string shaped like a real provider credential.

The secret seeder's tests need realistic tokens, and one written as a single literal (a
Slack token in tests/test_seeders.py) was refused by GitHub push protection. Fixtures build
such values at runtime -- "xoxb-" + "..." -- so the source never holds the contiguous
pattern while the test still checks the same string. This catches a new one at commit time
rather than at push.
"""
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PATTERNS = {
    "Slack token": re.compile(r"xox[abposr]-[0-9A-Za-z]{6,}-[0-9A-Za-z-]{6,}"),
    "Slack webhook": re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]{6,}/"),
    "GitHub classic token": re.compile(r"gh[pousr]_[0-9A-Za-z]{36}\b"),
    "GitHub fine-grained token": re.compile(r"github_pat_[0-9A-Za-z_]{60,}"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Stripe live key": re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "npm token": re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"),
}

# AWS's own documentation example key, which secret scanners allowlist by design.
ALLOWED = {"AKIAIOSFODNN7EXAMPLE"}


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True,
                         check=True).stdout
    return [name for name in out.decode("utf-8", "replace").split("\0") if name]


class NoTokenLiterals(unittest.TestCase):
    def test_no_tracked_file_holds_a_credential_shaped_literal(self):
        found = []
        for name in tracked_files():
            path = os.path.join(ROOT, name)
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except (IsADirectoryError, FileNotFoundError):
                continue
            for kind, pattern in PATTERNS.items():
                for match in pattern.finditer(text):
                    if match.group(0) not in ALLOWED:
                        line = text.count("\n", 0, match.start()) + 1
                        found.append("%s:%d %s" % (name, line, kind))
        self.assertEqual(found, [], "build these at runtime instead, e.g. \"xoxb-\" + \"...\"")

    def test_the_check_would_have_caught_the_push_that_was_refused(self):
        """The control: the exact literal GitHub refused must match."""
        refused = "xoxb-" + "2417283945-2417283945-KJh2kJh34kJh234kJh234kJ"
        self.assertTrue(PATTERNS["Slack token"].search(refused))


if __name__ == "__main__":
    unittest.main()
