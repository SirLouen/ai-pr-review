"""Every third-party action is pinned to a full commit SHA.

A tag like `@v4` can be moved by whoever controls that repository, and these actions run
beside a model key and a write token. A floating reference would let a compromised
upstream replace the code that handles both.
"""
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.M)
PINNED_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")
# The only references allowed to stay unpinned: this repository's own actions, whose
# release commit does not exist until it is published.
SELF = "SirLouen/ai-pr-review/"


def references(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    return [m.group(1) for m in USES_RE.finditer(text)
            if not m.group(0).lstrip().startswith("#")]


class Pins(unittest.TestCase):
    def test_every_action_in_this_repo_pins_a_commit(self):
        files = glob.glob(os.path.join(ROOT, "security", "*", "action.yml"))
        files.append(os.path.join(ROOT, "action.yml"))
        self.assertGreaterEqual(len(files), 4)
        for path in files:
            for ref in references(path):
                self.assertRegex(ref, PINNED_RE, "%s uses an unpinned %s"
                                 % (os.path.relpath(path, ROOT), ref))

    def test_the_example_workflow_leaves_only_its_own_actions_unpinned(self):
        path = os.path.join(ROOT, ".github", "workflows", "security-review.example.yml")
        for ref in references(path):
            if ref.startswith(SELF):
                continue
            self.assertRegex(ref, PINNED_RE, "example workflow uses an unpinned %s" % ref)

    def test_the_check_rejects_a_floating_tag(self):
        """The control only matters if it fires."""
        self.assertNotRegex("actions/upload-artifact@v7", PINNED_RE)
        self.assertNotRegex("actions/upload-artifact@<sha>", PINNED_RE)
        self.assertRegex("actions/upload-artifact@" + "0" * 40, PINNED_RE)


if __name__ == "__main__":
    unittest.main()
