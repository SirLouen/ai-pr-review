"""Tests for the deterministic seeders.

The secret fixtures below are syntactically valid but inert: the AWS id, tokens and
key material are well-known documentation samples or random-looking filler, and none of
them authenticates to anything.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import fingerprint as fp  # noqa: E402
from prreview.security import seeders  # noqa: E402

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"[:16]
AWS_SECRET = "kP8q2Vt7ZsD4mR1xJ0nB6wYc3LfH5gUa9EiOyTdM"
GH_TOKEN = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
SLACK = "xoxb-" + "2417283945-2417283945-KJh2kJh34kJh234kJh234kJ"

CONFIG_WITH_SECRET = """\
import os


def load_client():
    region = os.environ["AWS_REGION"]
    aws_secret_access_key = "%s"
    return connect(region, aws_secret_access_key)
""" % AWS_SECRET

CONFIG_CLEAN = """\
import os


def load_client():
    region = os.environ["AWS_REGION"]
    aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    return connect(region, aws_secret_access_key)
"""

PLACEHOLDERS = """\
API_KEY = "your-api-key-here"
password = "changeme-please-xxxx"
token = "${VAULT_TOKEN_PLACEHOLDER}"
client_secret = "process.env.CLIENT_SECRET"
db_password = "aaaaaaaaaaaaaaaaaaaaaa"
"""

PRIVILEGED_CHECKOUT_WORKFLOW = """\
name: pr-build
on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  contents: read
  pull-requests: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
"""

BENIGN_NO_CHECKOUT_WORKFLOW = """\
name: label
on:
  pull_request_target:
    types: [opened]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
"""

BENIGN_BASE_CHECKOUT_WORKFLOW = """\
name: base-only
on:
  pull_request_target:
    types: [opened]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm audit
"""

UNPRIVILEGED_HEAD_CHECKOUT_WORKFLOW = """\
name: pr
on: pull_request

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
"""

EXPRESSION_INJECTION_WORKFLOW = """\
name: triage
on:
  issue_comment:
    types: [created]
  workflow_run:
    workflows: [ci]
    types: [completed]

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: echo the title
        run: |
          echo "Issue: ${{ github.event.issue.title }}"
          gh issue comment --body "seen"
"""

BENIGN_ENV_INDIRECTION_WORKFLOW = """\
name: triage-safe
on:
  workflow_run:
    workflows: [ci]
    types: [completed]

jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - name: echo safely
        env:
          PR_NUMBER: ${{ github.event.number }}
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "PR $PR_NUMBER"
          echo "Title: $TITLE"
      - name: numeric field is not free text
        run: echo "pr ${{ github.event.number }}"
"""


def blob(commit, path, text, is_head=False):
    return {"commit": commit, "path": path, "text": text, "is_head": is_head}


class SecretScanTest(unittest.TestCase):
    def test_secret_added_then_removed_is_still_caught(self):
        blobs = [blob("c1", "src/config.py", CONFIG_WITH_SECRET),
                 blob("c2", "src/config.py", CONFIG_WITH_SECRET),
                 blob("c3", "src/config.py", CONFIG_CLEAN, is_head=True)]
        drafts = seeders.scan_secrets(blobs)
        self.assertEqual(1, len(drafts))
        draft = drafts[0]
        self.assertEqual("credential-assignment", draft["rule_id"])
        self.assertEqual(("c1", "c2"), draft["commits"])
        self.assertFalse(draft["present_at_head"])
        self.assertIn("later removed", draft["summary"])

    def test_head_only_scan_misses_it(self):
        """The per-commit walk is the control; scanning head alone reproduces the miss."""
        head_only = seeders.scan_secrets(
            [blob("c3", "src/config.py", CONFIG_CLEAN, is_head=True)])
        self.assertEqual((), head_only)

    def test_one_draft_per_credential_across_commits(self):
        blobs = [blob("c%d" % n, "src/config.py", CONFIG_WITH_SECRET) for n in range(5)]
        self.assertEqual(1, len(seeders.scan_secrets(blobs)))

    def test_high_signal_patterns(self):
        cases = {
            "aws-access-key-id": 'KEY = "%s"' % AWS_KEY,
            "github-token": 'tok = "%s"' % GH_TOKEN,
            "slack-token": 'slack = "%s"' % SLACK,
            "private-key-block": "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n",
        }
        for rule_id, text in cases.items():
            with self.subTest(rule_id):
                drafts = seeders.scan_secrets([blob("c1", "src/x.py", text, True)])
                self.assertIn(rule_id, {d["rule_id"] for d in drafts})

    def test_placeholders_and_env_indirection_are_not_flagged(self):
        drafts = seeders.scan_secrets([blob("c1", "src/settings.py", PLACEHOLDERS, True)])
        self.assertEqual((), drafts)

    def test_entropy_gate_rejects_a_prose_value(self):
        low = 'password = "passwordpasswordpassword"'
        high = 'password = "%s"' % AWS_SECRET
        self.assertEqual((), seeders.scan_secrets([blob("c1", "a.py", low, True)]))
        self.assertEqual(1, len(seeders.scan_secrets([blob("c1", "a.py", high, True)])))

    def test_generic_rule_is_suppressed_in_lockfiles_only(self):
        text = 'integrity_token = "%s"' % AWS_SECRET
        self.assertEqual((), seeders.scan_secrets(
            [blob("c1", "package-lock.json", text, True)]))
        self.assertEqual(1, len(seeders.scan_secrets(
            [blob("c1", "src/config.py", text, True)])))

    def test_fixed_prefix_rules_still_fire_in_a_lockfile(self):
        text = '"resolved": "https://x/%s"' % GH_TOKEN
        drafts = seeders.scan_secrets([blob("c1", "package-lock.json", text, True)])
        self.assertEqual(["github-token"], [d["rule_id"] for d in drafts])

    def test_inline_allowlist_markers_are_not_honoured(self):
        text = 'password = "%s"  # pragma: allowlist secret gitleaks:allow' % AWS_SECRET
        self.assertEqual(1, len(seeders.scan_secrets([blob("c1", "a.py", text, True)])))

    def test_the_secret_value_never_appears_in_the_draft(self):
        drafts = seeders.scan_secrets([blob("c1", "src/config.py",
                                            CONFIG_WITH_SECRET, True)])
        payload = json.dumps(drafts)
        self.assertNotIn(AWS_SECRET, payload)
        self.assertEqual(len(AWS_SECRET), drafts[0]["value_length"])
        self.assertEqual(16, len(drafts[0]["value_sha256"]))

    def test_symbol_is_resolved_from_head_when_still_present(self):
        drafts = seeders.scan_secrets([blob("c1", "src/config.py",
                                            CONFIG_WITH_SECRET, True)])
        self.assertEqual("load_client", drafts[0]["symbol"])


class SecretScanGitFixtureTest(unittest.TestCase):
    """Proves the in-memory blob interface matches what real git history produces."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("git") is None:
            raise unittest.SkipTest("git is not installed")
        cls.repo = tempfile.mkdtemp(prefix="sa-seeder-")


        def run(*args):
            return subprocess.run(("git",) + args, cwd=cls.repo, check=True,
                                  capture_output=True, text=True)

        run("init", "-q", "-b", "main")
        run("config", "user.email", "t@example.invalid")
        run("config", "user.name", "t")
        cls._write("src/config.py", CONFIG_CLEAN)
        run("add", "-A")
        run("commit", "-qm", "base")
        cls.base = run("rev-parse", "HEAD").stdout.strip()
        cls._write("src/config.py", CONFIG_WITH_SECRET)
        run("add", "-A")
        run("commit", "-qm", "oops")
        cls._write("src/config.py", CONFIG_CLEAN)
        run("add", "-A")
        run("commit", "-qm", "revert")
        cls.head = run("rev-parse", "HEAD").stdout.strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.repo, ignore_errors=True)

    @classmethod
    def _write(cls, rel, text):
        full = os.path.join(cls.repo, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(text)

    def _git(self, *args):
        return subprocess.run(("git",) + args, cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout

    def test_base_to_head_diff_does_not_contain_the_secret(self):
        diff = self._git("diff", "%s..%s" % (self.base, self.head))
        self.assertNotIn(AWS_SECRET, diff)

    def test_per_commit_walk_finds_it(self):
        shas = self._git("rev-list", "--reverse",
                         "%s..%s" % (self.base, self.head)).split()
        blobs = []
        for index, sha in enumerate(shas):
            text = self._git("show", "%s:src/config.py" % sha)
            blobs.append(blob(sha, "src/config.py", text,
                              is_head=index == len(shas) - 1))
        drafts = seeders.scan_secrets(blobs)
        self.assertEqual(1, len(drafts))
        self.assertFalse(drafts[0]["present_at_head"])
        self.assertEqual((shas[0],), drafts[0]["commits"])


class WorkflowSeederTest(unittest.TestCase):
    def test_privileged_trigger_with_head_checkout_is_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/pr.yml",
              "text": PRIVILEGED_CHECKOUT_WORKFLOW}])
        kinds = {d["seeder"] for d in drafts}
        self.assertIn("actions-privileged-checkout", kinds)
        hit = next(d for d in drafts if d["seeder"] == "actions-privileged-checkout")
        self.assertEqual("build", hit["job"])
        self.assertEqual("jobs.build", hit["symbol"])
        self.assertEqual(("pull_request_target",), hit["triggers"])
        self.assertEqual(16, hit["line"])

    def test_privileged_trigger_without_a_checkout_is_not_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/label.yml",
              "text": BENIGN_NO_CHECKOUT_WORKFLOW}])
        self.assertEqual((), drafts)

    def test_checkout_of_the_base_is_not_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/audit.yml",
              "text": BENIGN_BASE_CHECKOUT_WORKFLOW}])
        self.assertEqual((), drafts)

    def test_head_checkout_under_an_unprivileged_trigger_is_not_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/pr.yml",
              "text": UNPRIVILEGED_HEAD_CHECKOUT_WORKFLOW}])
        self.assertEqual((), drafts)

    def test_expression_injection_in_a_run_block_is_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/triage.yml",
              "text": EXPRESSION_INJECTION_WORKFLOW}])
        self.assertEqual(1, len(drafts))
        hit = drafts[0]
        self.assertEqual("actions-expression-injection", hit["seeder"])
        self.assertEqual("jobs.comment", hit["symbol"])
        self.assertIn("github.event.issue.title", hit["evidence"])
        self.assertEqual(("workflow_run",), hit["triggers"])

    def test_untrusted_field_in_env_and_numeric_field_in_run_are_not_flagged(self):
        drafts = seeders.scan_workflows(
            [{"path": ".github/workflows/safe.yml",
              "text": BENIGN_ENV_INDIRECTION_WORKFLOW}])
        self.assertEqual((), drafts)

    def test_every_draft_is_routed_to_a_verifier_and_carries_no_verdict(self):
        drafts = seeders.run(
            commit_blobs=[blob("c1", "src/config.py", CONFIG_WITH_SECRET, True)],
            workflows=[{"path": ".github/workflows/pr.yml",
                        "text": PRIVILEGED_CHECKOUT_WORKFLOW},
                       {"path": ".github/workflows/triage.yml",
                        "text": EXPRESSION_INJECTION_WORKFLOW}])
        self.assertEqual(3, len(drafts))
        for draft in drafts:
            self.assertEqual("draft_candidate", draft["kind"])
            self.assertTrue(draft["requires_verification"])
            self.assertIn("not a finding", draft["note"])
            self.assertFalse({"severity", "verdict", "decision", "confirmed"}
                             & set(draft))

    def test_two_credentials_in_one_function_collapse_to_one_draft(self):
        """Duplicate fingerprints would fail the vendored validator for the whole run."""
        text = ('def load():\n'
                '    aws_key = "%s"\n'
                '    gh_token = "%s"\n' % (AWS_KEY, GH_TOKEN))
        drafts = seeders.scan_secrets([blob("c1", "src/config.py", text, True)])
        self.assertEqual(1, len(drafts))
        self.assertEqual(("aws-access-key-id", "credential-assignment",
                          "github-token"), drafts[0]["rule_ids"])
        self.assertEqual((2, 3), drafts[0]["lines"])
        self.assertEqual(3, drafts[0]["merged_count"])

    def test_credentials_in_different_functions_stay_separate(self):
        """Guards the merge above against collapsing unrelated sinks."""
        text = ('def one():\n'
                '    aws_key = "%s"\n'
                '\n'
                'def two():\n'
                '    gh_token = "%s"\n' % (AWS_KEY, GH_TOKEN))
        drafts = seeders.scan_secrets([blob("c1", "src/config.py", text, True)])
        self.assertEqual(2, len(drafts))
        self.assertEqual(2, len({d["fingerprint"] for d in drafts}))

    def test_all_fingerprints_in_a_run_are_unique(self):
        drafts = seeders.run(
            commit_blobs=[blob("c1", "src/config.py", CONFIG_WITH_SECRET, True)],
            workflows=[{"path": ".github/workflows/pr.yml",
                        "text": PRIVILEGED_CHECKOUT_WORKFLOW},
                       {"path": ".github/workflows/triage.yml",
                        "text": EXPRESSION_INJECTION_WORKFLOW}])
        prints = [d["fingerprint"] for d in drafts]
        self.assertEqual(len(prints), len(set(prints)))

    def test_drafts_are_ordered_deterministically(self):
        args = dict(commit_blobs=[blob("c1", "src/config.py", CONFIG_WITH_SECRET, True)],
                    workflows=[{"path": ".github/workflows/triage.yml",
                                "text": EXPRESSION_INJECTION_WORKFLOW}])
        self.assertEqual(seeders.run(**args), seeders.run(**args))


class OneFingerprintSchemeTest(unittest.TestCase):
    """A seeded and a hunted candidate for one root cause must collapse to one record."""

    def test_every_seeder_fingerprint_uses_the_sa1_scheme(self):
        drafts = seeders.run(
            commit_blobs=[blob("c1", "src/config.py", CONFIG_WITH_SECRET, True)],
            workflows=[{"path": ".github/workflows/pr.yml",
                        "text": PRIVILEGED_CHECKOUT_WORKFLOW},
                       {"path": ".github/workflows/triage.yml",
                        "text": EXPRESSION_INJECTION_WORKFLOW}])
        for draft in drafts:
            self.assertTrue(draft["fingerprint"].startswith("sa1:"), draft["fingerprint"])
            self.assertRegex(draft["fingerprint"], fp.PATTERN)
            self.assertEqual(draft["class_ref"],
                             fp.parse(draft["fingerprint"])["class_ref"])

    def test_seeded_and_hunted_secret_collapse(self):
        seeded = seeders.scan_secrets(
            [blob("c1", "src/config.py", CONFIG_WITH_SECRET, True)])[0]
        # A hunter reaches the same root cause from a different line of the same
        # function: the line where the credential is passed on.
        hunted = fp.for_sink(seeders.CRYPTO_SECRETS, "src/config.py",
                             CONFIG_WITH_SECRET, 7)
        self.assertNotEqual(seeded["line"], 7, "citations must be different lines")
        self.assertEqual(seeded["fingerprint"], hunted)

    def test_seeded_and_hunted_workflow_candidate_collapse(self):
        seeded = seeders.scan_workflows(
            [{"path": ".github/workflows/pr.yml",
              "text": PRIVILEGED_CHECKOUT_WORKFLOW}])[0]
        # The hunter cites the `run:` line that consumes the checked-out code.
        hunted = fp.for_sink(seeders.CI_UNTRUSTED_CODE, ".github/workflows/pr.yml",
                             PRIVILEGED_CHECKOUT_WORKFLOW, 17)
        self.assertNotEqual(seeded["line"], 17)
        self.assertEqual(seeded["fingerprint"], hunted)
        self.assertEqual("sa1:supply.ci-untrusted-code:"
                         ".github/workflows/pr.yml@jobs.build", seeded["fingerprint"])

    def test_a_different_job_in_the_same_file_does_not_collapse(self):
        """Guards the collapse tests against a resolver that ignores the location."""
        two_jobs = PRIVILEGED_CHECKOUT_WORKFLOW + (
            "  publish:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: npm publish\n")
        in_build = fp.for_sink(seeders.CI_UNTRUSTED_CODE, ".github/workflows/pr.yml",
                               two_jobs, 17)
        in_publish = fp.for_sink(seeders.CI_UNTRUSTED_CODE, ".github/workflows/pr.yml",
                                 two_jobs, 23)
        self.assertNotEqual(in_build, in_publish)
        self.assertTrue(in_publish.endswith("@jobs.publish"), in_publish)

    def test_seeded_fingerprint_survives_a_workflow_rename(self):
        seeded = seeders.scan_workflows(
            [{"path": ".github/workflows/pr.yml",
              "text": PRIVILEGED_CHECKOUT_WORKFLOW}])[0]["fingerprint"]
        renames = fp.rename_map([{"path": ".github/workflows/build.yml",
                                  "previous_path": ".github/workflows/pr.yml"}])
        moved = seeders.scan_workflows(
            [{"path": ".github/workflows/build.yml",
              "text": PRIVILEGED_CHECKOUT_WORKFLOW}])[0]["fingerprint"]
        self.assertEqual(moved, renames.translate(seeded))


if __name__ == "__main__":
    unittest.main()
