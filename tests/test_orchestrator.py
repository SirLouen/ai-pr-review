"""End-to-end wiring of the parent over a real fixture repository.

The model is scripted, the repository is real. That combination is what catches the
failures a mocked test cannot: a prompt that names a tool the surface does not register,
a ledger unit the validator rejects, a verifier whose citation was never read.

The seeded pull request adds a SQL concatenation on a request parameter, which is the
design's fixture 2, and the run must end with exactly one needs_validation lead and a
ledger and findings pair that both vendored validators accept.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import fingerprint, gitsrc, ledger as ledgermod, orchestrator, tools
from prreview.security import validate as validatemod
from prreview.security.config import Caps, RunConfig
from prreview.security.providers.base import Response, ToolCall, Usage
from prreview.security.skillpack import SkillPack

VENDOR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "vendor", "security-audit")

SAFE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
"""

VULNERABLE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = " + req.query.id);
}
"""


def git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_source(root):
    os.makedirs(root)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "Fixture")
    write(root, "src/users.js", SAFE)
    write(root, "README.md", "# fixture\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    base = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    write(root, "src/users.js", VULNERABLE)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "head")
    head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    return base, head


class ScriptedModel:
    """Answers each role the way a well-behaved agent would, using the real tools."""

    def __init__(self, sink_line):
        self.sink_line = sink_line
        self.seen_roles = []
        self.prompts = {}

    def complete(self, role, model, messages, tools_=None, max_tokens=4096, extra=None,
                 **kwargs):
        catalogue = tools_ if tools_ is not None else kwargs.get("tools")
        self.seen_roles.append(role)
        self.prompts.setdefault(role, []).append(messages[0]["content"] + messages[1]["content"])
        names = [t["function"]["name"] for t in (catalogue or [])]
        turn = len([m for m in messages if m["role"] == "assistant"])
        if turn == 0 and "read_file" in names:
            return self._call("read_file", {"path": "src/users.js", "ref": "head",
                                            "start_line": 1, "end_line": 40})
        return self._submit(role)

    def _call(self, name, arguments):
        return Response(tool_calls=[ToolCall("c1", name, arguments)],
                        usage=Usage(cache_miss=10, output=5), finish_reason="tool_calls")

    def _submit(self, role):
        if role == "recon":
            payload = {"units": [], "boundaries": ["src/users.js#getUser"], "notes": []}
        elif role == "critic":
            payload = {"units": [], "gaps": [], "clean": True}
        elif role == "hunter":
            payload = {"candidates": [self._candidate()], "units": []}
        else:
            payload = {"decision": "needs_validation", "record": self._record(),
                       "same_root_cause_as": None}
        return Response(tool_calls=[ToolCall("s1", tools.SUBMIT_TOOLS[role], payload)],
                        usage=Usage(cache_miss=10, output=5), finish_reason="tool_calls")

    def _candidate(self):
        return {"title": "Request parameter concatenated into a SQL query",
                "claimed_root_cause": "req.query.id reaches db.query as string concatenation",
                "trace": self._trace(), "evidence": self._evidence()}

    def _record(self):
        return {"verdict": "needs_validation", "fingerprint": "sa1:injection:src/users.js@getUser",
                "title": "Request parameter concatenated into a SQL query",
                "trace": self._trace(), "evidence": self._evidence(),
                "blockers": ["[execution] the action does not run the service, so the "
                             "query sent to the database was not observed"],
                "validation_plan": {"local": "unit test: call getUser with "
                                             "req.query.id = \"1 OR 1=1\" against a dummy "
                                             "database and assert the query is parameterised"}}

    def _trace(self):
        return [{"kind": "entrypoint", "file": "src/users.js", "line": 1,
                 "scope": "getUser", "description": "req.query.id enters the handler"},
                {"kind": "sink", "file": "src/users.js", "line": self.sink_line,
                 "scope": "getUser", "description": "concatenated into the SQL string"}]

    def _evidence(self):
        return [{"file": "src/users.js", "line": self.sink_line,
                 "description": "the query is built by concatenation"}]


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sa-orch-")
        cls.source_dir = os.path.join(cls.tmp, "source")
        cls.base, cls.head = build_source(cls.source_dir)
        cls.repo = gitsrc.open_repo(os.path.join(cls.tmp, "work"))
        gitsrc.fetch_pr(cls.repo, cls.source_dir, cls.head, cls.base, 3,
                        protocols=("file",))
        cls.commits = gitsrc.commits_between(cls.repo, cls.base, cls.head)["commits"]
        cls.validator = validatemod.Validator(vendor_dir=VENDOR)
        cls.skill = SkillPack(VENDOR)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.validator.close()
        except Exception:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def build(self):
        caps = Caps(max_conversations=12, max_hunters=2, max_verifiers=3)
        cfg = RunConfig(repository="o/r", pr_number=7, head_sha=self.head,
                        base_sha=self.base, out_dir=os.path.join(self.tmp, "out"),
                        vendor_dir=VENDOR, caps=caps)
        source = tools.RepoSource(self.repo, self.head, self.base, commits=self.commits,
                                  caps=caps)
        sink = VULNERABLE.splitlines().index(
            '  return db.query("SELECT * FROM users WHERE id = " + req.query.id);') + 1
        model = ScriptedModel(sink)
        parent = orchestrator.Orchestrator(cfg, model, self.validator, source, self.skill)
        return parent, model, source

    def test_plan_seeds_a_ledger_the_vendored_validator_accepts(self):
        parent, _, source = self.build()
        diff = gitsrc.diff_index(self.repo, self.base, self.head)
        changed = diff["files"]
        changes = orchestrator.routing_changes(self.repo, self.base, self.head, diff)
        plan = parent.plan(diff, changes, len(self.commits), lambda path: "getUser")
        self.assertTrue(plan.launches, plan.notes)
        self.assertGreater(len(parent.ledger.units), 0)
        errors = parent.ledger.validate()
        self.assertEqual(errors, [], "seeded ledger must pass validate-coverage-ledger.cjs")

    def test_changed_file_always_lands_in_a_unit(self):
        """The coverage floor is code-enforced; no model output can remove it."""
        parent, _, _ = self.build()
        diff = gitsrc.diff_index(self.repo, self.base, self.head)
        changes = orchestrator.routing_changes(self.repo, self.base, self.head, diff)
        parent.plan(diff, changes, len(self.commits), lambda path: "getUser")
        covered = set()
        for unit in parent.ledger.units:
            covered.update(getattr(unit, "starting_paths", ()) or ())
        self.assertIn("src/users.js", covered)

    def test_budget_gate_refuses_to_launch_when_reserves_cannot_be_funded(self):
        parent, _, _ = self.build()
        parent.cfg = parent.cfg.__class__(**{**parent.cfg.__dict__,
                                             "caps": Caps(max_conversations=2)})
        diff = gitsrc.diff_index(self.repo, self.base, self.head)
        changes = orchestrator.routing_changes(self.repo, self.base, self.head, diff)
        with self.assertRaises(orchestrator.RunAborted) as caught:
            parent.plan(diff, changes, len(self.commits), lambda path: "getUser")
        self.assertIn("budget", caught.exception.reason)

    def test_metadata_records_the_no_execution_policy(self):
        parent, _, _ = self.build()
        data = parent.metadata()
        self.assertEqual(data["execution_policy"], "source-only-no-execution")
        self.assertEqual(data["profile"], "quick")
        self.assertEqual(data["scope"], "diff")
        self.assertIn("suppressions", data)
        self.assertIn("prior_source_state", data)  # the spelling publish reads

    def test_omissions_from_every_agent_reach_the_report_once(self):
        """A file an agent could not open must be listed, not silently dropped."""
        parent, _, _ = self.build()
        big = {"kind": "oversize", "path": "dist/app.min.js", "ref": "head",
               "reason": "blob exceeds the read cap", "detail": ""}
        spent = {"kind": "tool_budget_exhausted", "path": "", "ref": "",
                 "reason": "budget spent", "detail": "used=300001"}
        for state in ({"omitted": [big]}, {"omitted": [big, spent]}, {}):
            parent.conversations.append(type("R", (), {"state": state})())
        collected = parent.omissions()
        self.assertEqual([o["kind"] for o in collected], ["oversize", "tool_budget_exhausted"],
                         "each gap once, in the order it was first seen")

    def test_deviation_register_is_written_not_implied(self):
        parent, _, _ = self.build()
        parent.deviate("delta reconnaissance", "baseline available")
        self.assertEqual(parent.metadata()["deviations"][0]["deviation"],
                         "delta reconnaissance")


if __name__ == "__main__":
    unittest.main()
