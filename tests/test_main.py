"""The CLI over a real fixture repository, a scripted model and a stub GitHub API.

Nothing here is mocked below the driver: the git object store, the vendored validators,
the node bridge, the ledger and the renderer are all the real ones. That is what makes
these tests catch the failures a mocked driver cannot -- a bundle the publish job cannot
load, a digest that does not match, a phase called with the wrong shape.

The YAML tests are text-structural on purpose: the runner has no yaml module, and the two
properties that actually matter (the analyze job never gets a write scope, the publish job
never gets a model key) are properties of the text a maintainer reads.
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import __main__ as cli
from prreview.security import fingerprint as fp
from prreview.security import github as githubmod
from prreview.security import gitsrc, publish as publishmod, tools
from prreview.security import validate as validatemod
from prreview.security.providers.base import Response, ToolCall, Usage
from tests import fakehub

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "vendor", "security-audit")
ACTIONS = {name: os.path.join(ROOT, "security", name, "action.yml")
           for name in ("analyze", "publish", "baseline")}
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "security-review.example.yml")

SAFE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
"""

VULNERABLE = """export function getUser(db, req) {
  return db.query("SELECT * FROM users WHERE id = " + req.query.id);
}
"""

SINK_LINE = 2
FINGERPRINT_RE = re.compile(r"sa1:[A-Za-z0-9._\-]+:[^\s\"'`,\\]+@[^\s\"'`,\\]+")


# --------------------------------------------------------------------------- fixtures

def git(root, *args):
    subprocess.run(["git", "-C", root] + list(args), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(root, path, text):
    full = os.path.join(root, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as handle:
        handle.write(text)


def rev(root):
    return subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()


def build_source(root):
    os.makedirs(root)
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.invalid")
    git(root, "config", "user.name", "Fixture")
    write(root, "src/users.js", SAFE)
    write(root, "README.md", "# fixture\n")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base")
    base = rev(root)
    write(root, "src/users.js", VULNERABLE)
    git(root, "add", "-A")
    git(root, "commit", "-qm", "head")
    return base, rev(root)


class StubHub:
    """The calls the driver makes: PR facts before fetching, then the prior-run lookup.

    `artifacts` is empty by default, which is a first run on this pull request.
    """

    def __init__(self, base, head, private=False, changed_files=1, additions=1,
                 deletions=1, artifacts=()):
        self.base = base
        self.head = head
        self.private = private
        self.numbers = (changed_files, additions, deletions)
        self.artifacts = list(artifacts)
        self.calls = []

    def list_artifacts(self, repo, page=1, per_page=100):
        self.calls.append(("list_artifacts", repo, page))
        return {"total_count": len(self.artifacts),
                "artifacts": self.artifacts if page == 1 else []}

    def get_run(self, repo, run_id):
        raise AssertionError("no artifacts, so no run should be looked up")

    def download_artifact(self, repo, artifact_id, max_bytes):
        raise AssertionError("no artifacts, so nothing should be downloaded")

    def pull_request(self, repo, number):
        self.calls.append(("pull_request", repo, number))
        files, additions, deletions = self.numbers
        return {"number": number, "head": {"sha": self.head},
                "base": {"sha": self.base, "repo": {"private": self.private}},
                "changed_files": files, "additions": additions, "deletions": deletions,
                "commits": 2}

    def get(self, path):
        self.calls.append(("get", path))
        return {"merge_base_commit": {"sha": self.base}}


class ScriptedModel:
    """Answers each role the way a well-behaved agent would, using the real tools.

    The verifier reads its assigned fingerprint out of its own prompt, exactly as a real
    model must: the parent assembles fingerprints and a result cannot choose its own.
    """

    def __init__(self, fail_role=None):
        self.fail_role = fail_role
        self.roles = []
        self.prompts = {}

    def complete(self, role, model, messages, tools_=None, max_tokens=4096, extra=None,
                 **kwargs):
        catalogue = tools_ if tools_ is not None else kwargs.get("tools")
        self.roles.append(role)
        blob = "".join(m.get("content") or "" for m in messages if isinstance(m, dict))
        self.prompts.setdefault(role, []).append(blob)
        if role == self.fail_role:
            raise RuntimeError("scripted %s failure" % role)
        names = [t["function"]["name"] for t in (catalogue or [])]
        turn = len([m for m in messages if m.get("role") == "assistant"])
        if turn == 0 and "read_file" in names:
            return self._call("read_file", {"path": "src/users.js", "ref": "head",
                                            "start_line": 1, "end_line": 40})
        return self._submit(role, blob)

    def _call(self, name, arguments):
        return Response(tool_calls=[ToolCall("c1", name, arguments)],
                        usage=Usage(cache_miss=10, output=5), finish_reason="tool_calls")

    def _submit(self, role, blob):
        if role == "recon":
            # The typed facts the recon prompt asks for. The old fake sent the tool's
            # former three-field shape, which is how the prompt and tool disagreeing on
            # recon's output went unnoticed.
            payload = {"principals": [{"name": "anonymous HTTP client",
                                       "authority": "calls getUser",
                                       "path": "src/users.js", "line": 1}],
                       "boundaries": [{"name": "request to database",
                                       "control": "query parameterisation",
                                       "path": "src/users.js", "line": 2}],
                       "entry_surfaces": [{"surface": "req.query.id", "kind": "HTTP query",
                                           "path": "src/users.js", "line": 1}],
                       "starting_paths": ["src/users.js"]}
        elif role == "critic":
            payload = {"units": [], "gaps": [], "clean": True}
        elif role == "hunter":
            # A hunter accounts for every unit it was assigned, so the script reads its
            # own assignment back out of the prompt rather than inventing one. A fake
            # that skips this hides exactly the contract breaches the gate exists for.
            payload = {"candidates": [candidate()],
                       "units": [hunted_unit(cid) for cid in assigned_units(blob)]}
        else:
            record = finding(assigned(blob) or candidate()["fingerprint"])
            payload = {"decision": "needs_validation", "record": record,
                       "same_root_cause_as": None}
        return Response(tool_calls=[ToolCall("s1", tools.SUBMIT_TOOLS[role], payload)],
                        usage=Usage(cache_miss=10, output=5), finish_reason="tool_calls")


UNIT_ID_RE = re.compile(r'"coverage_id":\s*"([^"]+)"')


def assigned_units(blob):
    """The coverage ids the parent put in this hunter's prompt, in order."""
    seen, ordered = set(), []
    for cid in UNIT_ID_RE.findall(blob or ""):
        if cid not in seen:
            seen.add(cid)
            ordered.append(cid)
    return ordered


def hunted_unit(coverage_id):
    """A candidate unit with the evidence the ledger requires of one."""
    return {"coverage_id": coverage_id, "status": "candidate", "agent_id": "hunter-1",
            "reviewed_paths": ["src/users.js"],
            "local_checks": [{"agent_id": "hunter-1", "method": "source", "artifact": None,
                              "invariant": "the id reaches the query parameterised",
                              "result": "it is concatenated into the SQL string",
                              "reviewed_paths": ["src/users.js"]}],
            "result_fingerprints": [candidate()["fingerprint"]], "unresolved": []}


def assigned(blob):
    match = FINGERPRINT_RE.search(blob or "")
    return match.group(0) if match else ""


def trace():
    return [{"kind": "entrypoint", "file": "src/users.js", "line": 1, "scope": "getUser",
             "description": "req.query.id enters the handler"},
            {"kind": "sink", "file": "src/users.js", "line": SINK_LINE, "scope": "getUser",
             "description": "concatenated into the SQL string"}]


def evidence():
    return [{"file": "src/users.js", "line": SINK_LINE,
             "description": "the query is built by concatenation"}]


def candidate():
    return {"proposed_verdict": "needs_validation",
            "fingerprint": "sa1:injection:src/users.js@getUser",
            "title": "Request parameter concatenated into a SQL query",
            "description": "An attacker controls the WHERE clause of a user lookup.",
            "claimed_root_cause": "req.query.id reaches db.query as string concatenation",
            "trace": trace(), "evidence": evidence(),
            "blockers": ["[execution] the action does not run the service, so the query "
                         "sent to the database was not observed"],
            # Both keys: the strict tool schema carries no optionality, so a field that
            # does not apply is sent as null rather than omitted.
            "validation_plan": {"local": "unit test: call getUser with req.query.id = "
                                         "\"1 OR 1=1\" and assert the query is "
                                         "parameterised",
                                "deployment": None},
            "reason": None, "coverage_id": "u1"}


def finding(fingerprint, verdict="needs_validation"):
    """A verifier record exactly as a model must send it.

    Every property the strict schema declares is present, with null where it does not
    apply. Stripping the nulls here would be modelling the wrong end of the contract:
    the tool surface strips them on the way in, after checking the shape it was given.
    """
    record = candidate()
    record.pop("coverage_id")
    record["verdict"] = record.pop("proposed_verdict")
    record["fingerprint"] = fingerprint
    if verdict == "rejected":
        record["verdict"] = "rejected"
        record["blockers"] = None
        record["validation_plan"] = None
        record["reason"] = "the query is parameterised after all"
    declared = tools.SUBMIT_SCHEMAS["submit_verdict"]["properties"]["record"]["properties"]
    for key in declared:
        record.setdefault(key, None)
    return record


def hunter_records():
    """What `_extract` hands the parent for one hunter candidate."""
    record = candidate()
    record["verdict"] = record.pop("proposed_verdict")
    record.pop("coverage_id")
    return [{key: value for key, value in record.items() if value is not None}]


class FakeResult:
    def __init__(self, payload):
        self.result = payload


def unit_payload(assignment, coverage_id):
    """One coverage unit as a hunter submits it: the seven keys the surface accepts."""
    return {"coverage_id": coverage_id, "status": "candidate",
            "agent_id": assignment.agent_id, "reviewed_paths": ["src/users.js"],
            "local_checks": [{"agent_id": assignment.agent_id,
                              "invariant": "the query is parameterised",
                              "method": "source",
                              "result": "it is built by concatenation",
                              "reviewed_paths": ["src/users.js"], "artifact": None}],
            "result_fingerprints": [], "unresolved": []}


# ------------------------------------------------------------------------ base case

class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sa-main-")
        cls.source_dir = os.path.join(cls.tmp, "source")
        cls.base, cls.head = build_source(cls.source_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def env(self, out_dir, **overrides):
        env = {"SA_REPOSITORY": "octo/demo", "SA_PR_NUMBER": "7",
               "SA_HEAD_SHA": self.head, "SA_BASE_SHA": self.base,
               "SA_OUT_DIR": out_dir, "SA_VENDOR_DIR": VENDOR,
               "SA_MAX_CONVERSATIONS": "12", "SA_MAX_HUNTERS": "2",
               "SA_MAX_VERIFIERS": "3", "DEEPSEEK_API_KEY": "not-a-real-key",
               # No SA_GITHUB_TOKEN: the fixture remote is a local path, and gitsrc
               # refuses to hand a token to anything that is not https.
               "PATH": os.environ.get("PATH", "")}
        env.update(overrides)
        return env

    def services(self, model=None, gh=None):
        return cli.Services(provider=model or ScriptedModel(),
                            gh=gh or StubHub(self.base, self.head),
                            remote_url=self.source_dir, protocols=("file",))

    def run_analyze(self, model=None, gh=None, argv=("analyze",), out_dir=None):
        out_dir = out_dir or tempfile.mkdtemp(prefix="sa-out-", dir=self.tmp)
        env = self.env(out_dir)
        code = cli.main(list(argv), env=env, services=self.services(model, gh))
        return code, os.path.join(out_dir, "bundle")

    def metadata(self, bundle_dir):
        with open(os.path.join(bundle_dir, "run-metadata.json"), encoding="utf-8") as fh:
            return json.load(fh)


class TestArguments(unittest.TestCase):
    def parse(self, argv):
        # argparse prints its usage to stderr on every rejection; the rejection is the
        # assertion here, not the noise.
        with contextlib.redirect_stderr(io.StringIO()):
            return cli.build_parser().parse_args(argv)

    def test_a_pull_request_number_that_is_not_a_positive_integer_is_refused(self):
        for bad in ("0", "-3", "7; rm -rf /", "1e3", ""):
            with self.assertRaises(SystemExit) as caught:
                self.parse(["analyze", "--pr-number", bad])
            self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.parse(["analyze", "--pr-number", "7"]).pr_number, "7")

    def test_a_sha_that_is_not_a_full_lowercase_object_name_is_refused(self):
        for bad in ("main", "a" * 39, "A" * 40, "../../etc/passwd", "a" * 41):
            with self.assertRaises(SystemExit) as caught:
                self.parse(["analyze", "--head-sha", bad])
            self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.parse(["analyze", "--base-sha", "b" * 40]).base_sha,
                         "b" * 40)

    def test_a_malformed_model_map_is_refused(self):
        for bad in ("hunter", "wizard=deepseek-flash", "hunter=deepseek flash",
                    "hunter=$(id)", "verifier=a;b"):
            with self.assertRaises(SystemExit) as caught:
                self.parse(["analyze", "--models", bad])
            self.assertEqual(caught.exception.code, 2)
        good = "recon=deepseek-flash,verifier=deepseek-v4-pro"
        self.assertEqual(self.parse(["analyze", "--models", good]).models, good)

    def test_an_unknown_subcommand_is_refused(self):
        with self.assertRaises(SystemExit):
            self.parse(["exfiltrate"])

    def test_a_flag_overrides_the_environment_and_nothing_else_is_touched(self):
        env = {"SA_PR_NUMBER": "1", "SA_HEAD_SHA": "c" * 40, "KEEP": "me"}
        cli.apply_overrides(self.parse(["analyze", "--pr-number", "9"]), env)
        self.assertEqual(env["SA_PR_NUMBER"], "9")
        self.assertEqual(env["SA_HEAD_SHA"], "c" * 40)
        self.assertEqual(env["KEEP"], "me")


class TestAnalyze(Fixture):
    def test_analyze_writes_a_bundle_the_publish_job_can_load(self):
        code, bundle_dir = self.run_analyze()
        for name in ("findings.json", "coverage-ledger.json", "run-metadata.json",
                     "summary.md", "inline.json", "pr-annotations.json"):
            self.assertTrue(os.path.isfile(os.path.join(bundle_dir, name)),
                            "%s is missing from the bundle" % name)
        bundle = publishmod.load_bundle(bundle_dir)
        self.assertEqual(bundle.head_sha, self.head)
        self.assertEqual(publishmod.verify_integrity(bundle), [],
                         "every bundle file must match its recorded digest")
        self.assertEqual(bundle.metadata["execution_policy"], "source-only-no-execution")
        self.assertEqual(bundle.metadata["profile"], "quick")
        self.assertEqual(bundle.metadata["scope"], "diff")
        self.assertEqual(code, 0 if bundle.run_status == "complete" else 1,
                         "the exit status must agree with the recorded run status")

    def test_a_healthy_run_completes_and_produces_leads(self):
        """The assertion the other tests deliberately do not make.

        Tolerating either status let the whole pipeline break silently: recon, hunters
        and verifiers were each rejected by their own submit gate and every run came back
        "incomplete", which looks like a policy outcome rather than a broken harness.
        """
        code, bundle_dir = self.run_analyze()
        data = self.metadata(bundle_dir)
        self.assertEqual(data["run_status"], "complete",
                         "a well-behaved scripted run must complete; reason=%r notes=%r"
                         % (data.get("incomplete_reason"), data.get("notes")))
        self.assertEqual(code, 0)
        roles = [c["role"] for c in data["conversations"]]
        for role in ("recon", "hunter", "critic", "verifier"):
            self.assertIn(role, roles, "%s never ran" % role)
        self.assertEqual([c for c in data["conversations"] if c["status"] != "ok"], [],
                         "no conversation may end in a non-ok status on a healthy run")
        with open(os.path.join(bundle_dir, "findings.json"), encoding="utf-8") as fh:
            findings = json.load(fh)
        self.assertTrue(findings, "a seeded injection must produce at least one lead")
        for record in findings:
            self.assertIn(record["verdict"], ("needs_validation", "rejected"))
            self.assertNotIn("severity", record, "nothing is executed, so nothing is rated")
            self.assertTrue(record["fingerprint"].startswith("sa1:"))
        with open(os.path.join(bundle_dir, "summary.md"), encoding="utf-8") as fh:
            summary = fh.read()
        # These printed as "7 of ?" and "of $0.00 ceiling" while the usage keys drifted.
        self.assertNotIn("of ?", summary)
        self.assertNotIn("of $0.00 ceiling", summary)
        # Recon's facts reach the later agents, and the bundle shows what they were told.
        with open(os.path.join(bundle_dir, "architecture.md"), encoding="utf-8") as fh:
            architecture = fh.read()
        self.assertIn("anonymous HTTP client", architecture)
        self.assertIn("Origin: recon", architecture)
        bundle = publishmod.load_bundle(bundle_dir)
        self.assertEqual(publishmod.verify_integrity(bundle), [],
                         "architecture.md is digested like every other bundle file")

    def test_every_bundle_carries_a_summary_that_frames_the_run(self):
        _code, bundle_dir = self.run_analyze()
        with open(os.path.join(bundle_dir, "summary.md"), encoding="utf-8") as fh:
            summary = fh.read()
        self.assertIn("partial", summary.lower())
        data = self.metadata(bundle_dir)
        if data["run_status"] != "complete":
            self.assertIn("incomplete", summary.lower())

    def test_the_phases_run_in_the_order_the_skill_fixes(self):
        """P0 must be over before a model is asked anything, and recon must precede hunt."""
        model = ScriptedModel()
        _code, bundle_dir = self.run_analyze(model=model)
        seen = [role for index, role in enumerate(model.roles)
                if index == 0 or model.roles[index - 1] != role]
        self.assertTrue(seen, "no model conversation was started at all")
        self.assertEqual(seen[0], "recon")
        for role in seen:
            self.assertIn(role, ("recon", "hunter", "critic", "verifier"))
        data = self.metadata(bundle_dir)
        # Every role defaults to DeepSeek-V4.1-Flash. A verifier sharing the hunter's model
        # is allowed, and the run says so rather than implying a second model checked it.
        self.assertEqual(data["models"]["verifier"], "deepseek-flash")
        self.assertEqual(data["models"]["verifier"], data["models"]["hunter"])
        self.assertTrue(any("hunters' model" in note for note in data["notes"]),
                        "a shared verifier model must be disclosed")

    def test_every_conversation_that_failed_is_named_in_the_run_metadata(self):
        _code, bundle_dir = self.run_analyze()
        data = self.metadata(bundle_dir)
        for conversation in data["conversations"]:
            if conversation["status"] != "ok":
                self.assertTrue(any(conversation["agent_id"] in note
                                    for note in data["notes"]),
                                "a failed conversation must be reported, not swallowed")

    def test_no_record_is_ever_marked_confirmed_or_carries_a_severity(self):
        _code, bundle_dir = self.run_analyze()
        with open(os.path.join(bundle_dir, "findings.json"), encoding="utf-8") as fh:
            blob = fh.read()
        for record in json.loads(blob):
            self.assertIn(record.get("verdict"), ("needs_validation", "rejected"))
        self.assertNotIn('"severity"', blob)

    def test_the_pre_fetch_size_gate_runs_before_anything_is_fetched(self):
        gh = StubHub(self.base, self.head, changed_files=10 ** 6, additions=1, deletions=1)
        code, bundle_dir = self.run_analyze(gh=gh)
        self.assertNotEqual(code, 0)
        data = self.metadata(bundle_dir)
        self.assertEqual(data["run_status"], "incomplete")
        self.assertEqual(data["incomplete_reason"], "pr_exceeds_size_gate")
        self.assertEqual([c for c in gh.calls if c[0] == "pull_request"],
                         [("pull_request", "octo/demo", 7)])

    def test_a_crash_still_writes_a_bundle_that_says_so_and_exits_non_zero(self):
        out_dir = tempfile.mkdtemp(prefix="sa-out-", dir=self.tmp)
        services = self.services()
        services.remote_url = os.path.join(self.tmp, "no-such-repository")
        code = cli.main(["analyze"], env=self.env(out_dir), services=services)
        self.assertNotEqual(code, 0)
        bundle_dir = os.path.join(out_dir, "bundle")
        data = self.metadata(bundle_dir)
        self.assertEqual(data["run_status"], "incomplete")
        self.assertTrue(data["incomplete_reason"])
        self.assertEqual(publishmod.verify_integrity(publishmod.load_bundle(bundle_dir)), [],
                         "even a failure bundle must be loadable and digest-clean")

    def test_a_rejected_configuration_writes_no_bundle_and_exits_two(self):
        out_dir = tempfile.mkdtemp(prefix="sa-out-", dir=self.tmp)
        env = self.env(out_dir, SA_HEAD_SHA="not-a-sha")
        code = cli.main(["analyze"], env=env, services=self.services())
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(out_dir, "bundle")))

    def test_the_model_credential_is_removed_from_the_run_environment(self):
        out_dir = tempfile.mkdtemp(prefix="sa-out-", dir=self.tmp)
        env = self.env(out_dir, SA_GITHUB_TOKEN="not-a-real-token")
        with contextlib.redirect_stderr(io.StringIO()):
            cli.main(["analyze"], env=env, services=self.services())
        self.assertNotIn("DEEPSEEK_API_KEY", env)
        self.assertNotIn("SA_GITHUB_TOKEN", env)
        blob = json.dumps(self.metadata(os.path.join(out_dir, "bundle")))
        self.assertNotIn("not-a-real-key", blob)
        self.assertNotIn("not-a-real-token", blob)


class PlannedFixture(Fixture):
    """A real fetched repository with P0 already run, for the phases after it."""

    def setUp(self):
        self.out_dir = tempfile.mkdtemp(prefix="sa-plan-", dir=self.tmp)
        self.repo = gitsrc.open_repo(os.path.join(self.out_dir, "scratch"))
        gitsrc.fetch_pr(self.repo, self.source_dir, self.head, self.base, 3,
                        protocols=("file",))
        self.commits = gitsrc.commits_between(self.repo, self.base, self.head)["commits"]
        self.source = tools.RepoSource(self.repo, self.head, self.base,
                                       commits=self.commits)

    def planned(self):
        from prreview.security import config, orchestrator, skillpack
        from prreview.security import validate as validatemod
        cfg = config.RunConfig(repository="octo/demo", pr_number=7, head_sha=self.head,
                               base_sha=self.base, out_dir=self.out_dir,
                               vendor_dir=VENDOR,
                               caps=config.Caps(max_conversations=12, max_hunters=2))
        validator = validatemod.Validator(VENDOR)
        self.addCleanup(validator.close)
        parent = orchestrator.Orchestrator(cfg, ScriptedModel(), validator, self.source,
                                           skillpack.SkillPack(VENDOR))
        diff = gitsrc.diff_index(self.repo, self.base, self.head)
        changes = orchestrator.routing_changes(self.repo, self.base, self.head, diff)
        parent.plan(diff, changes, len(self.commits),
                    cli.symbol_resolver(self.source, diff))
        return parent


class TestCandidateNaming(PlannedFixture):
    """The P2 plumbing the CLI owns: the parent names every candidate, not the hunter."""

    def test_the_parent_replaces_whatever_fingerprint_the_hunter_proposed(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        units = [parent.ledger.get(cid) for cid in assignment.coverage_ids]
        named, skipped = cli.name_candidates(hunter_records(), units, self.source, set())
        self.assertEqual(skipped, [])
        record, unit = named[0]
        self.assertNotEqual(record["fingerprint"], candidate()["fingerprint"])
        parts = fp.parse(record["fingerprint"])
        self.assertEqual(parts["path"], "src/users.js")
        self.assertEqual(parts["symbol"], "getUser")
        self.assertEqual(parts["class_ref"], unit.ordinary_attack_class_block)

    def test_two_hunters_reaching_one_sink_do_not_collapse_into_one_lead(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        units = [parent.ledger.get(cid) for cid in assignment.coverage_ids]
        taken = set()
        first, _ = cli.name_candidates(hunter_records(), units, self.source, taken)
        second, _ = cli.name_candidates(hunter_records(), units, self.source, taken)
        self.assertNotEqual(first[0][0]["fingerprint"], second[0][0]["fingerprint"])
        self.assertEqual(fp.parse(second[0][0]["fingerprint"])["variant"], 2)

    def test_a_candidate_with_no_usable_sink_is_reported_not_silently_dropped(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        units = [parent.ledger.get(cid) for cid in assignment.coverage_ids]
        record = hunter_records()[0]
        record["trace"], record["evidence"] = [], []
        named, skipped = cli.name_candidates([record], units, self.source, set())
        self.assertEqual(named, [])
        self.assertEqual(len(skipped), 1)

    def test_a_closed_wave_leaves_a_candidate_unit_the_vendored_validator_accepts(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        coverage_id = assignment.coverage_ids[0]
        payload = {"records": hunter_records(),
                   "units": [unit_payload(assignment, coverage_id)]}
        notes = []
        candidates = cli.close_wave(parent, [(assignment, FakeResult(payload))],
                                    self.source, set(), notes)
        self.assertEqual(len(candidates), 1)
        unit = parent.ledger.get(coverage_id)
        self.assertEqual(unit.status, "candidate")
        self.assertEqual(list(unit.result_fingerprints), [candidates[0]["fingerprint"]])
        self.assertEqual(parent.ledger.validate(), [])

    def test_a_unit_the_hunter_left_unevidenced_is_deferred_not_closed(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        payload = {"records": [], "units": []}
        cli.close_wave(parent, [(assignment, FakeResult(payload))], self.source, set(), [])
        for coverage_id in assignment.coverage_ids:
            self.assertEqual(parent.ledger.get(coverage_id).status, "deferred")
        reasons = {entry["coverage_id"]: entry["reason"]
                   for entry in parent.ledger.not_reviewed() if entry["kind"] == "unit"}
        for coverage_id in assignment.coverage_ids:
            self.assertTrue(reasons[coverage_id])

    def test_a_wave_that_returned_nothing_is_never_reported_as_a_clean_run(self):
        parent = self.planned()
        launched = cli.launched_assignments(parent)
        self.assertTrue(launched)
        cli.note_empty_wave(parent, launched, [])
        self.assertEqual(parent.status, "incomplete")
        self.assertEqual(parent.reason, cli.REASON_NO_HUNT)

    def test_a_wave_that_returned_something_leaves_the_status_alone(self):
        parent = self.planned()
        launched = cli.launched_assignments(parent)
        cli.note_empty_wave(parent, launched, [(launched[0], FakeResult({}))])
        self.assertEqual(parent.status, "complete")


class TestGateAndRender(PlannedFixture):
    """P5 and P6 over real records: the gate, then the bundle the publish job reads."""

    def rendered(self, records_from_verifier):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        coverage_id = assignment.coverage_ids[0]
        payload = {"records": hunter_records(), "units": [unit_payload(assignment,
                                                                      coverage_id)]}
        candidates = cli.close_wave(parent, [(assignment, FakeResult(payload))],
                                    self.source, set(), [])
        fingerprint = candidates[0]["fingerprint"]
        # finding() is what a model SENDS (every declared field, nulls included). The tool
        # surface strips the inapplicable nulls before a record ever reaches the gate, so
        # the same strip runs here rather than hand-stripping and drifting from it.
        records = [validatemod.strip_optional_nulls(finding(fingerprint, verdict))
                   for verdict in records_from_verifier]
        gate, units = cli.finalize(parent.cfg, parent, self.source, records)
        writer = cli.BundleWriter(parent.cfg)
        writer.parent = parent
        diff = gitsrc.diff_index(self.repo, self.base, self.head)
        facts = {"merge_base": self.base, "private": True}
        cli.render_bundle(parent.cfg, writer, parent, diff, gate, units, facts)
        writer.write()
        return writer, gate, fingerprint

    def test_a_verified_lead_reaches_the_bundle_and_the_summary(self):
        writer, gate, fingerprint = self.rendered(["needs_validation"])
        self.assertEqual(gate.errors, [])
        self.assertEqual(len(gate.findings), 1)
        self.assertEqual(gate.findings[0]["fingerprint"], fingerprint)
        bundle = publishmod.load_bundle(writer.directory)
        self.assertEqual(publishmod.verify_integrity(bundle), [])
        self.assertEqual(bundle.run_status, "complete")
        self.assertIn("Request parameter concatenated", bundle.summary)
        self.assertEqual(len(bundle.inline), 1)
        self.assertEqual(len(bundle.annotations["leads"]), 1)
        self.assertIsNone(bundle.annotations["severity"])

    def test_a_rejected_record_is_kept_but_is_not_a_lead(self):
        writer, gate, _fingerprint = self.rendered(["rejected"])
        self.assertEqual(gate.errors, [])
        bundle = publishmod.load_bundle(writer.directory)
        self.assertEqual([r["verdict"] for r in bundle.findings], ["rejected"])
        self.assertEqual(bundle.inline, [])

    def test_a_record_citing_a_line_that_does_not_exist_is_quarantined(self):
        parent = self.planned()
        assignment = cli.launched_assignments(parent)[0]
        coverage_id = assignment.coverage_ids[0]
        payload = {"records": hunter_records(), "units": [unit_payload(assignment,
                                                                      coverage_id)]}
        candidates = cli.close_wave(parent, [(assignment, FakeResult(payload))],
                                    self.source, set(), [])
        record = finding(candidates[0]["fingerprint"])
        record["evidence"] = [{"file": "src/users.js", "line": 9999,
                               "description": "a line this file does not have"}]
        gate, _units = cli.finalize(parent.cfg, parent, self.source, [record])
        self.assertEqual(gate.findings, [])
        self.assertEqual(gate.quarantined_fingerprints, [candidates[0]["fingerprint"]])
        self.assertTrue(any("9999" in message
                            for entry in gate.quarantined for message in entry.messages))


class TestBaselineCommand(Fixture):
    def test_the_baseline_records_its_own_profile_and_scope(self):
        out_dir = tempfile.mkdtemp(prefix="sa-base-", dir=self.tmp)
        with contextlib.redirect_stderr(io.StringIO()):
            cli.main(["baseline"], env=self.env(out_dir), services=self.services())
        data = self.metadata(os.path.join(out_dir, "bundle"))
        self.assertEqual(data["profile"], "standard")
        # Not "repository": this audits a commit range, and overstating the scope would
        # make a later run read the ledger as covering ground nobody looked at.
        self.assertEqual(data["scope"], "default-branch-delta")

    def test_the_baseline_spends_the_four_reconnaissance_calls_the_skill_reserves(self):
        out_dir = tempfile.mkdtemp(prefix="sa-base-", dir=self.tmp)
        with contextlib.redirect_stderr(io.StringIO()):
            cli.main(["baseline"], env=self.env(out_dir), services=self.services())
        conversations = self.metadata(os.path.join(out_dir, "bundle"))["conversations"]
        self.assertEqual(sum(1 for c in conversations if c["role"] == "recon"), 4)


class TestPublishCommand(Fixture):
    """The publish half, over the bundle the analyze half actually wrote."""

    def publish_env(self, bundle_dir, **overrides):
        env = {"SA_REPOSITORY": "octo/demo", "SA_PR_NUMBER": "7",
               "SA_HEAD_SHA": self.head, "SA_BUNDLE_DIR": bundle_dir,
               "SA_VENDOR_DIR": VENDOR, "SA_GITHUB_TOKEN": "not-a-real-token"}
        env.update(overrides)
        return env

    def test_a_bundle_written_by_analyze_is_published_end_to_end(self):
        _code, bundle_dir = self.run_analyze()
        state = fakehub.State(repo="octo/demo", number=7, head_sha=self.head)
        state.changed_files = 1
        state.files = [{"filename": "src/users.js", "status": "modified",
                        "patch": "@@ -1,3 +1,3 @@\n context\n-old\n+new\n"}]
        with fakehub.FakeGitHub(state) as fake:
            services = cli.Services(token="not-a-real-token",
                                    gh=githubmod.GitHub("not-a-real-token", api=fake.url))
            outputs = os.path.join(self.tmp, "github-output")
            env = self.publish_env(bundle_dir, GITHUB_OUTPUT=outputs)
            with contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(["publish"], env=env, services=services)
        self.assertIn(code, (0, 1))
        with open(outputs, encoding="utf-8") as handle:
            written = handle.read()
        self.assertRegex(written, r"^status=(published|superseded|blocked)\n\Z",
                         "the step output is the publish status, not the exit code")
        self.assertTrue(state.issue_comments,
                        "the publish job must post a summary for every run it loads")
        self.assertTrue(state.check_runs, "the publish job must complete a check run")
        posted = json.dumps(state.issue_comments)
        self.assertNotIn("not-a-real-token", posted)

    def test_publishing_a_bundle_for_another_head_posts_no_lead_text(self):
        _code, bundle_dir = self.run_analyze()
        state = fakehub.State(repo="octo/demo", number=7, head_sha="f" * 40)
        with fakehub.FakeGitHub(state) as fake:
            services = cli.Services(token="tok", gh=githubmod.GitHub("tok", api=fake.url))
            env = self.publish_env(bundle_dir, SA_HEAD_SHA="e" * 40)
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["publish"], env=env, services=services)
        for comment in state.issue_comments:
            self.assertNotIn("Request parameter concatenated", comment["body"])

    def test_publish_refuses_a_malformed_identity_and_a_missing_token(self):
        args = ["publish"]
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                cli.main(args, env=self.publish_env("/nowhere", SA_HEAD_SHA="nope"),
                         services=self.services()), 2)
            env = self.publish_env("/nowhere")
            env.pop("SA_GITHUB_TOKEN")
            self.assertEqual(cli.main(args, env=env, services=cli.Services()), 2)


class TestReplayCommand(Fixture):
    def test_replay_runs_without_any_model_credential(self):
        out_dir = tempfile.mkdtemp(prefix="sa-replay-", dir=self.tmp)
        cassette = tempfile.mkdtemp(prefix="sa-cassette-", dir=self.tmp)
        env = self.env(out_dir)
        env.pop("DEEPSEEK_API_KEY")
        services = cli.Services(gh=StubHub(self.base, self.head),
                                remote_url=self.source_dir, protocols=("file",))
        with contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["replay", "--cassette", cassette], env=env,
                            services=services)
        # An empty cassette cannot answer, so the run must end incomplete rather than
        # reach for a live provider.
        self.assertNotEqual(code, 0)
        data = self.metadata(os.path.join(out_dir, "bundle"))
        self.assertEqual(data["run_status"], "incomplete")


class TestSeeders(Fixture):
    def test_a_commit_patch_is_split_by_its_target_path(self):
        patch = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n"
                 " keep\n+added one\n"
                 "diff --git a/b.py b/b.py\n--- /dev/null\n+++ b/b.py\n@@ -0,0 +1 @@\n"
                 "+added two\n")
        self.assertEqual(cli.patch_blobs(patch),
                         [("a.py", "added one"), ("b.py", "added two")])

    def test_a_removal_only_patch_yields_no_blob(self):
        patch = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +0,0 @@\n-gone\n"
        self.assertEqual(cli.patch_blobs(patch), [])


class TestSelftest(unittest.TestCase):
    def test_selftest_passes_on_this_checkout(self):
        args = cli.build_parser().parse_args(["selftest"])
        self.assertEqual(cli.cmd_selftest(args, {"SA_VENDOR_DIR": VENDOR}), 0)

    def test_a_loose_object_schema_is_reported_as_not_strict_compatible(self):
        loose = {"type": "object", "properties": {"a": {"type": "string"}}}
        problems = cli.strict_schema_problems(loose, "t")
        self.assertTrue(any("additionalProperties" in p for p in problems))
        self.assertTrue(any("missing a" in p for p in problems))

    def test_the_real_tool_catalogue_is_strict_compatible(self):
        for role in ("recon", "hunter", "critic", "verifier"):
            for definition in tools.tool_definitions(role, strict=True):
                function = definition["function"]
                self.assertTrue(function.get("strict"))
                self.assertEqual(
                    cli.strict_schema_problems(function["parameters"], function["name"]),
                    [])


# ------------------------------------------------------------------------------ YAML

def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def uncommented(text):
    """The file with every full-line comment removed, for "this never appears" checks."""
    return "\n".join(line for line in text.splitlines()
                      if not line.lstrip().startswith("#"))


def load_yaml(path):
    """A structural reader for the subset these files use: mappings, lists and scalars.

    The runner has no yaml module. This is deliberately narrow -- it understands nesting
    by indentation and nothing else -- so a file it cannot read fails the test rather
    than quietly returning an empty mapping.
    """
    raw = read(path)
    root = {}
    stack = [(-1, root)]
    block_indent = None
    for line in raw.splitlines():
        if block_indent is not None:
            if not line.strip() or len(line) - len(line.lstrip()) > block_indent:
                continue
            block_indent = None
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        parent = stack[-1][1]
        if stripped.startswith("- "):
            item = stripped[2:].strip()
            entry = {}
            key, sep, value = item.partition(":")
            if sep:
                entry[key.strip()] = value.strip()
                parent.setdefault("__items__", []).append(entry)
                stack.append((indent + 1, entry))
            else:
                parent.setdefault("__items__", []).append(item)
            continue
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if value in (">-", "|", ">", "|-"):
            block_indent = indent
            parent[key] = ""
        elif value:
            parent[key] = value
        else:
            child = {}
            parent[key] = child
            stack.append((indent, child))
    return root


class TestActionYaml(unittest.TestCase):
    def setUp(self):
        self.parsed = {name: load_yaml(path) for name, path in ACTIONS.items()}
        self.text = {name: read(path) for name, path in ACTIONS.items()}

    def steps(self, name):
        return self.parsed[name]["runs"]["steps"]["__items__"]

    def test_every_action_file_parses_into_the_expected_shape(self):
        for name, data in self.parsed.items():
            self.assertIn("name", data, name)
            self.assertIn("inputs", data, name)
            self.assertEqual(data.get("runs", {}).get("using"), "composite", name)
            self.assertTrue(self.steps(name), "%s has no steps" % name)

    def test_the_analyze_action_takes_a_model_key_and_the_publish_action_does_not(self):
        self.assertIn("deepseek-api-key", self.parsed["analyze"]["inputs"])
        self.assertIn("deepseek-api-key", self.parsed["baseline"]["inputs"])
        for forbidden in ("deepseek-api-key", "anthropic-api-key", "models"):
            self.assertNotIn(forbidden, self.parsed["publish"]["inputs"],
                             "publish must hold no model credential or model choice")
        for secret in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY"):
            self.assertNotIn(secret, self.text["publish"])

    def test_the_analyze_action_never_asks_for_a_write_scope(self):
        for name in ("analyze", "baseline"):
            for scope in ("contents: write", "pull-requests: write", "issues: write",
                          "checks: write", "security-events: write", "id-token: write"):
                self.assertNotIn(scope, self.text[name],
                                 "%s must never request %s" % (name, scope))
            self.assertNotIn("create_issue_comment", self.text[name])

    def test_no_run_body_interpolates_anything_into_the_script(self):
        """An input in a `run:` body is shell source; in `env:` it is only ever a string."""
        for name, text in self.text.items():
            in_run, indent = False, 0
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                here = len(line) - len(line.lstrip())
                if in_run and here <= indent:
                    in_run = False
                if in_run:
                    self.assertNotIn("${{", line,
                                     "%s interpolates into a run body: %s" % (name, stripped))
                elif re.match(r"^run:\s*[|>]", stripped):
                    in_run, indent = True, here
                elif stripped.startswith("run:"):
                    self.assertNotIn("${{ inputs.", stripped,
                                     "%s interpolates an input into a one-line run: %s"
                                     % (name, stripped))

    def test_the_shell_steps_validate_every_input_they_use(self):
        for name in ("analyze", "baseline"):
            self.assertIn("[[ ! \"$SA_HEAD_SHA\" =~ ^[0-9a-f]{40}$ ]]", self.text[name])
            self.assertIn("[[ ! \"$SA_BASE_SHA\" =~ ^[0-9a-f]{40}$ ]]", self.text[name])
        self.assertIn("[[ ! \"$SA_PR_NUMBER\" =~ ^[1-9][0-9]{0,8}$ ]]",
                      self.text["analyze"])
        self.assertIn("[[ ! \"$HEAD_SHA\" =~ ^[0-9a-f]{40}$ ]]", self.text["publish"])
        self.assertIn("[[ ! \"$PR_NUMBER\" =~ ^[1-9][0-9]{0,8}$ ]]", self.text["publish"])

    def test_the_setup_python_action_is_pinned_to_the_repository_wide_sha(self):
        pin = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
        for name, text in self.text.items():
            self.assertIn(pin, text, name)

    def test_no_action_is_used_at_a_floating_tag(self):
        used = re.findall(r"uses:\s*([^\s#]+)", "\n".join(self.text.values()))
        for reference in used:
            self.assertTrue(re.search(r"@([0-9a-f]{40}|<sha>)$", reference),
                            "%s is neither sha-pinned nor marked as needing a pin"
                            % reference)

    def test_the_baseline_carries_its_own_cost_cap(self):
        analyze_cap = self.parsed["analyze"]["inputs"]["max-usd"]["default"]
        baseline_cap = self.parsed["baseline"]["inputs"]["max-usd"]["default"]
        self.assertNotEqual(analyze_cap, baseline_cap)

    def test_the_publish_action_defaults_to_a_check_that_cannot_block_a_merge(self):
        self.assertEqual(self.parsed["publish"]["inputs"]["fail-on"]["default"], "never")


class TestConsumerWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = read(WORKFLOW)
        self.parsed = load_yaml(WORKFLOW)

    def test_the_workflow_parses_and_declares_the_three_jobs(self):
        for job in ("unlabel-on-push", "analyze", "publish"):
            self.assertIn(job, self.parsed["jobs"], job)

    def test_permissions_are_empty_at_the_top_and_set_per_job(self):
        self.assertEqual(self.parsed.get("permissions"), "{}")
        for job in ("unlabel-on-push", "analyze", "publish"):
            self.assertIn("permissions", self.parsed["jobs"][job], job)

    def test_the_analyze_job_gets_no_write_scope_and_the_publish_job_gets_no_key(self):
        analyze = self.parsed["jobs"]["analyze"]["permissions"]
        self.assertEqual(analyze.get("contents"), "read")
        for scope, value in analyze.items():
            self.assertNotEqual(value, "write", "analyze must hold no write scope")
        publish = self.parsed["jobs"]["publish"]
        self.assertNotIn("DEEPSEEK_API_KEY", json.dumps(publish))
        self.assertEqual(publish["permissions"].get("pull-requests"), "write")

    def test_a_new_fork_head_needs_a_fresh_label(self):
        self.assertIn("unlabel-on-push", self.text)
        self.assertIn("github.event.action == 'synchronize'", self.text)
        self.assertIn("labels/security-review", self.text)

    def test_the_trigger_is_the_default_branch_definition_and_never_checks_out_the_pr(self):
        self.assertIn("pull_request_target", self.text)
        body = uncommented(self.text)
        self.assertNotIn("actions/checkout", body)
        self.assertNotIn("actions/cache", body)

    def test_concurrency_is_declared_on_the_jobs_not_the_workflow(self):
        jobs = self.parsed["jobs"]
        self.assertIn("concurrency", jobs["analyze"])
        self.assertIn("concurrency", jobs["publish"])
        head = self.text.split("jobs:", 1)[0]
        self.assertNotIn("concurrency", head)

    def test_the_egress_allowlist_is_documented_as_needing_an_audit_run_first(self):
        self.assertIn("harden-runner", self.text)
        self.assertIn("egress-policy: audit", self.text)
        self.assertIn("blob", self.text)

    def test_the_workflow_says_the_check_must_not_be_required(self):
        self.assertIn("advisory", self.text.lower())
        self.assertIn("fail-on: never", self.text)


class TestReadme(unittest.TestCase):
    def setUp(self):
        self.text = read(os.path.join(ROOT, "README.md"))

    def test_the_security_section_states_the_policy_a_reader_needs(self):
        section = self.text.split("## AI security review", 1)
        self.assertEqual(len(section), 2, "README has no security-reviewer section")
        body = section[1]
        self.assertIn("needs_validation", body)
        self.assertIn("advisory", body.lower())
        self.assertIn("required check", body.lower())
        self.assertIn("prompt injection", body.lower())

    def test_the_existing_pr_agent_section_is_still_there(self):
        self.assertIn("PR-Agent", self.text)
        self.assertIn("## Usage", self.text)


if __name__ == "__main__":
    unittest.main()
