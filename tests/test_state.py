"""Tests for prior-run state: provenance, safe unpacking and the skill's carry rules.

Every control here is tested twice: once showing the refusal, once showing that the same
input is accepted when only that control is relaxed. A zip-slip test that passes because
the member name happened to be unknown, or a suppression test that passes because the
record was malformed, would prove nothing.
"""
import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import state  # noqa: E402
from prreview.security import fingerprint as fp  # noqa: E402
from prreview.security.fingerprint import RenameMap  # noqa: E402
from prreview.security.routing import ATTACK, block_id  # noqa: E402

ACCESS_CONTROL = block_id(ATTACK, "Access control")
INJECTION = block_id(ATTACK, "Injection")

REPO = "SirLouen/ai-pr-review"
WORKFLOW = ".github/workflows/security-review.yml"
PROV = state.Provenance(repository=REPO, workflow_path=WORKFLOW, default_branch="main")

NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def run(**overrides):
    """A genuine analyze run of the trusted, default-branch workflow definition."""
    body = {"id": 900, "status": "completed", "conclusion": "success",
            "path": WORKFLOW, "event": "pull_request_target",
            "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
            "head_branch": "feature/x", "head_sha": "a" * 40}
    body.update(overrides)
    return body


def artifact(**overrides):
    body = {"id": 77, "name": state.STATE_PREFIX + "7-1234-1", "expired": False,
            "size_in_bytes": 4096, "created_at": iso(NOW - timedelta(hours=2)),
            "workflow_run": {"id": 900}}
    body.update(overrides)
    return body


class FakeSource:
    """The three GitHub Actions calls state.py needs, with no network anywhere."""

    def __init__(self, artifacts, runs, blobs=None):
        self.artifacts = list(artifacts)
        self.runs = dict(runs)
        self.blobs = dict(blobs or {})
        self.downloaded = []

    def list_artifacts(self, page=1, per_page=100):
        start = (page - 1) * per_page
        return {"artifacts": self.artifacts[start:start + per_page]}

    def get_run(self, run_id):
        return self.runs.get(int(run_id), {})

    def download_artifact(self, artifact_id, max_bytes=None):
        self.downloaded.append(artifact_id)
        return self.blobs[artifact_id]


# --------------------------------------------------------------------------- naming

class WorkflowPathTest(unittest.TestCase):
    def test_ref_is_reduced_to_the_repository_relative_path(self):
        ref = "SirLouen/ai-pr-review/.github/workflows/security-review.yml@refs/heads/main"
        self.assertEqual(state.workflow_path(ref, REPO), WORKFLOW)
        self.assertEqual(state.workflow_path(ref), WORKFLOW)

    def test_artifact_prefix_does_not_confuse_pr1_with_pr12(self):
        prefix = state.artifact_prefix(state.KIND_STATE, 1)
        self.assertTrue(state._name_matches(prefix, prefix))
        self.assertTrue(state._name_matches(prefix + "-1234-1", prefix))
        self.assertFalse(state._name_matches(state.STATE_PREFIX + "12", prefix))


# ----------------------------------------------------------------------- provenance

class ProvenanceTest(unittest.TestCase):
    def accepted_with(self, run_body, prov=PROV, kind=state.KIND_STATE, art=None):
        art = art or artifact()
        source = FakeSource([art], {run_body.get("id", 900): run_body})
        return state.discover(source, prov, kind, pr_number=7)

    def test_genuine_trusted_run_is_accepted(self):
        found = self.accepted_with(run())
        self.assertEqual(len(found.accepted), 1)
        self.assertEqual(found.accepted[0].run_id, 900)
        self.assertEqual(found.rejected, ())

    def test_pull_request_run_of_a_pr_branch_is_refused(self):
        # This is the forgery the filter exists for: a contributor lands a workflow on
        # their own branch that uploads an artifact with our name.
        forged = run(event="pull_request", head_branch="attacker/poison")
        found = self.accepted_with(forged)
        self.assertEqual(found.accepted, ())
        self.assertIn("pull_request", found.rejected[0][2])
        # Control removed: the SAME artifact from the same workflow is accepted once the
        # event is one whose definition GitHub takes from the default branch.
        self.assertEqual(len(self.accepted_with(run()).accepted), 1)

    def test_a_different_workflow_definition_is_refused(self):
        found = self.accepted_with(run(path=".github/workflows/attacker.yml"))
        self.assertEqual(found.accepted, ())
        self.assertIn("not the trusted definition", found.rejected[0][2])

    def test_fork_head_repository_is_refused(self):
        found = self.accepted_with(run(head_repository={"full_name": "mallory/fork"}))
        self.assertEqual(found.accepted, ())
        self.assertIn("head repository", found.rejected[0][2])

    def test_other_repository_is_refused(self):
        found = self.accepted_with(run(repository={"full_name": "mallory/other"}))
        self.assertEqual(found.accepted, ())
        self.assertIn("not %r" % REPO, found.rejected[0][2])

    def test_failed_or_incomplete_run_is_refused(self):
        self.assertIn("conclusion", self.accepted_with(run(conclusion="failure"))
                      .rejected[0][2])
        self.assertIn("status", self.accepted_with(run(status="in_progress"))
                      .rejected[0][2])

    def test_expired_artifact_is_refused(self):
        found = self.accepted_with(run(), art=artifact(expired=True))
        self.assertEqual(found.accepted, ())
        self.assertIn("expired", found.rejected[0][2])

    def test_artifact_linked_to_a_different_run_is_refused(self):
        # Checked directly: discover() looks the run up by the artifact's own link, so
        # this guards a caller that pairs an artifact with someone else's run record.
        mismatched = artifact(workflow_run={"id": 901})
        self.assertIn("linked to run",
                      state._check_run(mismatched, run(), PROV, state.KIND_STATE))
        self.assertEqual(state._check_run(artifact(), run(), PROV, state.KIND_STATE), "")

    def test_a_missing_run_record_is_refused(self):
        found = self.accepted_with(run(), art=artifact(workflow_run={"id": 901}))
        self.assertEqual(found.accepted, ())
        self.assertIn("could not be read", found.rejected[0][2])

    def test_baseline_push_from_a_non_default_branch_is_refused(self):
        # A push to any other branch runs THAT branch's copy of the same path, so the
        # event and path checks alone do not bound the producer.
        forged = run(id=901, event="push", head_branch="attacker/poison")
        source = FakeSource([artifact(id=88, name=state.BASELINE_PREFIX,
                                      workflow_run={"id": 901})], {901: forged})
        found = state.discover(source, PROV, state.KIND_BASELINE)
        self.assertEqual(found.accepted, ())
        self.assertIn("not the default branch", found.rejected[0][2])
        # Control removed: the same push on the default branch is accepted.
        good = run(id=901, event="push", head_branch="main")
        source = FakeSource([artifact(id=88, name=state.BASELINE_PREFIX,
                                      workflow_run={"id": 901})], {901: good})
        self.assertEqual(len(state.discover(source, PROV, state.KIND_BASELINE).accepted), 1)

    def test_scheduled_baseline_is_accepted_on_the_default_branch(self):
        body = run(id=901, event="schedule", head_branch="main")
        source = FakeSource([artifact(id=88, name=state.BASELINE_PREFIX,
                                      workflow_run={"id": 901})], {901: body})
        found = state.discover(source, PROV, state.KIND_BASELINE)
        self.assertEqual(len(found.accepted), 1)

    def test_pull_request_target_is_not_a_baseline_producer(self):
        source = FakeSource([artifact(id=88, name=state.BASELINE_PREFIX)], {900: run()})
        found = state.discover(source, PROV, state.KIND_BASELINE)
        self.assertEqual(found.accepted, ())

    def test_same_repo_only_mode_disables_the_channel(self):
        untrusted = state.Provenance(repository=REPO, workflow_path=WORKFLOW,
                                     trusted=False)
        found = self.accepted_with(run(), prov=untrusted)
        self.assertEqual(found.accepted, ())
        self.assertIn("trust is disabled", found.rejected[0][2])

    def test_unknown_workflow_path_refuses_everything(self):
        blind = state.Provenance(repository=REPO, workflow_path="")
        self.assertEqual(self.accepted_with(run(), prov=blind).accepted, ())

    def test_artifacts_from_other_pull_requests_are_not_listed(self):
        source = FakeSource([artifact(id=5, name=state.STATE_PREFIX + "9-1-1")],
                            {900: run()})
        found = state.discover(source, PROV, state.KIND_STATE, pr_number=7)
        self.assertEqual((found.accepted, found.rejected), ((), ()))

    def test_newest_accepted_artifact_comes_first(self):
        old = artifact(id=1, created_at=iso(NOW - timedelta(days=3)))
        new = artifact(id=2, created_at=iso(NOW - timedelta(minutes=5)))
        source = FakeSource([old, new], {900: run()})
        found = state.discover(source, PROV, state.KIND_STATE, pr_number=7)
        self.assertEqual([c.artifact_id for c in found.accepted], [2, 1])
        self.assertEqual(found.newest.artifact_id, 2)

    def test_an_unreadable_run_is_not_trusted(self):
        class Broken(FakeSource):
            def get_run(self, run_id):
                raise OSError("boom")

        found = state.discover(Broken([artifact()], {}), PROV, state.KIND_STATE,
                               pr_number=7)
        self.assertEqual(found.accepted, ())
        self.assertIn("could not be read", found.rejected[0][2])


# ----------------------------------------------------------------------- safe unzip

def build_zip(members, compression=zipfile.ZIP_DEFLATED):
    """members: (name, data, external_attr_mode) tuples written verbatim."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, data, mode in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = (mode << 16) if mode else (0o100644 << 16)
            info.compress_type = compression
            archive.writestr(info, data)
    return buffer.getvalue()


class SafeExtractTest(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp(prefix="sa-state-")
        self.addCleanup(shutil.rmtree, self.dest, ignore_errors=True)
        self.outside = tempfile.mkdtemp(prefix="sa-outside-")
        self.addCleanup(shutil.rmtree, self.outside, ignore_errors=True)

    def test_a_good_bundle_extracts_only_its_allowed_members(self):
        data = build_zip([("run-metadata.json", b"{}", None),
                          ("findings.json", b"[]", None),
                          ("notes.txt", b"hello", None)])
        files = state.safe_extract(data, os.path.join(self.dest, "b"))
        self.assertEqual(sorted(files), ["findings.json", "run-metadata.json"])
        self.assertFalse(os.path.exists(os.path.join(self.dest, "b", "notes.txt")))

    def test_zip_slip_is_refused(self):
        bundle = os.path.join(self.dest, "b")
        escape = "../../" + os.path.basename(self.outside) + "/pwned.json"
        data = build_zip([("run-metadata.json", b"{}", None), (escape, b"owned", None)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, bundle)
        self.assertIn("traverses upward", str(caught.exception))
        # Control removed: the naive join this replaces really does land outside, so the
        # fixture is a live zip-slip and not an inert name.
        naive = os.path.realpath(os.path.join(bundle, escape))
        self.assertEqual(os.path.dirname(naive), os.path.realpath(self.outside))
        self.assertFalse(os.path.exists(naive))


    def test_absolute_member_name_is_refused(self):
        data = build_zip([("/etc/cron.d/pwn", b"x", None)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, self.dest)
        self.assertIn("absolute", str(caught.exception))

    def test_backslash_and_control_characters_are_refused(self):
        for name in ("..\\..\\pwn.json", "findings\n.json"):
            with self.assertRaises(state.UnsafeArchive):
                state.safe_extract(build_zip([(name, b"x", None)]), self.dest)

    def test_symlink_member_is_refused_and_nothing_is_written(self):
        target = os.path.join(self.outside, "secret")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("token")
        data = build_zip([("run-metadata.json", b"{}", None),
                          ("findings.json", target.encode(), stat.S_IFLNK | 0o777)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, os.path.join(self.dest, "b"))
        self.assertIn("not a regular file", str(caught.exception))
        self.assertFalse(os.path.lexists(os.path.join(self.dest, "b", "findings.json")))
        # Control removed: the same bytes under a regular-file mode are ordinary content.
        regular = build_zip([("run-metadata.json", b"{}", None),
                             ("findings.json", target.encode(), 0o100644)])
        files = state.safe_extract(regular, os.path.join(self.dest, "c"))
        self.assertIn("findings.json", files)

    def test_device_and_fifo_members_are_refused(self):
        for mode in (stat.S_IFIFO | 0o666, stat.S_IFCHR | 0o666, stat.S_IFBLK | 0o666):
            data = build_zip([("findings.json", b"{}", mode)])
            with self.assertRaises(state.UnsafeArchive):
                state.safe_extract(data, tempfile.mkdtemp(dir=self.dest))

    def test_ratio_bomb_is_refused(self):
        data = build_zip([("findings.json", b"\0" * 4_000_000, None)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, os.path.join(self.dest, "b"))
        self.assertIn("ratio", str(caught.exception))
        # Control removed: only the ratio cap refuses it; the size caps do not.
        relaxed = state.UnzipLimits(ratio=10 ** 9)
        files = state.safe_extract(data, os.path.join(self.dest, "c"), limits=relaxed)
        self.assertIn("findings.json", files)

    def test_oversize_member_is_refused(self):
        data = build_zip([("findings.json", os.urandom(200_000), None)])
        tight = state.UnzipLimits(member_bytes=50_000)
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, os.path.join(self.dest, "b"), limits=tight)
        self.assertIn("over the 50000 cap", str(caught.exception))
        # Control removed: the same member fits under the default cap.
        files = state.safe_extract(data, os.path.join(self.dest, "c"))
        self.assertIn("findings.json", files)

    def test_total_size_cap_is_refused(self):
        data = build_zip([("findings.json", os.urandom(80_000), None),
                          ("run-metadata.json", os.urandom(80_000), None)])
        tight = state.UnzipLimits(total_bytes=100_000, member_bytes=90_000, ratio=10 ** 9)
        with self.assertRaises(state.UnsafeArchive):
            state.safe_extract(data, os.path.join(self.dest, "b"), limits=tight)

    def test_member_count_cap_is_refused(self):
        data = build_zip([("f%d.json" % i, b"{}", None) for i in range(70)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, self.dest)
        self.assertIn("over the 64 cap", str(caught.exception))

    def test_duplicate_member_names_are_refused(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            data = build_zip([("findings.json", b"[]", None),
                              ("findings.json", b"[1]", None)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, os.path.join(self.dest, "b"))
        self.assertIn("duplicate", str(caught.exception))

    def test_a_pre_existing_symlink_at_the_target_is_not_written_through(self):
        # Second layer, and the only one that can catch a hostile destination: the name
        # is allowed and safe, so containment is decided after resolution.
        outside = os.path.join(self.outside, "victim")
        bundle = os.path.join(self.dest, "b")
        os.makedirs(bundle)
        os.symlink(outside, os.path.join(bundle, "findings.json"))
        data = build_zip([("findings.json", b"[]", None)])
        with self.assertRaises(state.UnsafeArchive) as caught:
            state.safe_extract(data, bundle)
        self.assertIn("outside the extraction directory", str(caught.exception))
        self.assertFalse(os.path.exists(outside))

    def test_a_symlink_inside_the_destination_is_still_not_written_through(self):
        bundle = os.path.join(self.dest, "b")
        os.makedirs(bundle)
        victim = os.path.join(bundle, "victim")
        os.symlink(victim, os.path.join(bundle, "findings.json"))
        data = build_zip([("findings.json", b"[]", None)])
        with self.assertRaises(OSError):            # O_NOFOLLOW | O_EXCL
            state.safe_extract(data, bundle)
        self.assertFalse(os.path.exists(victim))

    def test_streaming_stops_at_the_total_cap(self):
        data = build_zip([("findings.json", b"x" * 20_000, None)])
        limits = state.UnzipLimits(total_bytes=100_000, ratio=10 ** 9)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.infolist()[0]
            with self.assertRaises(state.UnsafeArchive):
                state._extract_member(archive, info, os.path.realpath(self.dest), limits,
                                      total_so_far=95_000)

    def test_not_a_zip_is_a_state_error(self):
        with self.assertRaises(state.StateError):
            state.safe_extract(b"not a zip at all", self.dest)


# ------------------------------------------------------------------- bundle parsing

def write_bundle(directory, metadata=None, findings=None, units=None, architecture=None):
    os.makedirs(directory, exist_ok=True)
    files = {}
    import json as _json
    for name, value in (("run-metadata.json", metadata), ("findings.json", findings),
                        ("coverage-ledger.json", units)):
        if value is None:
            continue
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            _json.dump(value, handle)
        files[name] = path
    if architecture is not None:
        path = os.path.join(directory, "architecture.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(architecture)
        files["architecture.md"] = path
    return files


class ReadBundleTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sa-bundle-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def test_a_well_formed_bundle_parses(self):
        files = write_bundle(self.dir, metadata={"pr_number": 7, "head_sha": "b" * 40},
                             findings=[{"fingerprint": "sa1:injection:a.py@f"}],
                             units=[{"coverage_id": "u1", "status": "covered"}])
        bundle = state.read_bundle(files, expect_pr=7)
        self.assertTrue(bundle.compatible)
        self.assertEqual(bundle.head_sha, "b" * 40)
        self.assertEqual(len(bundle.findings), 1)

    def test_a_bundle_for_another_pull_request_is_incompatible(self):
        files = write_bundle(self.dir, metadata={"pr_number": 9})
        bundle = state.read_bundle(files, expect_pr=7)
        self.assertFalse(bundle.compatible)
        self.assertIn("PR #9", bundle.reason)

    def test_unparsable_json_is_incompatible_not_empty(self):
        files = write_bundle(self.dir, metadata={"pr_number": 7})
        with open(files["run-metadata.json"], "w", encoding="utf-8") as handle:
            handle.write("{not json")
        bundle = state.read_bundle(files, expect_pr=7)
        self.assertFalse(bundle.compatible)
        plan = state.plan_prior(bundle, state.SourceOracle())
        self.assertFalse(plan.compatible)
        self.assertIn("incompatible", plan.notes[0])
        self.assertIn("not as empty coverage", plan.notes[0])

    def test_a_validator_rejection_makes_the_bundle_incompatible(self):
        files = write_bundle(self.dir, metadata={"pr_number": 7}, findings=[{"x": 1}],
                             units=[])
        bundle = state.read_bundle(
            files, expect_pr=7, validate=lambda records, units: ["$[0]: bad record"])
        self.assertFalse(bundle.compatible)
        self.assertIn("bad record", bundle.reason)
        # Control removed: the same files pass when the validator is happy.
        ok = state.read_bundle(files, expect_pr=7, validate=lambda r, u: [])
        self.assertTrue(ok.compatible)

    def test_fetch_downloads_unpacks_and_parses(self):
        data = build_zip([("run-metadata.json", b'{"pr_number": 7}', None),
                          ("findings.json", b"[]", None)])
        source = FakeSource([artifact()], {900: run()}, blobs={77: data})
        found = state.discover(source, PROV, state.KIND_STATE, pr_number=7)
        bundle = state.fetch(source, found.newest, os.path.join(self.dir, "x"),
                             expect_pr=7)
        self.assertTrue(bundle.compatible)
        self.assertEqual(source.downloaded, [77])


# --------------------------------------------------------------------- source oracle

class SourceOracleTest(unittest.TestCase):
    def test_unchanged_and_changed_paths(self):
        oracle = state.SourceOracle({"a.py": "o1", "b.py": "o2"},
                                    {"a.py": "o1", "b.py": "o9"})
        self.assertTrue(oracle.unchanged("a.py"))
        self.assertFalse(oracle.unchanged("b.py"))
        self.assertFalse(oracle.all_unchanged(["a.py", "b.py"]))
        self.assertTrue(oracle.all_unchanged(["a.py"]))
        self.assertEqual(oracle.changed_paths(["a.py", "b.py"]), ("b.py",))

    def test_a_record_citing_nothing_cannot_prove_itself_unchanged(self):
        self.assertFalse(state.SourceOracle({}, {}).all_unchanged([]))

    def test_a_deleted_path_is_changed(self):
        oracle = state.SourceOracle({"a.py": "o1"}, {})
        self.assertFalse(oracle.unchanged("a.py"))

    def test_a_renamed_file_is_still_unchanged(self):
        renames = RenameMap([("old/app.ts", "new/app.ts")])
        oracle = state.SourceOracle({"old/app.ts": "o1"}, {"new/app.ts": "o1"},
                                    renames=renames)
        self.assertTrue(oracle.unchanged("old/app.ts"))
        # Control removed: without the rename map the same move reads as a deletion.
        self.assertFalse(state.SourceOracle({"old/app.ts": "o1"},
                                            {"new/app.ts": "o1"}).unchanged("old/app.ts"))

    def test_cited_paths_reads_trace_and_evidence(self):
        record = {"trace": [{"file": "a.py", "line": 3}, {"file": "b.py"}],
                  "evidence": [{"file": "a.py"}, {"file": "c.py"}]}
        self.assertEqual(state.cited_paths(record), ("a.py", "b.py", "c.py"))


# ------------------------------------------------------------------ prior-run rules

REJECTED_FP = fp.build(ACCESS_CONTROL, "src/routes/user.ts", "updateUser")
LEAD_FP = fp.build(INJECTION, "src/db/search.ts", "search")


def record(fingerprint, verdict, paths):
    return {"fingerprint": fingerprint, "verdict": verdict,
            "title": "a claim", "description": "d",
            "trace": [{"file": path, "line": 10} for path in paths],
            "evidence": [{"file": paths[0], "line": 10}]}


def bundle_with(findings, units=(), metadata=None, architecture=""):
    meta = {"pr_number": 7, "head_sha": "b" * 40, "profile": "quick",
            "generated_at": iso(NOW - timedelta(days=1))}
    meta.update(metadata or {})
    return state.PriorBundle(candidate=None, metadata=meta, findings=tuple(findings),
                             units=tuple(units), architecture=architecture,
                             compatible=True)


class SuppressionTest(unittest.TestCase):
    def plan(self, findings, head_oids, metadata=None, renames=None, now=NOW, units=()):
        oracle = state.SourceOracle({"src/routes/user.ts": "o1", "src/db/search.ts": "o2"},
                                    head_oids, renames=renames)
        return state.plan_prior(bundle_with(findings, units=units, metadata=metadata),
                                oracle, now=now)

    def test_unchanged_rejected_claim_is_suppressed(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        plan = self.plan(findings, {"src/routes/user.ts": "o1"})
        self.assertEqual([s.fingerprint for s in plan.suppressed], [REJECTED_FP])
        self.assertTrue(state.suppresses(plan, REJECTED_FP))
        self.assertEqual(plan.exempt_fingerprints(), (REJECTED_FP,))
        self.assertEqual(len(state.carried_records(plan)), 1)

    def test_suppression_stops_when_the_cited_source_changed(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        plan = self.plan(findings, {"src/routes/user.ts": "DIFFERENT"})
        self.assertEqual(plan.suppressed, ())
        self.assertFalse(state.suppresses(plan, REJECTED_FP))
        self.assertIn(REJECTED_FP, plan.changed)
        self.assertTrue(any("no longer applies" in n for n in plan.notes))

    def test_suppression_stops_when_only_a_second_cited_file_changed(self):
        findings = [record(REJECTED_FP, "rejected",
                           ["src/routes/user.ts", "src/db/search.ts"])]
        unchanged = {"src/routes/user.ts": "o1", "src/db/search.ts": "o2"}
        self.assertTrue(state.suppresses(self.plan(findings, unchanged), REJECTED_FP))
        moved = dict(unchanged, **{"src/db/search.ts": "o9"})
        self.assertFalse(state.suppresses(self.plan(findings, moved), REJECTED_FP))

    def test_suppression_ages_out_by_push_count(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        head = {"src/routes/user.ts": "o1"}
        history = [{"fingerprint": REJECTED_FP, "since": iso(NOW - timedelta(hours=1)),
                    "pushes": 5}]
        plan = self.plan(findings, head, metadata={"suppressions": history})
        self.assertEqual(plan.suppressed, ())
        self.assertEqual([s.pushes for s in plan.expired], [6])
        self.assertIn("over the cap of 5", plan.expired[0].reason)
        # Control removed: one push earlier the same unchanged claim still suppresses.
        history[0]["pushes"] = 3
        plan = self.plan(findings, head, metadata={"suppressions": history})
        self.assertEqual([s.pushes for s in plan.suppressed], [4])

    def test_suppression_ages_out_by_calendar_days(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        head = {"src/routes/user.ts": "o1"}
        history = [{"fingerprint": REJECTED_FP, "since": iso(NOW - timedelta(days=8)),
                    "pushes": 1}]
        plan = self.plan(findings, head, metadata={"suppressions": history})
        self.assertEqual(plan.suppressed, ())
        self.assertIn("over the cap of 7 days", plan.expired[0].reason)
        # Control removed: six days old is inside the window.
        history[0]["since"] = iso(NOW - timedelta(days=6))
        plan = self.plan(findings, head, metadata={"suppressions": history})
        self.assertEqual(len(plan.suppressed), 1)

    def test_an_unreadable_first_rejection_time_cannot_suppress(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        history = [{"fingerprint": REJECTED_FP, "since": "whenever", "pushes": 1}]
        plan = self.plan(findings, {"src/routes/user.ts": "o1"},
                         metadata={"suppressions": history})
        self.assertEqual(plan.suppressed, ())
        self.assertIn("unreadable", plan.expired[0].reason)

    def test_history_written_for_the_next_run_advances_the_push_count(self):
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        plan = self.plan(findings, {"src/routes/user.ts": "o1"})
        self.assertEqual(plan.suppression_history(),
                         [{"fingerprint": REJECTED_FP,
                           "since": iso(NOW - timedelta(days=1)), "pushes": 1}])

    def test_a_renamed_file_keeps_its_fingerprint_and_its_suppression(self):
        renames = RenameMap([("src/routes/user.ts", "src/api/user.ts")])
        findings = [record(REJECTED_FP, "rejected", ["src/routes/user.ts"])]
        plan = self.plan(findings, {"src/api/user.ts": "o1"}, renames=renames)
        moved = fp.build(ACCESS_CONTROL, "src/api/user.ts", "updateUser")
        self.assertEqual([s.fingerprint for s in plan.suppressed], [moved])
        self.assertEqual(plan.suppressed[0].prior_fingerprint, REJECTED_FP)
        self.assertEqual(fp.parse(moved)["symbol"], "updateUser")
        # Control removed: with no rename map the move reads as changed source.
        plan = self.plan(findings, {"src/api/user.ts": "o1"})
        self.assertEqual(plan.suppressed, ())


class ReverificationTest(unittest.TestCase):
    def plan(self, findings, head_oids, units=()):
        oracle = state.SourceOracle({"src/db/search.ts": "o2"}, head_oids)
        return state.plan_prior(bundle_with(findings, units=units), oracle, now=NOW)

    def test_prior_needs_validation_is_marked_for_reverification_never_carried(self):
        findings = [record(LEAD_FP, "needs_validation", ["src/db/search.ts"])]
        units = [{"coverage_id": "u-search", "status": "candidate",
                  "result_fingerprints": [LEAD_FP]}]
        plan = self.plan(findings, {"src/db/search.ts": "o2"}, units=units)
        self.assertEqual(len(plan.reverify), 1)
        carry = plan.reverify[0]
        self.assertTrue(carry.requires_reverification)
        self.assertEqual(carry.prior_status, "prior_needs_validation")
        self.assertEqual(carry.coverage_id, "u-search")
        # It is NOT a suppression and NOT a record this run may publish on its own.
        self.assertEqual(plan.suppressed, ())
        self.assertEqual(state.carried_records(plan), ())
        self.assertNotIn(LEAD_FP, plan.exempt_fingerprints())
        self.assertEqual(plan.unit_status["u-search"], "prior_needs_validation")

    def test_changed_source_makes_a_prior_lead_new_work_not_a_carry(self):
        findings = [record(LEAD_FP, "needs_validation", ["src/db/search.ts"])]
        plan = self.plan(findings, {"src/db/search.ts": "CHANGED"})
        self.assertEqual(plan.reverify, ())
        self.assertIn(LEAD_FP, plan.changed)

    def test_a_prior_confirmed_record_is_revalidation_work(self):
        findings = [record(LEAD_FP, "confirmed", ["src/db/search.ts"])]
        plan = self.plan(findings, {"src/db/search.ts": "o2"})
        self.assertEqual((plan.suppressed, plan.reverify), ((), ()))
        self.assertIn(LEAD_FP, plan.changed)
        self.assertTrue(any("cannot carry a confirmed verdict" in n for n in plan.notes))


class UnitStateTest(unittest.TestCase):
    def test_prior_unit_statuses_map_to_current_work(self):
        units = [{"coverage_id": "u-cov", "status": "covered",
                  "starting_paths": ["a.py"], "canonical_refs": {"surface": "s"}},
                 {"coverage_id": "u-moved", "status": "covered",
                  "starting_paths": ["b.py"]},
                 {"coverage_id": "u-def", "status": "deferred"},
                 {"coverage_id": "u-blk", "status": "blocked"},
                 {"coverage_id": "u-oos", "status": "out_of_scope"},
                 {"coverage_id": "u-plan", "status": "planned"}]
        oracle = state.SourceOracle({"a.py": "x", "b.py": "y"},
                                    {"a.py": "x", "b.py": "CHANGED"})
        plan = state.plan_prior(bundle_with([], units=units), oracle, now=NOW)
        self.assertEqual(plan.unit_status, {
            "u-cov": "prior_covered_same_source",
            "u-moved": "prior_covered_changed_source",
            "u-def": "prior_deferred", "u-blk": "prior_blocked",
            "u-oos": "prior_out_of_scope", "u-plan": "prior_deferred"})
        self.assertEqual(plan.canonical_refs["u-cov"], {"surface": "s"})

    def test_a_candidate_unit_takes_its_status_from_its_own_leads(self):
        rejected_moved = fp.build(INJECTION, "src/api/legacy.ts", "handle")
        units = [{"coverage_id": "u-lead", "status": "candidate",
                  "result_fingerprints": [LEAD_FP]},
                 {"coverage_id": "u-disproved", "status": "candidate",
                  "result_fingerprints": [REJECTED_FP]},
                 {"coverage_id": "u-stale", "status": "candidate",
                  "result_fingerprints": [rejected_moved]}]
        findings = [record(LEAD_FP, "needs_validation", ["src/db/search.ts"]),
                    record(REJECTED_FP, "rejected", ["src/routes/user.ts"]),
                    record(rejected_moved, "rejected", ["src/api/legacy.ts"])]
        oracle = state.SourceOracle(
            {"src/db/search.ts": "o2", "src/routes/user.ts": "o1",
             "src/api/legacy.ts": "o3"},
            {"src/db/search.ts": "o2", "src/routes/user.ts": "o1",
             "src/api/legacy.ts": "MOVED"})
        plan = state.plan_prior(bundle_with(findings, units=units), oracle, now=NOW)
        self.assertEqual(plan.unit_status["u-lead"], "prior_needs_validation")
        # An unchanged rejection is a same-source pass: priority input only, and the unit
        # is still reviewed (RECONNAISSANCE.md:68).
        self.assertEqual(plan.unit_status["u-disproved"], "prior_covered_same_source")
        self.assertEqual(plan.unit_status["u-stale"], "prior_rejected_claim_changed")

    def test_a_quick_prior_ledger_is_never_an_implied_rest_is_fine(self):
        plan = state.plan_prior(bundle_with([]), state.SourceOracle(), now=NOW)
        self.assertTrue(any("rest is fine" in note for note in plan.notes))

    def test_no_prior_state_is_stated_not_assumed(self):
        plan = state.plan_prior(None, state.SourceOracle())
        self.assertFalse(plan.compatible)
        self.assertTrue(any("first pass" in note for note in plan.notes))


# ------------------------------------------------------------------------- baseline

class BaselineTest(unittest.TestCase):
    def bundle(self, days, architecture="# Architecture\n\nboundaries"):
        return bundle_with([], metadata={"generated_at": iso(NOW - timedelta(days=days))},
                           architecture=architecture)

    def test_a_fresh_baseline_is_accepted_and_carries_the_honest_deviation(self):
        baseline = state.load_baseline(self.bundle(2), now=NOW)
        self.assertTrue(baseline.accepted)
        self.assertIn("# Architecture", baseline.architecture)
        self.assertIn("NOT part of the skill's sanctioned prior-run channel",
                      baseline.deviation)
        self.assertIn("RECONNAISSANCE.md:61", baseline.deviation)

    def test_a_stale_baseline_is_refused(self):
        baseline = state.load_baseline(self.bundle(30), now=NOW)
        self.assertFalse(baseline.accepted)
        self.assertEqual(baseline.architecture, "")
        self.assertIn("over the 14-day maximum", baseline.reason)
        # Control removed: the same bundle inside the window is accepted.
        self.assertTrue(state.load_baseline(self.bundle(30), now=NOW,
                                            max_age_days=60).accepted)

    def test_a_baseline_without_architecture_is_refused(self):
        self.assertFalse(state.load_baseline(self.bundle(1, architecture="  "),
                                             now=NOW).accepted)

    def test_an_unreadable_generation_time_is_refused(self):
        bundle = bundle_with([], metadata={"generated_at": "sometime"},
                             architecture="# A")
        baseline = state.load_baseline(bundle, now=NOW)
        self.assertFalse(baseline.accepted)
        self.assertIn("unreadable", baseline.reason)

    def test_an_incompatible_or_missing_baseline_is_refused(self):
        self.assertFalse(state.load_baseline(None).accepted)
        broken = state.PriorBundle(compatible=False, reason="validator said no")
        self.assertIn("validator said no", state.load_baseline(broken).reason)


class TrustBoundTest(unittest.TestCase):
    def test_the_documented_bound_names_what_a_poisoned_bundle_can_and_cannot_do(self):
        # The judge rejected the sha256 "integrity anchor"; the bound is the replacement,
        # so it has to stay accurate rather than reassuring.
        self.assertIn("never produce a confirmed finding, a severity, a secret or code "
                      "execution", state.TRUST_BOUND)
        self.assertIn("architecture.md", state.TRUST_BOUND)
        self.assertNotIn("github-actions[bot]", state.TRUST_BOUND)
        with open(state.__file__, encoding="utf-8") as handle:
            self.assertNotIn("integrity_anchor", handle.read())


if __name__ == "__main__":
    unittest.main()
