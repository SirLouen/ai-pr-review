"""Tests for the trusted publish step.

Everything runs against the loopback fake GitHub in `tests/fakehub.py`; no test here
reaches the network. The bundle these tests publish is built by the real renderer,
because the contract between the two modules is the thing most likely to break: the
renderer owns every string and the anchoring logic, publish owns the live data and the
API calls, and publish never sanitises anything a second time.

Where a test asserts a control, it also asserts the failure that control prevents. The
freshness gate is driven by a moving live head rather than by the workflow input,
because comparing the input to the bundle agrees whatever the pull request did; the
resolve rule is tested in both directions, because "resolve everything" and "resolve
nothing" both pass a one-sided test.
"""
import copy
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import publish as pub
from prreview.security import render
from prreview.security import validate
from prreview.security.github import GitHub
from tests.fakehub import FakeGitHub

TOKEN = "ghs_PublishJobWriteTokenNeverLogged"
REPO = "octo/demo"
PR = 7
HEAD = "a" * 40
BASE = "c" * 40
NEW_HEAD = "b" * 40
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "vendor", "security-audit")

FP_USERS = "sa1:access-control:src/api/users.ts@updateUser"
FP_AUTH = "sa1:access-control:src/middleware/auth.ts@requireAuth"

USERS_PATCH = "\n".join([
    "@@ -40,6 +40,9 @@ router.put('/users/:id',",
    " const id = req.params.id;",
    " const body = req.body;",
    "+  // no ownership comparison",
    "+  await users.update(id, body);",
    "+  res.json({ ok: true });",
    " }",
    " ",
    " export default router;",
])

# The guard on old line 12 is deleted; the new side stops at line 14.
AUTH_PATCH = "\n".join([
    "@@ -10,6 +10,5 @@ export function requireAuth(req, res, next) {",
    " export function requireAuth(req, res, next) {",
    "   const token = req.headers.authorization;",
    "-  if (!verify(token)) return res.status(401).end();",
    "   req.user = decode(token);",
    "   next();",
    " }",
])

LIVE_FILES = [{"filename": "src/api/users.ts", "patch": USERS_PATCH},
              {"filename": "src/middleware/auth.ts", "patch": AUTH_PATCH}]


def record(fingerprint, cited, title="Lead"):
    """The subset of a findings.json record that publish and the renderer read."""
    trace = [{"kind": "entrypoint", "file": cited[0][0], "line": cited[0][1],
              "scope": "router", "description": "Input enters here."}]
    if len(cited) > 1:
        trace.append({"kind": "sink", "file": cited[-1][0], "line": cited[-1][1],
                      "scope": "handler", "description": "It reaches the sink."})
    return {"verdict": "needs_validation", "fingerprint": fingerprint, "title": title,
            "description": "A source-grounded candidate.",
            "claimed_root_cause": "No ownership comparison before the write.",
            "trace": trace,
            "evidence": [{"file": cited[-1][0], "line": cited[-1][1],
                          "description": "The call is unguarded."}],
            "blockers": ["[execution] Nothing was executed in this run."],
            "validation_plan": {"local": "Add a test asserting 403 for another user's id."}}


def digest_for(rec):
    """The dedupe digest the renderer puts in the marker for this record."""
    return render.record_hash(rec)


def rendered(records, diff=None):
    """The bundle text the analyze job would produce, from the real renderer."""
    made = render.RunReport(repository=REPO, pr_number=PR, head_sha=HEAD,
                            merge_base_sha=BASE, findings=records,
                            diff=diff if diff is not None else render.DiffIndex(LIVE_FILES),
                            disclosure=render.Disclosure(mode="all", public=False))
    return (render.inline_comments(made), render.summary_markdown(made),
            render.annotations_sidecar(made))


def legacy_entry(rec, body=None, framed=True):
    """A hand-built `inline.json` entry, for the shapes the renderer never emits."""
    digest = digest_for(rec)
    sink = rec["trace"][-1]
    if body is None:
        body = ("<!-- sa-fp:%s rh:%s -->\n**%s**\n\n%s"
                % (rec["fingerprint"], digest, rec["title"], rec["claimed_root_cause"]))
        if framed:
            body += ("\n\nThis is a partial pass; no code was executed, so it has no "
                     "severity.")
    return {"fingerprint": rec["fingerprint"], "record_hash": digest, "priority": "P1",
            "body": body, "anchor": "line", "path": sink["file"], "line": sink["line"],
            "side": "RIGHT"}


def write_bundle(directory, findings, units=None, metadata=None, summary=None,
                 inline=None, annotations=None):
    """Write a bundle and the digests run-metadata.json must record for it."""
    os.makedirs(directory, exist_ok=True)
    made_inline, made_summary, made_annotations = rendered(findings)
    if inline is None:
        inline = made_inline
    if summary is None:
        summary = made_summary
    if annotations is None:
        annotations = made_annotations
    payloads = {"findings.json": json.dumps(findings),
                "coverage-ledger.json": json.dumps(units if units is not None else []),
                "summary.md": summary,
                "inline.json": json.dumps(inline),
                "pr-annotations.json": json.dumps(annotations)}
    digests = {}
    for name, text in payloads.items():
        data = text.encode("utf-8")
        with open(os.path.join(directory, name), "wb") as stream:
            stream.write(data)
        digests[name] = hashlib.sha256(data).hexdigest()
    meta = {"head_sha": HEAD, "run_id": "pr7-aaaaaaaaaaaa", "run_status": "complete",
            "digests": digests}
    meta.update(metadata or {})
    with open(os.path.join(directory, "run-metadata.json"), "w", encoding="utf-8") as stream:
        json.dump(meta, stream)
    return directory


def gate_for(findings, errors=(), quarantined=()):
    return validate.GateResult(ok=not errors, findings=list(findings),
                               quarantined=list(quarantined), errors=list(errors))


class PublishTestCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeGitHub()
        self.addCleanup(self.fake.close)
        self.state = self.fake.state
        self.state.head_sha = HEAD
        self.state.add_file("src/api/users.ts", USERS_PATCH)
        self.state.add_file("src/middleware/auth.ts", AUTH_PATCH)
        self.logs = []
        self.gh = GitHub(TOKEN, api=self.fake.url, retries=0,
                         sleep=lambda _s: None, log=self.logs.append)
        self.work = tempfile.mkdtemp(prefix="sa-publish-")
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self._bundles = 0

    def publisher(self, **kwargs):
        return pub.Publisher(self.gh, REPO, PR, HEAD, **kwargs)

    def bundle(self, findings, **kwargs):
        self._bundles += 1
        directory = write_bundle(os.path.join(self.work, "bundle%d" % self._bundles),
                                 findings, **kwargs)
        return pub.load_bundle(directory)

    def inline_bodies(self):
        bodies = [c["body"] for c in self.state.review_comments]
        for review in self.state.reviews:
            bodies.extend(c["body"] for c in (review or {}).get("comments") or [])
        return bodies

    def posted_bodies(self):
        bodies = self.inline_bodies()
        bodies.extend(c["body"] for c in self.state.issue_comments)
        bodies.extend(r["body"] for r in self.state.replies)
        return bodies


# --------------------------------------------- anchoring against the live patches

class TestAnchoringFromLivePatches(unittest.TestCase):
    """Publish's half of anchoring: build the index from live patches, ask the renderer.

    The choice itself is the renderer's and is tested there; what is tested here is
    that the live `GET /pulls/{n}/files` shape feeds it correctly.
    """

    def setUp(self):
        self.diff = render.DiffIndex(LIVE_FILES)

    def anchor(self, rec, seeded=()):
        candidates = render.anchor_candidates(rec, seeded=seeded)
        return render.select_anchor(candidates, self.diff, allow_deleted_control=True)

    def test_sink_on_the_right_side_wins(self):
        anchor = self.anchor(record(FP_USERS, [("src/api/users.ts", 40),
                                               ("src/api/users.ts", 44)]))
        self.assertEqual((anchor["path"], anchor["line"], anchor["side"]),
                         ("src/api/users.ts", 44, "RIGHT"))

    def test_deleted_control_falls_to_the_left_side(self):
        """The guard is gone from head, so its cited line is past the new-side hunk."""
        anchor = self.anchor(record(FP_AUTH, [("src/middleware/auth.ts", 15),
                                              ("src/middleware/auth.ts", 15)]))
        self.assertEqual((anchor["path"], anchor["line"], anchor["side"]),
                         ("src/middleware/auth.ts", 12, "LEFT"))

    def test_the_window_is_the_control(self):
        """Control removed: far from any removal there is no LEFT anchor to find."""
        anchor = self.anchor(record(FP_AUTH, [("src/middleware/auth.ts", 400),
                                              ("src/middleware/auth.ts", 400)]))
        self.assertEqual(anchor["anchor"], "file")

    def test_file_level_when_no_line_is_in_the_diff(self):
        anchor = self.anchor(record(FP_USERS, [("src/api/users.ts", 900),
                                               ("src/api/users.ts", 901)]))
        self.assertEqual(anchor["anchor"], "file")
        self.assertIsNone(anchor["line"])

    def test_no_anchor_when_the_file_is_not_in_the_pr(self):
        self.assertEqual(self.anchor(record("sa1:x:src/other.ts@f",
                                            [("src/other.ts", 3)]))["anchor"], "summary")

    def test_the_bundles_claim_is_only_a_hint(self):
        """A seeded anchor the live patch rejects does not become a comment."""
        rec = record("sa1:x:src/other.ts@f", [("src/other.ts", 3)])
        self.assertEqual(self.anchor(rec, seeded=[("src/other.ts", 3)])["anchor"],
                         "summary")
        anchor = self.anchor(rec, seeded=[("src/api/users.ts", 43)])
        self.assertEqual((anchor["path"], anchor["line"]), ("src/api/users.ts", 43))

    def test_a_line_the_patch_never_shows_is_refused(self):
        """The hunk header claims lines 40-48; the patch body only reaches 47."""
        self.assertTrue(self.diff.right("src/api/users.ts", 47))
        self.assertFalse(self.diff.right("src/api/users.ts", 48))

    def test_file_level_payload_never_travels_inside_a_review(self):
        """subject_type "file" is rejected inside a review's comments[] array."""
        anchor = pub.file_anchor("src/api/users.ts")
        self.assertNotIn("subject_type", pub.review_comment_payload(anchor, "body"))
        self.assertEqual(pub.standalone_payload(anchor, "body", HEAD)["subject_type"],
                         "file")
        line = {"anchor": "line", "path": "src/api/users.ts", "line": 44,
                "side": "RIGHT"}
        self.assertNotIn("subject_type", pub.standalone_payload(line, "body", HEAD))
        self.assertEqual(pub.review_comment_payload(line, "body")["side"], "RIGHT")


# ----------------------------------------------------------------- bundle gates

class TestBundleLoading(PublishTestCase):
    def test_missing_required_file_is_refused(self):
        directory = os.path.join(self.work, "empty")
        os.makedirs(directory)
        with self.assertRaises(pub.PublishError):
            pub.load_bundle(directory)

    def test_malformed_head_sha_is_refused(self):
        directory = write_bundle(os.path.join(self.work, "b1"), [],
                                 metadata={"head_sha": "not-a-sha"})
        with self.assertRaises(pub.PublishError):
            pub.load_bundle(directory)

    def test_oversize_file_is_refused(self):
        directory = write_bundle(os.path.join(self.work, "b2"), [])
        with open(os.path.join(directory, "summary.md"), "w", encoding="utf-8") as stream:
            stream.write("x" * (pub.BUNDLE_FILES["summary.md"] + 1))
        with self.assertRaises(pub.PublishError):
            pub.load_bundle(directory)

    def test_unknown_file_is_ignored(self):
        directory = write_bundle(os.path.join(self.work, "b3"), [])
        with open(os.path.join(directory, "transcript.txt"), "w", encoding="utf-8") as s:
            s.write("model prose")
        self.assertNotIn("transcript.txt", pub.load_bundle(directory).files)

    def test_integrity_catches_a_tampered_file(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        directory = write_bundle(os.path.join(self.work, "b4"), [rec])
        self.assertEqual(pub.verify_integrity(pub.load_bundle(directory)), [])
        with open(os.path.join(directory, "findings.json"), "w", encoding="utf-8") as stream:
            json.dump([record(FP_USERS, [("src/api/users.ts", 44)],
                              title="swapped after the fact")], stream)
        messages = pub.verify_integrity(pub.load_bundle(directory))
        self.assertTrue(any("findings.json" in m for m in messages))

    def test_integrity_needs_digests_at_all(self):
        directory = write_bundle(os.path.join(self.work, "b5"), [], metadata={"digests": {}})
        self.assertTrue(pub.verify_integrity(pub.load_bundle(directory)))


class TestExistenceRecheck(PublishTestCase):
    def test_absent_cited_file_is_quarantined_not_fatal(self):
        self.state.present_paths = {"src/api/users.ts"}
        findings = [record(FP_USERS, [("src/api/users.ts", 44)]),
                    record("sa1:x:src/gone.ts@f", [("src/gone.ts", 3)])]
        missing = pub.missing_cited_paths(self.gh, REPO, HEAD, findings)
        self.assertEqual(missing, {"src/gone.ts"})
        gate = gate_for(findings)
        self.assertEqual(pub.quarantine_missing(gate, missing), ["sa1:x:src/gone.ts@f"])
        self.assertEqual([r["fingerprint"] for r in gate.findings], [FP_USERS])

    def test_a_path_with_a_hash_is_percent_encoded(self):
        self.state.present_paths = {"src/a#b.ts"}
        findings = [record("sa1:x:h@f", [("src/a#b.ts", 1)])]
        self.assertEqual(pub.missing_cited_paths(self.gh, REPO, HEAD, findings), set())
        self.assertIn("/repos/octo/demo/contents/src/a%23b.ts",
                      [r["path"] for r in self.state.requests])

    def test_a_quarantined_record_cannot_be_published_from_inline_json(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec])
        gate = gate_for([], quarantined=[validate.Quarantined(FP_USERS, ["gone"])])
        result = self.publisher().publish(bundle, gate)
        self.assertEqual(self.state.reviews, [])
        self.assertEqual(result.posted, 0)
        self.assertTrue(any("removed by the publish-side gate" in m
                            for m in result.messages))

    def test_nothing_quarantined_means_nothing_dropped(self):
        """Control removed: the same bundle with an empty quarantine posts its lead."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec])
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted_line, 1)


# ------------------------------------------------------------- the freshness gate

class TestFreshness(PublishTestCase):
    def test_stale_head_publishes_only_the_superseded_notice(self):
        self.state.head_sha = NEW_HEAD
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.status, "superseded")
        self.assertEqual(self.state.reviews, [])
        self.assertEqual(self.state.review_comments, [])
        self.assertEqual(len(self.state.issue_comments), 1)
        self.assertIn("superseded", self.state.issue_comments[0]["body"])
        self.assertNotIn("No ownership comparison", self.state.issue_comments[0]["body"])
        self.assertEqual(result.conclusion, "neutral")

    def test_matching_live_head_publishes(self):
        """Control removed: with the live head equal to the analysed head, leads post."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.status, "published")
        self.assertEqual(result.posted_line, 1)

    def test_the_gate_reads_the_live_api_not_the_workflow_input(self):
        """The input and run-metadata share an origin, so only the live head disagrees."""
        self.state.head_sha = NEW_HEAD
        publisher = self.publisher()
        self.assertFalse(publisher.is_fresh())
        self.assertEqual(publisher.live_head(), NEW_HEAD)
        self.assertIn("/repos/octo/demo/pulls/7", [r["path"] for r in self.state.requests])

    def test_head_moving_mid_run_aborts_before_the_write(self):
        # is_fresh, the PR fetch, then the re-check immediately before the review write.
        self.state.head_sequence = [HEAD, HEAD] + [NEW_HEAD] * 8
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.status, "superseded")
        self.assertEqual(self.state.reviews, [])

    def test_commit_id_is_pinned_to_the_analysed_head(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(self.state.reviews[0]["commit_id"], HEAD)


# ------------------------------------------------------------------- 422 fallback

class TestAnchorFallback(PublishTestCase):
    def lead(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        return rec, self.bundle([rec])

    def test_review_422_falls_back_to_one_comment_at_a_time(self):
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 422,
                             "line must be part of the diff")
        rec, bundle = self.lead()
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted_line, 1)
        self.assertEqual(len(self.state.review_comments), 1)
        self.assertEqual(self.state.review_comments[0]["commit_id"], HEAD)

    def test_line_422_falls_back_to_a_file_level_comment(self):
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 422, "nope")
        self.state.fail_once("POST /repos/octo/demo/pulls/7/comments", 422, "nope")
        rec, bundle = self.lead()
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted_file, 1)
        self.assertEqual(self.state.review_comments[0]["subject_type"], "file")

    def test_file_422_falls_back_to_summary_only(self):
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 422, "nope")
        for _ in range(2):
            self.state.fail_once("POST /repos/octo/demo/pulls/7/comments", 422, "nope")
        rec, bundle = self.lead()
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted, 0)
        self.assertEqual(result.summary_only, [FP_USERS])
        self.assertIn("could not be anchored", self.state.issue_comments[-1]["body"])

    def test_a_non_422_error_is_not_swallowed(self):
        """Control removed: only a 422 means "the anchor is wrong"."""
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 500, "server error")
        rec, bundle = self.lead()
        with self.assertRaises(Exception):
            self.publisher().publish(bundle, gate_for([rec]))

    def test_unanchorable_lead_goes_straight_to_the_summary(self):
        rec = record("sa1:x:src/absent.ts@f", [("src/absent.ts", 4)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.summary_only, ["sa1:x:src/absent.ts@f"])
        self.assertEqual(self.state.reviews, [])

    def test_the_live_patch_overrides_the_bundles_own_anchor(self):
        """The analyze job anchored at line 44; the live diff no longer has it."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec])
        self.assertEqual(bundle.inline[0]["line"], 44)
        self.state.files = [{"filename": "src/api/users.ts", "status": "modified",
                             "patch": "@@ -1,1 +1,2 @@\n context\n+added\n"}]
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted_file, 1)
        self.assertEqual(self.state.review_comments[0]["subject_type"], "file")


# -------------------------------------------------------------------- deduping

class TestDedupe(PublishTestCase):
    def existing_comment(self, reference, digest, text="an older wording", line=44):
        body = "<!-- sa-fp:%s rh:%s -->\n%s" % (reference, digest, text)
        return self.state.add_review_comment(body, path="src/api/users.ts", line=line)

    def test_identical_lead_is_not_reposted(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        self.existing_comment(FP_USERS, digest_for(rec))
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.posted, 0)
        self.assertEqual(self.state.minimized, [])

    def test_the_marker_carries_the_fingerprint_so_it_survives_a_push(self):
        """A per-run handle would change whenever the run's lead set changed, and every
        comment would be reposted; the fingerprint does not move."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        other = record(FP_AUTH, [("src/middleware/auth.ts", 11)])
        first = self.bundle([rec])
        second = self.bundle([other, rec])          # a second lead, found later
        reference, digest = pub.parse_marker(
            [e for e in second.inline if e["fingerprint"] == FP_USERS][0]["body"])
        self.assertEqual(reference, FP_USERS)
        self.assertEqual(pub.parse_marker(first.inline[0]["body"]), (FP_USERS, digest))
        self.existing_comment(FP_USERS, digest)
        result = self.publisher().publish(second, gate_for([other, rec]))
        self.assertEqual(result.unchanged, 1)
        self.assertEqual(result.posted_line, 1)     # only the new lead

    def test_changed_lead_posts_a_new_comment_and_hides_the_old_one(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        old = self.existing_comment(FP_USERS, "0" * 16)
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.posted_line, 1)
        self.assertIn((old["node_id"], "OUTDATED"), self.state.minimized)
        self.assertNotIn((old["node_id"], "RESOLVED"), self.state.minimized)

    def test_an_outdated_anchor_supersedes_even_with_identical_text(self):
        """GitHub reports line: null once it drops an anchor; that comment is stale."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        old = self.existing_comment(FP_USERS, digest_for(rec), line=None)
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.posted_line, 1)
        self.assertIn((old["node_id"], "OUTDATED"), self.state.minimized)

    def test_another_accounts_marker_is_ignored(self):
        """Any workflow posts as github-actions[bot], so a marker never suppresses."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        body = "<!-- sa-fp:%s rh:%s -->\ntext" % (FP_USERS, digest_for(rec))
        self.state.add_review_comment(body, path="src/api/users.ts", login="someone-else")
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.unchanged, 0)
        self.assertEqual(result.posted_line, 1)

    def test_the_digest_comes_from_the_marker_not_from_the_head(self):
        """Otherwise every push would repost every lead unchanged."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec])
        first, _ = pub.build_inline(bundle, REPO, HEAD)
        second, _ = pub.build_inline(bundle, REPO, NEW_HEAD)
        self.assertEqual(first[0].digest, second[0].digest)
        self.assertEqual(first[0].digest, digest_for(rec))

    def test_summary_comment_is_new_each_run_and_hides_the_earlier_one(self):
        earlier = self.state.add_issue_comment(
            (render.MARKER % "pr7-old") + "\nprevious run")
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(len(self.state.issue_comments), 2)
        self.assertIn((earlier["node_id"], "OUTDATED"), self.state.minimized)


# --------------------------------------------- a lead that stopped being reported

class TestRetireAbsent(PublishTestCase):
    def setup_absent(self, source_state):
        body = "<!-- sa-fp:%s rh:%s -->\nthe earlier wording" % (FP_AUTH, "1" * 16)
        comment = self.state.add_review_comment(body, path="src/middleware/auth.ts")
        thread = self.state.add_thread(comment)
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec], metadata={"prior_source_state": source_state})
        result = self.publisher().publish(bundle, gate_for([rec]))
        return comment, thread, result

    def test_unchanged_source_does_not_resolve_the_thread(self):
        comment, thread, result = self.setup_absent({FP_AUTH: "unchanged"})
        self.assertEqual(self.state.resolved, [])
        self.assertNotIn(thread["id"], self.state.resolved)
        self.assertEqual(result.suspected_suppression, [FP_AUTH])
        self.assertIn((comment["node_id"], "OUTDATED"), self.state.minimized)
        self.assertNotIn((comment["node_id"], "RESOLVED"), self.state.minimized)
        self.assertIn("not re-reported", self.state.replies[0]["body"].lower())
        self.assertIn("Not re-reported, source unchanged",
                      self.state.issue_comments[-1]["body"])

    def test_an_unknown_source_state_is_treated_as_unchanged(self):
        """Fail closed: publish cannot see blobs, so silence never means "fixed"."""
        _comment, _thread, result = self.setup_absent({})
        self.assertEqual(self.state.resolved, [])
        self.assertEqual(result.suspected_suppression, [FP_AUTH])

    def test_changed_source_does_resolve_the_thread(self):
        """Control removed: only FIXED code resolves, and this is what fixed looks like."""
        comment, thread, result = self.setup_absent({FP_AUTH: "changed"})
        self.assertEqual(self.state.resolved, [thread["id"]])
        self.assertEqual(result.suspected_suppression, [])
        self.assertIn((comment["node_id"], "RESOLVED"), self.state.minimized)
        self.assertIn("no longer reported", self.state.replies[0]["body"].lower())

    def test_prior_state_is_keyed_by_the_same_fingerprint_the_marker_carries(self):
        """The marker, the current-lead set and prior_source_state are one namespace;
        a handle in any of them would retire the wrong thread."""
        comment, _thread, result = self.setup_absent({FP_AUTH: "changed"})
        reference, _digest = pub.parse_marker(comment["body"])
        self.assertEqual(reference, FP_AUTH)
        self.assertEqual(result.suspected_suppression, [])

    def test_a_still_reported_lead_is_never_retired(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        body = "<!-- sa-fp:%s rh:%s -->\nolder" % (FP_USERS, "2" * 16)
        comment = self.state.add_review_comment(body, path="src/api/users.ts")
        self.state.add_thread(comment)
        bundle = self.bundle([rec], metadata={"prior_source_state": {FP_USERS: "changed"}})
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(self.state.resolved, [])
        self.assertEqual(result.suspected_suppression, [])
        self.assertEqual(result.posted_line, 1)


# ------------------------------------------------------------------- check runs

class TestCheckRuns(PublishTestCase):
    def test_start_creates_an_in_progress_run_before_analyze(self):
        run = pub.start_check_run(self.gh, REPO, HEAD)
        self.assertEqual(run["status"], "in_progress")
        self.assertEqual(run["head_sha"], HEAD)
        self.assertEqual(run["name"], pub.CHECK_NAME)
        self.assertIn("does not block a merge", run["output"]["summary"])

    def test_a_stuck_run_is_what_a_cancelled_analyze_leaves_behind(self):
        pub.start_check_run(self.gh, REPO, HEAD)
        self.assertEqual(self.state.check_runs[0]["status"], "in_progress")
        self.assertNotIn("conclusion", self.state.check_runs[0])

    def test_publish_completes_the_run_the_start_step_made(self):
        started = pub.start_check_run(self.gh, REPO, HEAD)
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher(check_run_id=started["id"]).publish(
            self.bundle([rec]), gate_for([rec]))
        run = self.state.check_runs[0]
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["conclusion"], "neutral")
        self.assertEqual(result.conclusion, "neutral")
        self.assertEqual(len(self.state.check_runs), 1)

    def test_the_run_is_found_by_head_and_name_when_no_id_is_passed(self):
        started = pub.start_check_run(self.gh, REPO, HEAD)
        self.assertEqual(pub.find_check_run(self.gh, REPO, HEAD), started["id"])
        self.publisher().publish(self.bundle([]), gate_for([]))
        self.assertEqual(len(self.state.check_runs), 1)
        self.assertEqual(self.state.check_runs[0]["conclusion"], "success")

    def test_a_missing_start_step_does_not_lose_the_check(self):
        self.publisher().publish(self.bundle([]), gate_for([]))
        self.assertEqual(len(self.state.check_runs), 1)
        self.assertEqual(self.state.check_runs[0]["status"], "completed")

    def test_conclusion_policy(self):
        self.assertEqual(pub.decide_conclusion(True, True, 0), "success")
        self.assertEqual(pub.decide_conclusion(True, True, 3), "neutral")
        self.assertEqual(pub.decide_conclusion(True, False, 0), "neutral")
        self.assertEqual(pub.decide_conclusion(False, True, 0), "neutral")
        self.assertEqual(pub.decide_conclusion(True, True, 0, superseded=True), "neutral")
        self.assertEqual(pub.decide_conclusion(True, True, 2, fail_on="any-lead"), "failure")
        # opt-in failure never overrides an incomplete or superseded run
        self.assertEqual(pub.decide_conclusion(True, False, 2, fail_on="any-lead"), "neutral")

    def test_never_success_on_an_incomplete_run(self):
        bundle = self.bundle([], metadata={"run_status": "incomplete",
                                           "incomplete_reason": "validation_budget_exhausted"})
        result = self.publisher().publish(bundle, gate_for([]))
        self.assertEqual(result.conclusion, "neutral")
        self.assertIn("incomplete", self.state.check_runs[0]["output"]["title"])
        self.assertIn("Incomplete run", self.state.issue_comments[0]["body"])

    def test_an_incomplete_bundle_that_does_not_say_so_is_still_marked(self):
        """The bundle is untrusted: a rendered summary that omitted the gap does not
        get to make the run look complete."""
        bundle = self.bundle([], summary=(render.MARKER % "pr7") + "\n"
                                         + render.PARTIAL_NOTICE,
                             metadata={"run_status": "incomplete",
                                       "incomplete_reason": "tool_budget"})
        self.publisher().publish(bundle, gate_for([]))
        self.assertIn("Incomplete run", self.state.issue_comments[0]["body"])

    def test_fail_on_is_opt_in(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher(fail_on="any-lead").publish(self.bundle([rec]),
                                                            gate_for([rec]))
        self.assertEqual(result.conclusion, "failure")
        self.assertIn("Do not make it a required check",
                      self.state.check_runs[0]["output"]["summary"])

    def test_the_default_never_fails_the_check(self):
        """Control removed: the same run under the default conclusion is neutral."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.conclusion, "neutral")

    def test_an_unknown_fail_on_value_falls_back_to_never(self):
        self.assertEqual(self.publisher(fail_on="whatever").fail_on, "never")


# -------------------------------------------------------- a bundle that fails

class TestGateFailure(PublishTestCase):
    def test_a_failing_gate_posts_only_the_incomplete_notice(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        errors = ['$[0].verdict: "confirmed" requires an observed result']
        result = self.publisher().publish(self.bundle([rec]),
                                          gate_for([rec], errors=errors))
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.state.reviews, [])
        self.assertEqual(self.state.review_comments, [])
        self.assertEqual(len(self.state.issue_comments), 1)
        body = self.state.issue_comments[0]["body"]
        self.assertIn("nothing published", body.lower())
        self.assertIn("observed result", body)
        self.assertNotIn("No ownership comparison", body)      # no lead text at all
        self.assertEqual(result.conclusion, "neutral")

    def test_a_passing_gate_does_publish(self):
        """Control removed: the same bundle with no gate errors posts its lead."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertEqual(result.status, "published")
        self.assertEqual(result.posted_line, 1)

    def test_a_bundle_for_another_head_is_refused(self):
        directory = write_bundle(os.path.join(self.work, "other"),
                                 [record(FP_USERS, [("src/api/users.ts", 44)])],
                                 metadata={"head_sha": NEW_HEAD})
        result = pub.run(self.gh, REPO, PR, HEAD, directory, None, VENDOR)
        self.assertEqual(result.status, "blocked")
        self.assertEqual(self.state.reviews, [])

    def test_a_missing_bundle_directory_is_a_notice_not_a_crash(self):
        result = pub.run(self.gh, REPO, PR, HEAD, os.path.join(self.work, "nope"),
                         None, VENDOR)
        self.assertEqual(result.status, "blocked")
        self.assertIn("nothing published", self.state.issue_comments[0]["body"].lower())

    def test_a_tampered_bundle_never_reaches_the_validators(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        directory = write_bundle(os.path.join(self.work, "tampered"), [rec])
        with open(os.path.join(directory, "summary.md"), "w", encoding="utf-8") as stream:
            stream.write("swapped in the artifact store")
        result = pub.run(self.gh, REPO, PR, HEAD, directory, None, VENDOR)
        self.assertEqual(result.status, "blocked")
        self.assertTrue(any("digest" in m for m in result.messages))


# ------------------------------------------------------------------ output text

class TestPostedText(PublishTestCase):
    """Publish writes no text. What it posts is the renderer's, unaltered or rebuilt."""

    def test_the_renderers_body_is_posted_byte_for_byte(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)],
                     title="Tea & crumpets in <b>#4</b>")
        bundle = self.bundle([rec])
        expected = bundle.inline[0]["body"]
        self.publisher().publish(bundle, gate_for([rec]))
        posted = self.state.reviews[0]["comments"][0]["body"]
        self.assertEqual(posted, expected)
        # Escaped exactly once. A second sanitiser pass here would show the reader
        # `&amp;amp;` and `\\*` instead of `&` and the bold marker.
        self.assertIn("Tea &amp; crumpets", posted)
        self.assertNotIn("&amp;amp;", posted)
        self.assertNotIn("&#38;", posted)

    def test_the_renderers_summary_is_posted_byte_for_byte(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)], title="Tea & crumpets")
        bundle = self.bundle([rec])
        self.publisher().publish(bundle, gate_for([rec]))
        posted = self.state.issue_comments[-1]["body"]
        self.assertTrue(posted.startswith(bundle.summary.strip()))
        self.assertIn("Tea &amp; crumpets", posted)
        self.assertNotIn("&amp;amp;", posted)

    def test_publish_never_re_escapes_even_a_hostile_body(self):
        """The control: a second escaping pass is detectable, and does not happen."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec])
        once = bundle.inline[0]["body"]
        self.assertNotEqual(once, render.sanitize_for_github(once, limit=None,
                                                             allow_newlines=True))
        self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(self.state.reviews[0]["comments"][0]["body"], once)

    def test_a_body_that_is_not_inert_is_rebuilt_by_the_renderer(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        entry = legacy_entry(rec, body="<!-- sa-fp:%s rh:%s -->\npartial severity: see "
                                       "![x](https://evil.example/x)"
                                       % (FP_USERS, digest_for(rec)))
        bundle = self.bundle([rec], inline=[entry])
        leads, messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertTrue(any("rebuilt by the renderer" in m for m in messages))
        self.assertNotIn("![", leads[0].body)
        self.assertIn("No ownership comparison", leads[0].body)
        self.assertEqual(render.inert_problems(leads[0].body), [])

    def test_the_inertness_check_is_the_control(self):
        """Control removed: without it the image embed would be posted verbatim."""
        self.assertTrue(render.inert_problems("see ![x](https://evil/x)"))
        self.assertEqual(render.inert_problems("a plain sentence with `code`."), [])

    def test_a_body_that_lost_its_framing_is_rebuilt_not_patched(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec], inline=[legacy_entry(rec, framed=False)])
        leads, messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertTrue(any("no partial-pass framing" in m for m in messages))
        self.assertIn("partial, diff-scoped, quick-profile", leads[0].body)
        self.assertEqual(render.framing_problems(leads[0].body), [])
        # Rebuilt, not appended to: the body is the renderer's whole lead body.
        self.assertIn("To settle it locally", leads[0].body)

    def test_a_rebuilt_bodys_marker_is_the_one_used_for_dedupe(self):
        """Otherwise the posted marker and the dedupe key would disagree and the next
        push would repost the comment."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        bundle = self.bundle([rec], inline=[legacy_entry(rec, framed=False)])
        leads, _messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertEqual(pub.parse_marker(leads[0].body),
                         (leads[0].reference, leads[0].digest))

    def test_a_lead_whose_record_is_gone_cannot_be_rebuilt_and_is_summary_only(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        entry = legacy_entry(rec, body="<!-- sa-fp:%s rh:%s -->\npartial severity "
                                       "![x](https://evil.example/x)"
                                       % (FP_USERS, digest_for(rec)))
        bundle = self.bundle([rec], inline=[entry])
        bundle.findings = []
        leads, messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertEqual(leads, [])
        self.assertTrue(any("summary-only" in m for m in messages))

    def test_hostile_record_text_never_reaches_a_posted_body(self):
        hostile = record(FP_USERS, [("src/api/users.ts", 44)],
                         title="Bug owned by @security-team see #4242")
        hostile["claimed_root_cause"] = "</details><details><summary>Approved</summary>"
        bundle = self.bundle([hostile])
        self.publisher().publish(bundle, gate_for([hostile]))
        bodies = self.posted_bodies()
        self.assertTrue(bodies)
        for body in bodies:
            visible = re.sub(r"<!--.*?-->", "", body, flags=re.S)
            self.assertNotIn("@security-team", visible)
            self.assertNotIn("#4242", visible)
            self.assertNotIn("<summary>Approved", visible)
        self.assertTrue(any("&#64;security-team" in body for body in bodies))

    def test_every_posted_surface_frames_the_run_as_partial(self):
        """Summary, inline body, file-level body and check output, in one run."""
        anchored = record(FP_USERS, [("src/api/users.ts", 44)])
        file_level = record(FP_AUTH, [("src/middleware/auth.ts", 900)])
        bundle = self.bundle([anchored, file_level])
        self.publisher().publish(bundle, gate_for([anchored, file_level]))

        summary = self.state.issue_comments[-1]["body"]
        self.assertIn("(partial)", summary)
        self.assertIn("quick-profile", summary)
        self.assertIn("not a clean bill", summary)
        self.assertIn("not** a severity", summary)

        inline = self.state.reviews[0]["comments"][0]["body"]
        standalone = self.state.review_comments[0]["body"]
        self.assertEqual(self.state.review_comments[0]["subject_type"], "file")
        check = self.state.check_runs[0]["output"]
        for text in (summary, inline, standalone, check["summary"]):
            self.assertEqual(render.framing_problems(text), [], text[:120])
            self.assertEqual(render.inert_problems(text), [], text[:120])
        self.assertIn("does not block a merge by default", inline)
        self.assertIn("Do not make it a required check", check["summary"])

    def test_the_framing_check_is_not_vacuous(self):
        """Control removed: a body with neither word fails, which is why it is rebuilt."""
        self.assertEqual(render.framing_problems("A lead in src/api/users.ts."),
                         ["no partial-pass framing"])

    def test_the_local_plan_is_quoted_not_a_runnable_block(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        body = render.rebuild_lead_body(rec, FP_USERS, repository=REPO, head_sha=HEAD)
        self.assertIn("model-written, unverified", body)
        self.assertIn("> Add a test", body)
        self.assertNotIn("```", body)

    def test_run_id_in_the_marker_cannot_carry_markup(self):
        bundle = self.bundle([], summary="Bundle summary.",
                             metadata={"run_id": "pr7 --><script>x</script>"})
        body = render.framed_summary(bundle.summary, run_id=bundle.run_id,
                                     head_sha=HEAD)
        marker = body.split("\n")[0]
        self.assertTrue(marker.startswith("<!-- ai-security-review v1 run="))
        self.assertTrue(marker.endswith("-->"))
        self.assertEqual(marker.count("<"), 1)
        self.assertEqual(marker.count(">"), 1)

    def test_comment_length_is_capped(self):
        bundle = self.bundle([], summary="x" * (render.SUMMARY_LIMIT * 2))
        posted = render.framed_summary(bundle.summary, run_id=bundle.run_id,
                                       head_sha=HEAD)
        self.assertLessEqual(len(posted), render.SUMMARY_LIMIT)

    def test_an_oversize_inline_body_is_capped_before_it_is_checked(self):
        """A cap applied after the check could remove the framing it just verified."""
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        entry = legacy_entry(rec)
        entry["body"] += "\n" + "\n".join("padding %d" % n for n in range(4000))
        bundle = self.bundle([rec], inline=[entry])
        leads, _messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertLessEqual(len(leads[0].body), render.INLINE_LIMIT)
        self.assertEqual(render.framing_problems(leads[0].body), [])

    def test_notices_carry_no_lead_text(self):
        notice = render.gate_notice(HEAD, ["$[0].trace[1].line: 900 is outside"])
        self.assertIn("not a clean result", notice)
        self.assertIn("900 is outside", notice)
        self.assertIn("does not block a merge", notice)

    def test_no_inline_json_means_summary_only(self):
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        result = self.publisher().publish(self.bundle([rec], inline=[]), gate_for([rec]))
        self.assertEqual(self.state.reviews, [])
        self.assertTrue(any("no inline.json" in m for m in result.messages))

    def test_an_entry_with_no_candidates_still_anchors(self):
        """An older bundle carries only its own claim; the record supplies the rest."""
        rec = record(FP_USERS, [("src/api/users.ts", 40), ("src/api/users.ts", 44)])
        entry = legacy_entry(rec)
        self.assertNotIn("candidates", entry)
        bundle = self.bundle([rec], inline=[entry])
        leads, _messages = pub.build_inline(bundle, REPO, HEAD)
        self.assertEqual(leads[0].candidates[0], ("src/api/users.ts", 44))
        result = self.publisher().publish(bundle, gate_for([rec]))
        self.assertEqual(result.posted_line, 1)


# --------------------------------------------------------------- token hygiene

class TestTokenNeverLogged(PublishTestCase):
    def test_no_log_line_or_posted_body_carries_the_token(self):
        self.state.fail_once("POST /repos/octo/demo/pulls/7/reviews", 422, "nope")
        first = record(FP_USERS, [("src/api/users.ts", 44)])
        second = record(FP_AUTH, [("src/middleware/auth.ts", 11)])
        bundle = self.bundle([first, second], metadata={"prior_source_state": {}})
        self.publisher().publish(bundle, gate_for([first, second]))
        self.assertTrue(self.logs)
        for line in self.logs:
            self.assertNotIn(TOKEN, line)
        for body in self.posted_bodies():
            self.assertNotIn(TOKEN, body)

    def test_an_error_path_does_not_leak_it_either(self):
        for _ in range(6):
            self.state.fail_once("POST /graphql", 500, "the token %s failed" % TOKEN)
        rec = record(FP_USERS, [("src/api/users.ts", 44)])
        self.publisher().publish(self.bundle([rec]), gate_for([rec]))
        self.assertTrue(self.logs)
        for line in self.logs:
            self.assertNotIn(TOKEN, line)


# ------------------------------------------------- the real vendored validators

@unittest.skipUnless(shutil.which("node"), "node is required for the vendored validators")
class TestRealRevalidation(PublishTestCase):
    """One end-to-end pass through validate.final_gate, so the wiring is real."""

    @classmethod
    def setUpClass(cls):
        cls.validator = validate.Validator(VENDOR)
        cls.validator.ping()
        cls.refs = {"surface": "src/api/users.ts#PUT /users/:id",
                    "boundary": "src/api/users.ts#updateUser",
                    "subsystem": "profile/quick/all-in-scope-subsystems",
                    "attack_class": "ATTACK-CLASSES.md#Access control"}
        cls.coverage_id = cls.validator.coverage_id(cls.refs)

    @classmethod
    def tearDownClass(cls):
        cls.validator.close()

    def valid_record(self):
        return {
            "verdict": "needs_validation",
            "fingerprint": FP_USERS,
            "title": "PUT /users/:id may update another user's profile",
            "description": "The route writes the record named by :id with no ownership check.",
            "claimed_root_cause": "No ownership comparison before users.update.",
            "trace": [{"kind": "entrypoint", "file": "src/api/users.ts", "line": 40,
                       "scope": "router.put", "description": "A caller supplies :id."},
                      {"kind": "sink", "file": "src/api/users.ts", "line": 44,
                       "scope": "updateUser", "description": "users.update runs unguarded."}],
            "evidence": [{"file": "src/api/users.ts", "line": 44,
                          "description": "The call at this line has no guard."}],
            "blockers": ["[execution] This run executes no repository code, so no bounded "
                         "local result establishes the behaviour."],
            "validation_plan": {"local": "Add a test that calls the route and asserts 403."},
        }

    def valid_unit(self):
        return {
            "coverage_id": self.coverage_id,
            "canonical_refs": dict(self.refs),
            "surface": self.refs["surface"],
            "boundary": self.refs["boundary"],
            "subsystem": "All in-scope subsystems (quick)",
            "attack_class": "Access control",
            "starting_paths": ["src/api/users.ts"],
            "ordinary_attack_class_block": self.refs["attack_class"],
            "selected_companion_blocks": [],
            "excluded_blocks": [],
            "prior_status": "none",
            "attempts": [],
            "wave": 1,
            "status": "candidate",
            "agent_id": "hunter-1",
            "reviewed_paths": ["src/api/users.ts"],
            "local_checks": [{"agent_id": "hunter-1",
                              "reviewed_paths": ["src/api/users.ts"],
                              "invariant": "Only the owner updates a user record.",
                              "method": "source",
                              "result": "Re-read of the changed lines; no guard is present.",
                              "artifact": None}],
            "result_fingerprints": [FP_USERS],
            "unresolved": ["Gateway ownership enforcement is not source-visible."],
        }

    def test_a_valid_bundle_survives_revalidation_and_publishes(self):
        bundle = self.bundle([self.valid_record()], units=[self.valid_unit()])
        gate = pub.revalidate(bundle, self.validator, VENDOR)
        self.assertEqual(gate.errors, [])
        self.assertTrue(gate.ok)
        result = self.publisher().publish(bundle, gate)
        self.assertEqual(result.status, "published")
        self.assertEqual(result.posted_line, 1)

    def test_a_confirmed_verdict_is_quarantined_and_no_lead_is_posted(self):
        bad = copy.deepcopy(self.valid_record())
        bad["verdict"] = "confirmed"
        bundle = self.bundle([bad], units=[self.valid_unit()])
        gate = pub.revalidate(bundle, self.validator, VENDOR)
        self.assertTrue(gate.quarantined)
        self.assertEqual(gate.findings, [])
        result = self.publisher().publish(bundle, gate)
        self.assertEqual(self.state.reviews, [])
        self.assertEqual(result.posted, 0)

    def test_the_vendored_validator_alone_would_accept_it(self):
        """Control removed: the schema is not what rejects a fabricated confirmation."""
        bad = copy.deepcopy(self.valid_record())
        bad["verdict"] = "confirmed"
        bad.update({
            "root_cause": "No ownership comparison before users.update.",
            "intended_behavior": "Only the owner or an admin updates a user record.",
            "conditions": [],
            "execution": {"attacker_perspective": "An authenticated user of the API.",
                          "payloads": ["PUT /users/2"],
                          "instructions": ["Send the request as user 1."],
                          "observed_result": "Not executed; inferred from source."},
            "remediation": {"strategy": "Compare req.user.id with req.params.id."},
            "severity": {"likelihood": {"score": "high", "reason": "Any authenticated user."},
                         "impact": {"score": "high", "reason": "Profile takeover."},
                         "overall_severity": "high"},
            "confidence": {"score": "high", "reason": "The route body is fully visible."},
        })
        for key in ("claimed_root_cause", "blockers", "validation_plan"):
            bad.pop(key, None)
        self.assertEqual(self.validator.validate_findings([bad]), [])

    def test_a_duplicate_fingerprint_does_not_void_the_other_lead(self):
        first = self.valid_record()
        duplicate = copy.deepcopy(first)
        duplicate["title"] = "A second record on the same fingerprint"
        bundle = self.bundle([first, duplicate], units=[self.valid_unit()])
        gate = pub.revalidate(bundle, self.validator, VENDOR)
        self.assertLessEqual(len(gate.findings), 1)
        self.assertTrue(gate.ok)


if __name__ == "__main__":
    unittest.main()
