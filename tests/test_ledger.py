"""Tests for the coverage ledger.

Every positive test ends at the vendored `validate-coverage-ledger.cjs`, because that
file -- not this repository -- decides whether a ledger is a coverage claim. Every
negative test removes exactly one control and asserts the failure it was holding back,
so no test here passes by accident.
"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import ledger as lg
from prreview.security import routing as rt
from prreview.security.config import Caps
from prreview.security.validate import Validator, run_cli_validator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(ROOT, "vendor", "security-audit")
HELPER = os.path.join(ROOT, "node", "sa-helper.cjs")

WORKFLOW = {
    "path": ".github/workflows/ci.yml",
    "status": "modified",
    "added": ["on:", "  pull_request_target:", "jobs:", "  build:",
              "    permissions:", "      contents: write", "    steps:",
              "      - uses: actions/checkout@v4", "        with:",
              "          ref: ${{ github.event.pull_request.head.sha }}",
              "      - run: npm ci && npm test"],
    "removed": [],
}
USERS = {
    "path": "src/api/users.ts",
    "status": "modified",
    "added": ["export async function getUser(req, res) {",
              "  const id = req.params.id;",
              "  return db.query(`select * from users where id = ${id}`);"],
    "removed": [],
}
CONFIG = {
    "path": "src/config.ts",
    "status": "modified",
    "added": ["export const TIMEOUT_MS = 30000;"],
    "removed": [],
}
QUIET = {
    "path": "lib/quiet.go",
    "status": "modified",
    "added": ["func tidy(values []string) []string {", "\treturn values", "}"],
    "removed": [],
}
README = {"path": "README.md", "status": "modified", "added": ["Docs."], "removed": []}

CHANGES = [WORKFLOW, USERS, CONFIG, QUIET, README]

SYMBOLS = {
    "src/api/users.ts": "getUser",
    "src/config.ts": "_top",
    "lib/quiet.go": "tidy",
    ".github/workflows/ci.yml": "jobs.build",
}


def symbol_resolver(path):
    return SYMBOLS.get(path, "")


def check(owner, paths, invariant="No untrusted value reaches the sink unvalidated.",
          result="Read the changed lines and both sibling paths."):
    return lg.source_check(owner, paths, invariant, result)


class LedgerTestCase(unittest.TestCase):
    """One warm sa-helper for the whole module; a fresh ledger per test."""

    @classmethod
    def setUpClass(cls):
        cls.validator = Validator(VENDOR, helper_path=HELPER)
        cls.validator.ping()

    @classmethod
    def tearDownClass(cls):
        cls.validator.close()

    def seed(self, changes=None, commit_count=2, resolver=symbol_resolver, prior=None):
        changes = CHANGES if changes is None else changes
        routing = rt.route(changes)
        return lg.seed(self.validator, routing, changes, commit_count=commit_count,
                       symbol_resolver=resolver, prior=prior), routing

    def assertValid(self, ledger, message=""):
        errors = ledger.validate()
        self.assertEqual(errors, [], "%s%s" % (message and message + ": ", errors))

    def assertCliValid(self, ledger):
        """Run the vendored CLI itself, not only the in-process bridge."""
        with tempfile.TemporaryDirectory() as tmp:
            path = ledger.write(tmp)
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        messages = run_cli_validator("validate-coverage-ledger.cjs", document, VENDOR)
        self.assertEqual(messages, [])
        return document


# --------------------------------------------------------------------- construction

class SeedingTest(LedgerTestCase):

    def test_seeded_ledger_passes_the_vendored_validator(self):
        ledger, _ = self.seed()
        self.assertValid(ledger)
        self.assertEqual(len(self.assertCliValid(ledger)), len(ledger))

    def test_quick_profile_uses_the_fixed_subsystem_reference(self):
        ledger, _ = self.seed()
        refs = {u.canonical_refs["subsystem"] for u in ledger.units}
        self.assertEqual(refs, {"profile/quick/all-in-scope-subsystems"})

    def test_coverage_id_comes_from_the_vendored_encoder(self):
        ledger, _ = self.seed()
        for unit in ledger.units:
            self.assertEqual(unit.coverage_id,
                             self.validator.coverage_id(unit.canonical_refs))

    def test_a_wrong_coverage_id_is_rejected(self):
        ledger, _ = self.seed()
        document = ledger.document()
        document[0]["coverage_id"] = "surface::boundary::subsystem::class"
        errors = self.validator.validate_ledger(document)
        self.assertTrue(any("expected canonical ID" in e for e in errors), errors)
        # Control: the same document without the mutation is accepted.
        self.assertEqual(self.validator.validate_ledger(ledger.document()), [])

    def test_units_are_sorted_lexicographically(self):
        ledger, _ = self.seed()
        ids = [u.coverage_id for u in ledger.units]
        self.assertEqual(ids, sorted(ids))
        shuffled = list(reversed(ledger.document()))
        errors = self.validator.validate_ledger(shuffled)
        self.assertTrue(any("must be sorted lexicographically" in e for e in errors),
                        errors)

    def test_diff_wide_units_are_named_as_synthetic(self):
        ledger, _ = self.seed()
        synthetic = [u for u in ledger.units if u.synthetic]
        self.assertEqual(
            {u.canonical_refs["surface"] for u in synthetic},
            {"repo#pull-request-diff", "repo#pull-request-commits"})
        for unit in synthetic:
            self.assertIn("mandatory diff-wide unit", unit.surface)
            self.assertIn(lg.SYNTHETIC_NOTE, unit.boundary)
            self.assertTrue(unit.mandatory)

    def test_commit_history_unit_only_exists_for_a_multi_commit_pr(self):
        single, _ = self.seed(commit_count=1)
        many, _ = self.seed(commit_count=3)
        surfaces = lambda led: {u.canonical_refs["surface"] for u in led.units}
        self.assertNotIn("repo#pull-request-commits", surfaces(single))
        self.assertIn("repo#pull-request-commits", surfaces(many))

    def test_ci_units_exist_for_every_routed_ci_class(self):
        ledger, routing = self.seed()
        expected = set(rt.routed_ci_classes(routing))
        self.assertTrue(expected)
        got = {u.canonical_refs["attack_class"] for u in ledger.units
               if u.origin == lg.ORIGIN_CI}
        self.assertEqual(got, expected)
        for unit in ledger.units:
            if unit.origin != lg.ORIGIN_CI:
                continue
            self.assertEqual(unit.canonical_refs["surface"],
                             ".github/workflows/ci.yml#on")
            self.assertEqual(unit.canonical_refs["boundary"],
                             ".github/workflows/ci.yml#permissions")

    def test_a_doc_only_change_set_still_yields_a_valid_ledger(self):
        ledger, _ = self.seed(changes=[README], commit_count=1)
        self.assertValid(ledger)
        self.assertEqual(lg.floor_gap(ledger), ())


# --------------------------------------------------------------- source-derived refs

class BoundaryTest(LedgerTestCase):

    def test_boundary_is_derived_from_source_not_a_fixed_literal(self):
        ledger, _ = self.seed()
        floor = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH]
        self.assertTrue(floor)
        by_path = {u.starting_paths[0]: u.canonical_refs["boundary"] for u in floor}
        self.assertEqual(by_path["src/api/users.ts"], "src/api/users.ts#getUser")
        self.assertEqual(by_path["lib/quiet.go"], "lib/quiet.go#tidy")
        # No two changed files share a boundary reference.
        self.assertEqual(len(set(by_path.values())), len(by_path))

    def test_removing_the_symbol_resolver_collapses_the_boundary_to_module_scope(self):
        with_symbols, _ = self.seed()
        without, _ = self.seed(resolver=None)
        pick = lambda led, path: [u.canonical_refs["boundary"] for u in led.units
                                  if u.origin == lg.ORIGIN_PATH
                                  and u.starting_paths[0] == path][0]
        self.assertEqual(pick(with_symbols, "src/api/users.ts"),
                         "src/api/users.ts#getUser")
        self.assertEqual(pick(without, "src/api/users.ts"),
                         "src/api/users.ts#module scope")
        # Even the degraded form stays per-file, so the claim never collapses to one row.
        degraded = {u.canonical_refs["boundary"] for u in without.units
                    if u.origin == lg.ORIGIN_PATH}
        self.assertEqual(len(degraded), len(without.floor_required))

    def test_a_hash_in_a_repository_path_does_not_split_the_reference(self):
        odd = {"path": "src/a#b.ts", "status": "modified",
               "added": ["export function handler(req) { return req.body; }"],
               "removed": []}
        ledger, _ = self.seed(changes=[odd], commit_count=1,
                              resolver=lambda p: "handler")
        unit = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH][0]
        self.assertEqual(unit.canonical_refs["boundary"], "src/a#b.ts#handler")
        self.assertEqual(unit.canonical_refs["boundary"].rsplit("#", 1)[0], "src/a#b.ts")
        self.assertValid(ledger)
        self.assertEqual(lg.floor_gap(ledger), ())

    def test_an_unresolvable_symbol_falls_back_to_the_module_boundary(self):
        ledger, _ = self.seed()
        config = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH
                  and u.starting_paths[0] == "src/config.ts"][0]
        self.assertEqual(config.canonical_refs["boundary"], "src/config.ts#module scope")
        self.assertEqual(config.boundary_kind, "module-scope")

    def test_only_diff_wide_units_use_synthetic_references(self):
        ledger, _ = self.seed()
        for unit in ledger.units:
            if unit.synthetic:
                continue
            path = unit.canonical_refs["boundary"].rsplit("#", 1)[0]
            self.assertIn(path, ledger.changed_paths,
                          "%s has a boundary that names no changed file" % unit.coverage_id)


# --------------------------------------------------------------------- coverage floor

class FloorTest(LedgerTestCase):

    def test_a_changed_file_with_no_recon_signal_is_still_covered(self):
        ledger, routing = self.seed()
        # Control: nothing in the pre-filter routes lib/quiet.go anywhere.
        self.assertEqual(routing.path_tags.get("lib/quiet.go", ()), ())
        named = [u for u in ledger.units if "lib/quiet.go" in u.starting_paths]
        self.assertTrue(named, "the floor did not seed the unsignalled file")
        self.assertTrue(any(u.origin == lg.ORIGIN_PATH for u in named))
        self.assertEqual(lg.floor_gap(ledger), ())

    def test_removing_the_floor_units_reproduces_the_gap(self):
        ledger, _ = self.seed()
        lg.assert_floor(ledger)
        for unit in [u for u in ledger.units if u.origin == lg.ORIGIN_PATH]:
            del ledger._units[unit.coverage_id]
        # The diff-wide unit still names every non-doc path, so drop it too: that is
        # exactly the state a model-chosen unit list would produce.
        for unit in [u for u in ledger.units if u.synthetic]:
            del ledger._units[unit.coverage_id]
        self.assertIn("lib/quiet.go", lg.floor_gap(ledger))
        with self.assertRaises(lg.LedgerError):
            lg.assert_floor(ledger)

    def test_no_model_proposal_can_remove_a_floor_unit(self):
        ledger, _ = self.seed()
        before = {u.coverage_id for u in ledger.units}
        target = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH][0]
        unit, note = lg.add_proposed(ledger, {
            "surface_ref": target.canonical_refs["surface"],
            "boundary_ref": target.canonical_refs["boundary"],
            "attack_class_ref": target.canonical_refs["attack_class"],
            "starting_paths": list(target.starting_paths),
        })
        self.assertEqual(note, "already seeded by the coverage floor")
        self.assertIs(unit, target)
        self.assertEqual({u.coverage_id for u in ledger.units}, before)
        self.assertValid(ledger)

    def test_an_out_of_scope_proposal_is_recorded_not_assigned(self):
        ledger, _ = self.seed()
        unit, note = lg.add_proposed(ledger, {
            "surface_ref": "src/elsewhere.ts#handler",
            "boundary_ref": "src/elsewhere.ts#requireOwner",
            "attack_class_ref": "ATTACK-CLASSES.md#Access control",
            "starting_paths": ["src/elsewhere.ts"],
            "reason": "reachable but untouched by this pull request",
        })
        self.assertEqual(note, "")
        self.assertEqual(unit.status, "out_of_scope")
        self.assertIsNone(unit.agent_id)
        self.assertEqual(unit.unresolved,
                         ("reachable but untouched by this pull request",))
        self.assertValid(ledger)
        self.assertIn(unit.coverage_id,
                      [e.get("coverage_id") for e in ledger.not_reviewed()])

    def test_a_path_the_validator_cannot_represent_is_disclosed_not_dropped(self):
        # `aux` is a Windows reserved component, so the skill's own validator rejects
        # every path under it. Silence here would be a free suppression primitive.
        hostile = {"path": "src/aux/handler.ts", "status": "added",
                   "added": ["export function handler(req) { return req.body; }"],
                   "removed": []}
        ledger, _ = self.seed(changes=[USERS, hostile])
        self.assertValid(ledger)
        for unit in ledger.units:
            self.assertNotIn("src/aux/handler.ts", unit.starting_paths)
        listed = [e for e in ledger.not_reviewed() if e.get("path") == "src/aux/handler.ts"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["status"], "unrepresentable")
        # Control: the vendored validator really does reject that path.
        self.assertTrue(self.validator.screen_paths(["src/aux/handler.ts"]))
        self.assertFalse(self.validator.screen_paths(["src/api/users.ts"]))

    def test_a_change_set_with_no_representable_path_fails_loudly(self):
        hostile = {"path": "src/aux/handler.ts", "status": "added",
                   "added": ["x"], "removed": []}
        routing = rt.route([hostile])
        with self.assertRaises(lg.LedgerError):
            lg.seed(self.validator, routing, [hostile], commit_count=1)


# ------------------------------------------------------------------- state machine

class StateTest(LedgerTestCase):

    def unit_id(self, ledger, origin=lg.ORIGIN_PATH):
        return [u for u in ledger.units if u.origin == origin][0].coverage_id

    def test_every_state_produces_a_ledger_the_validator_accepts(self):
        ledger, _ = self.seed()
        ids = [u.coverage_id for u in ledger.units]
        self.assertValid(ledger, "planned")

        ledger.assign(ids[0], "hunter-1")
        self.assertValid(ledger, "in_progress")

        ledger.close_covered(ids[0], "hunter-1",
                             [check("hunter-1", ledger.get(ids[0]).starting_paths)])
        self.assertValid(ledger, "covered")

        ledger.assign(ids[1], "hunter-2")
        ledger.close_candidate(
            ids[1], "hunter-2", [check("hunter-2", ledger.get(ids[1]).starting_paths)],
            ["injection:src/api/users.ts@getUser"])
        self.assertValid(ledger, "candidate")

        ledger.assign(ids[2], "hunter-3")
        ledger.close_blocked(
            ids[2], "hunter-3", [check("hunter-3", ledger.get(ids[2]).starting_paths)],
            ["[execution] this run executes nothing, so the effect is unobserved"])
        self.assertValid(ledger, "blocked")

        ledger.defer(ids[3], lg.REASON_RESERVES)
        self.assertValid(ledger, "deferred")

        ledger.mark_out_of_scope(ids[4], "outside the merge-base...head scope")
        self.assertValid(ledger, "out_of_scope")

        ledger.mark_not_applicable(ids[5], "no such boundary exists in the changed file")
        self.assertValid(ledger, "not_applicable")
        self.assertEqual(len(self.assertCliValid(ledger)), len(ledger))

    def test_source_only_evidence_is_valid_ledger_evidence(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        ledger.assign(cid, "hunter-1")
        ledger.close_covered(cid, "hunter-1",
                             [check("hunter-1", ledger.get(cid).starting_paths)])
        self.assertValid(ledger)
        document = ledger.document()
        unit = [u for u in document if u["coverage_id"] == cid][0]
        self.assertEqual(unit["local_checks"][0]["method"], "source")
        self.assertIsNone(unit["local_checks"][0]["artifact"])
        # Control: the same check with an artifact is rejected, which is why a
        # no-execution run must keep artifact null rather than inventing one.
        unit["local_checks"][0]["artifact"] = "agents/hunter-1/artifacts/out.txt"
        errors = self.validator.validate_ledger(document)
        self.assertTrue(any("source-only check must use null" in e for e in errors),
                        errors)

    def test_reviewed_paths_are_the_union_of_owned_check_paths(self):
        ledger, _ = self.seed()
        cid = [u.coverage_id for u in ledger.units if u.synthetic][0]
        ledger.assign(cid, "hunter-1")
        ledger.close_covered(cid, "hunter-1", [
            check("hunter-1", ["src/api/users.ts"]),
            check("verifier-1", ["src/config.ts"]),
        ])
        self.assertEqual(ledger.get(cid).reviewed_paths,
                         ("src/api/users.ts", "src/config.ts"))
        self.assertValid(ledger)
        # Control: breaking the union is what the validator is watching for.
        document = ledger.document()
        unit = [u for u in document if u["coverage_id"] == cid][0]
        unit["reviewed_paths"] = ["src/api/users.ts", "src/nowhere.ts"]
        errors = self.validator.validate_ledger(document)
        self.assertTrue(any("has no check owner" in e for e in errors), errors)

    def test_fingerprints_only_live_on_candidate_units(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        ledger.assign(cid, "hunter-1")
        paths = ledger.get(cid).starting_paths
        with self.assertRaises(lg.LedgerError):
            lg._apply(ledger.get(cid), "covered", owner="hunter-1",
                      checks=[check("hunter-1", paths)],
                      fingerprints=["injection:src/api/users.ts@getUser"])
        ledger.close_covered(cid, "hunter-1", [check("hunter-1", paths)])
        self.assertEqual(ledger.get(cid).result_fingerprints, ())
        # Control: forcing a fingerprint onto the covered unit is rejected upstream too.
        document = ledger.document()
        unit = [u for u in document if u["coverage_id"] == cid][0]
        unit["result_fingerprints"] = ["injection:src/api/users.ts@getUser"]
        errors = self.validator.validate_ledger(document)
        self.assertTrue(any("must keep this array empty" in e for e in errors), errors)

    def test_a_candidate_without_a_fingerprint_is_refused(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        ledger.assign(cid, "hunter-1")
        with self.assertRaises(lg.LedgerError):
            ledger.close_candidate(cid, "hunter-1",
                                   [check("hunter-1", ledger.get(cid).starting_paths)],
                                   [])

    def test_owner_and_evidence_rules_for_unassigned_states(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        unit = ledger.get(cid)
        with self.assertRaises(lg.LedgerError):
            lg._apply(unit, "deferred", owner="hunter-1", unresolved=("why",))
        with self.assertRaises(lg.LedgerError):
            lg._apply(unit, "deferred")            # deferred needs a reason
        with self.assertRaises(lg.LedgerError):
            lg._apply(unit, "out_of_scope", checks=[check("hunter-1", ["src/config.ts"])],
                      unresolved=("why",))
        self.assertEqual(unit.status, "planned")

    def test_illegal_transitions_are_refused(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        with self.assertRaises(lg.LedgerError):
            ledger.close_covered(cid, "hunter-1",
                                 [check("hunter-1", ledger.get(cid).starting_paths)])
        ledger.assign(cid, "hunter-1")
        ledger.close_covered(cid, "hunter-1",
                             [check("hunter-1", ledger.get(cid).starting_paths)])
        with self.assertRaises(lg.LedgerError):
            ledger.mark_out_of_scope(cid, "too late")

    def test_reopening_archives_the_attempt_and_needs_a_fresh_owner(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        paths = ledger.get(cid).starting_paths
        ledger.assign(cid, "hunter-1")
        ledger.close_covered(cid, "hunter-1", [check("hunter-1", paths)])
        with self.assertRaises(lg.LedgerError):
            ledger.reopen(cid, "the critic found an unchecked sibling path",
                          owner="hunter-1")
        ledger.reopen(cid, "the critic found an unchecked sibling path", owner="hunter-9")
        unit = ledger.get(cid)
        self.assertEqual(unit.wave, 2)
        self.assertEqual(unit.attempts[0]["wave"], 1)
        self.assertEqual(unit.attempts[0]["agent_id"], "hunter-1")
        self.assertEqual(unit.local_checks, ())
        self.assertValid(ledger)
        ledger.close_covered(cid, "hunter-9", [check("hunter-9", paths)])
        self.assertValid(ledger)
        self.assertEqual(len(self.assertCliValid(ledger)), len(ledger))

    def test_a_quick_run_defers_a_reopened_unit_with_the_skill_reason(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        paths = ledger.get(cid).starting_paths
        ledger.assign(cid, "hunter-1")
        ledger.close_candidate(cid, "hunter-1", [check("hunter-1", paths)],
                               ["injection:src/api/users.ts@getUser"])
        ledger.reopen(cid, lg.REASON_QUICK_CRITIC)
        unit = ledger.get(cid)
        self.assertEqual(unit.status, "deferred")
        self.assertEqual(unit.unresolved, (lg.REASON_QUICK_CRITIC,))
        self.assertEqual(unit.attempts[0]["result_fingerprints"],
                         ["injection:src/api/users.ts@getUser"])
        self.assertValid(ledger)

    def test_a_malformed_hunter_result_returns_the_unit_to_planned(self):
        ledger, _ = self.seed()
        cid = self.unit_id(ledger)
        ledger.assign(cid, "hunter-1")
        ledger.replan(cid)
        self.assertEqual(ledger.get(cid).status, "planned")
        self.assertIsNone(ledger.get(cid).agent_id)
        ledger.defer(cid, lg.REASON_MALFORMED)
        self.assertValid(ledger)

    def test_a_semantic_collision_is_refused_rather_than_merged(self):
        ledger, _ = self.seed()
        clone = copy.deepcopy([u for u in ledger.units if u.origin == lg.ORIGIN_PATH][0])
        clone.canonical_refs = dict(clone.canonical_refs,
                                    surface=clone.canonical_refs["surface"] + "#dup")
        clone.coverage_id = self.validator.coverage_id(clone.canonical_refs)
        with self.assertRaises(lg.LedgerError):
            ledger.add(clone)


# ----------------------------------------------------------- clustering and priority

class ClusteringTest(LedgerTestCase):

    def test_queue_is_ranked_lowest_trust_and_highest_value_first(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger)
        first = ledger.get(queue[0].coverage_ids[0])
        self.assertEqual(first.priority[0], 0)
        self.assertEqual(first.priority[1], 0)
        ranks = [ledger.get(a.coverage_ids[0]).priority for a in queue]
        self.assertEqual(ranks, sorted(ranks))
        # The unsignalled Go file must rank behind the privileged workflow.
        quiet = [u for u in ledger.units if "lib/quiet.go" in u.starting_paths
                 and u.origin == lg.ORIGIN_PATH][0]
        ci = [u for u in ledger.units if u.origin == lg.ORIGIN_CI][0]
        self.assertLess(ci.priority, quiet.priority)

    def test_removing_the_trust_and_value_signals_changes_the_order(self):
        ledger, _ = self.seed()
        ci = [u for u in ledger.units if u.origin == lg.ORIGIN_CI][0]
        ranked_first = lg.rank(ci)[0]
        stripped = copy.deepcopy(ci)
        stripped.tags = ()
        stripped.origin = lg.ORIGIN_RECON
        stripped.attack_class = "Some speculative class"
        self.assertGreater(lg.rank(stripped)[0], ranked_first)

    def test_every_unit_records_its_ordering_rationale(self):
        ledger, _ = self.seed()
        for unit in ledger.units:
            self.assertTrue(unit.rationale)
            self.assertEqual(unit.to_json()["parent"]["ordering_rationale"],
                             unit.rationale)

    def test_clusters_respect_the_unit_and_companion_caps(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger, units_per_hunter=4, companions_per_hunter=3)
        self.assertTrue(queue)
        seen = []
        for assignment in queue:
            self.assertLessEqual(len(assignment.coverage_ids), 4)
            self.assertLessEqual(len(assignment.companions), 3)
            self.assertTrue(lg.safe_agent_id(assignment.agent_id))
            seen.extend(assignment.coverage_ids)
        self.assertEqual(sorted(seen),
                         sorted(u.coverage_id for u in ledger.by_status("planned")))
        self.assertEqual(len(set(seen)), len(seen))

    def test_the_unit_cap_actually_splits_an_oversized_cluster(self):
        # Ten sibling files in one package share a cluster key, so without the cap they
        # would all land on one hunter and the cap would be untested.
        changes = [{"path": "src/pkg/mod%d.ts" % i, "status": "modified",
                    "added": ["export function f%d(x) { return x; }" % i],
                    "removed": []} for i in range(10)]
        ledger, _ = self.seed(changes=changes, commit_count=1,
                              resolver=lambda p: "f" + p.split("mod")[1].split(".")[0])
        wide = lg.cluster(ledger, units_per_hunter=4)
        self.assertTrue(any(len(a.coverage_ids) == 4 for a in wide),
                        "the cap never binds, so this test would prove nothing")
        self.assertTrue(all(len(a.coverage_ids) <= 4 for a in wide))
        narrow = lg.cluster(ledger, units_per_hunter=2)
        self.assertTrue(all(len(a.coverage_ids) <= 2 for a in narrow))
        self.assertGreater(len(narrow), len(wide))

    def test_the_companion_cap_holds_and_names_what_it_drops(self):
        ledger, _ = self.seed()
        for index, unit in enumerate(ledger.by_status("planned")):
            unit.companions = (rt.SUPPLY, rt.WEB, rt.DATA, rt.CLOUD)[:1 + index % 4]
        capped = lg.cluster(ledger, companions_per_hunter=2)
        dropped = []
        for assignment in capped:
            self.assertLessEqual(len(assignment.companions), 2)
            dropped.extend(assignment.deferred_companions)
            # HUNTING.md:7 order decides which companions survive the cap.
            self.assertEqual(list(assignment.companions),
                             sorted(assignment.companions, key=lg._companion_rank))
            if assignment.deferred_companions:
                self.assertEqual(assignment.companions[0], rt.SUPPLY)
        self.assertTrue(dropped, "the companion cap never bound in this fixture")
        # Control: raising the cap keeps everything.
        for assignment in lg.cluster(ledger, companions_per_hunter=4):
            self.assertEqual(assignment.deferred_companions, ())

    def test_the_queue_is_stable_across_runs(self):
        first, _ = self.seed()
        second, _ = self.seed()
        self.assertEqual([a.coverage_ids for a in lg.cluster(first)],
                         [a.coverage_ids for a in lg.cluster(second)])

    def test_unrelated_boundaries_are_never_combined(self):
        ledger, _ = self.seed()
        for assignment in lg.cluster(ledger):
            keys = {lg._cluster_key(ledger.get(cid)) for cid in assignment.coverage_ids}
            self.assertEqual(len(keys), 1)


# ----------------------------------------------------------------------- budget gate

class BudgetTest(LedgerTestCase):

    def test_the_gate_launches_nothing_when_reserves_cannot_be_funded(self):
        plan = lg.budget_gate(Caps(max_conversations=3), cluster_count=5, recon_calls=1)
        self.assertEqual(plan.run_status, "incomplete")
        self.assertEqual(plan.incomplete_reason,
                         "budget_cannot_fund_reconnaissance_and_reserves")
        self.assertEqual(plan.hunters, 0)
        self.assertFalse(plan.launches)
        # Control: one more conversation funds the minimum.
        ok = lg.budget_gate(Caps(max_conversations=4), cluster_count=5, recon_calls=1)
        self.assertEqual(ok.run_status, "running")
        self.assertGreaterEqual(ok.hunters, 1)

    def test_the_four_call_recon_fallback_raises_the_floor(self):
        plan = lg.budget_gate(Caps(max_conversations=6), cluster_count=5, recon_calls=4)
        self.assertEqual(plan.incomplete_reason, lg.REASON_NO_RECON)
        ok = lg.budget_gate(Caps(max_conversations=7), cluster_count=5, recon_calls=4)
        self.assertEqual(ok.run_status, "running")

    def test_reserves_are_taken_before_hunters(self):
        plan = lg.budget_gate(Caps(max_conversations=18, max_hunters=6),
                              cluster_count=50, recon_calls=1)
        self.assertEqual(plan.critic_reserve, 1)
        self.assertGreaterEqual(plan.verifier_reserve, 1)
        self.assertLessEqual(plan.hunters + plan.verifier_reserve + plan.critic_reserve
                             + plan.recon_calls, plan.budget)
        self.assertLessEqual(plan.hunters, 6)

    def test_nothing_launches_when_the_ledger_refuses_the_gate(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger)
        plan = lg.budget_gate(Caps(max_conversations=3), cluster_count=len(queue))
        launched, deferred = lg.apply_budget(ledger, queue, plan)
        self.assertEqual(launched, ())
        self.assertEqual(len(deferred), len(ledger.units))
        for unit in ledger.units:
            self.assertEqual(unit.status, "deferred")
            self.assertEqual(unit.unresolved, (lg.REASON_NO_RECON,))
        self.assertValid(ledger)

    def test_floor_overflow_is_deferred_with_a_reason_and_listed(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger)
        self.assertGreater(len(queue), 2)
        plan = lg.budget_gate(Caps(max_conversations=18, max_hunters=2),
                              cluster_count=len(queue))
        self.assertEqual(plan.hunters, 2)
        launched, deferred = lg.apply_budget(ledger, queue, plan)
        self.assertEqual(len(launched), 2)
        self.assertTrue(deferred)
        for cid in deferred:
            unit = ledger.get(cid)
            self.assertEqual(unit.status, "deferred")
            self.assertEqual(unit.unresolved,
                             ("budget_cannot_reserve_critics_and_validation",))
        # Nothing is dropped: every seeded unit is either assigned or disclosed.
        listed = {e["coverage_id"] for e in ledger.not_reviewed() if e["kind"] == "unit"}
        assigned = {cid for a in launched for cid in a.coverage_ids}
        self.assertEqual(listed | assigned, {u.coverage_id for u in ledger.units})
        self.assertTrue(set(deferred) <= listed)
        self.assertValid(ledger)
        self.assertEqual(len(self.assertCliValid(ledger)), len(ledger))

    def test_deferred_floor_units_are_marked_as_floor_in_the_disclosure(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger)
        plan = lg.budget_gate(Caps(max_conversations=18, max_hunters=1),
                              cluster_count=len(queue))
        lg.apply_budget(ledger, queue, plan)
        floor_entries = [e for e in ledger.not_reviewed()
                         if e["kind"] == "unit" and e["floor"]]
        self.assertTrue(floor_entries)
        for entry in floor_entries:
            self.assertTrue(entry["reason"])
            self.assertTrue(entry["starting_paths"])

    def test_a_lost_critic_reserve_uses_the_skill_reason(self):
        plan = lg.budget_gate(Caps(max_conversations=18), cluster_count=4)
        lost = lg.critic_reserve_lost(plan)
        self.assertEqual(lost.run_status, "incomplete")
        self.assertEqual(lost.incomplete_reason, "critic_budget_exhausted")
        self.assertEqual(lost.hunters, 0)

    def test_untouched_units_are_deferred_after_the_wave(self):
        ledger, _ = self.seed()
        queue = lg.cluster(ledger)
        plan = lg.budget_gate(Caps(max_conversations=18, max_hunters=6),
                              cluster_count=len(queue))
        lg.apply_budget(ledger, queue, plan)
        self.assertTrue(ledger.by_status("in_progress"))
        lg.defer_untouched(ledger, lg.REASON_MALFORMED)
        self.assertEqual(ledger.by_status("planned", "in_progress"), ())
        self.assertValid(ledger)

    def test_validation_overflow_keeps_fingerprints_on_their_units(self):
        ledger, _ = self.seed()
        cids = [u.coverage_id for u in ledger.units][:2]
        prints = []
        for index, cid in enumerate(cids, start=1):
            owner = "hunter-%d" % index
            ledger.assign(cid, owner)
            fp = "injection:src/api/users.ts@sink%d" % index
            prints.append(fp)
            ledger.close_candidate(cid, owner,
                                   [check(owner, ledger.get(cid).starting_paths)], [fp])
        to_verify, unverified = lg.validation_plan(prints, remaining=1)
        self.assertEqual(len(to_verify), 1)
        self.assertEqual(len(unverified), 1)
        self.assertEqual(to_verify + unverified, tuple(sorted(prints)))
        touched = lg.mark_unvalidated(ledger, unverified)
        self.assertTrue(touched)
        for cid in touched:
            self.assertIn("validation_budget_exhausted", ledger.get(cid).unresolved)
        self.assertValid(ledger)


# ------------------------------------------------------------------ excluded blocks

class ExcludedBlocksTest(LedgerTestCase):

    def test_excluded_blocks_are_recorded_at_group_heading_granularity(self):
        ledger, routing = self.seed()
        unit = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH][0]
        blocks = {e["block"] for e in unit.excluded_blocks}
        self.assertTrue(blocks)
        self.assertTrue(blocks >= {e["block"] for e in routing.excluded})
        for entry in unit.excluded_blocks:
            self.assertTrue(entry["reason"])
        self.assertLessEqual(len(unit.excluded_blocks), lg.MAX_EXCLUDED_BLOCKS)

    def test_a_selected_block_is_never_also_excluded(self):
        ledger, _ = self.seed()
        for unit in ledger.units:
            selected = set(unit.selected_companion_blocks)
            excluded = {e["block"] for e in unit.excluded_blocks}
            self.assertEqual(selected & excluded, set(), unit.coverage_id)
        self.assertValid(ledger)

    def test_a_peer_owned_group_is_excluded_with_that_reason(self):
        ledger, _ = self.seed()
        unit = [u for u in ledger.units if u.origin == lg.ORIGIN_PATH][0]
        peer = [e for e in unit.excluded_blocks if "peer coverage unit" in e["reason"]]
        self.assertTrue(peer, "the routed CI group should be peer-owned for this unit")
        ci_unit = [u for u in ledger.units if u.origin == lg.ORIGIN_CI][0]
        self.assertNotIn(rt.SUPPLY,
                         {e["block"].split("#", 1)[0] for e in ci_unit.excluded_blocks
                          if "peer coverage unit" in e["reason"]})


if __name__ == "__main__":
    unittest.main()
