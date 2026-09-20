"""Tests for how prior-run state reaches this run: suppression, carry, and write-back.

state.py decides; __main__.Prior applies the decision to a run. These tests build a prior
bundle directly, so they exercise the glue without HTTP and without a model.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import __main__ as cli
from prreview.security import state
from prreview.security import validate as validatemod

FP_REJECTED = "sa1:injection:src/users.js@getUser"
FP_LEAD = "sa1:access-control:src/admin.js@deleteUser"


def record(fingerprint, verdict, path):
    base = {"fingerprint": fingerprint, "verdict": verdict, "title": "t",
            "trace": [{"kind": "sink", "file": path, "line": 3, "scope": "f",
                       "description": "d"}],
            "evidence": [{"file": path, "line": 3, "description": "d"}]}
    if verdict == "rejected":
        base["reason"] = "parameterised after all"
    else:
        base["blockers"] = ["[execution] not run"]
        base["validation_plan"] = {"local": "unit test", "deployment": None}
    return base


def bundle(findings, head_sha="a" * 40):
    return state.PriorBundle(metadata={"pr_number": 7, "head_sha": head_sha,
                                       "profile": "quick",
                                       "generated_at": "2026-09-17T00:00:00Z"},
                             findings=tuple(findings), units=(), compatible=True)


def plan_for(findings, changed_paths=()):
    """A prior plan where every cited path is unchanged unless named in changed_paths."""
    paths = set()
    for item in findings:
        paths.update(state.cited_paths(item))
    prior = {p: "oid-" + p for p in paths}
    head = {p: ("new-" + p if p in changed_paths else "oid-" + p) for p in paths}
    return state.plan_prior(bundle(findings), state.SourceOracle(prior, head))


class Suppression(unittest.TestCase):
    def test_an_unchanged_rejection_suppresses_exactly_that_claim(self):
        prior = cli.Prior(plan=plan_for([record(FP_REJECTED, "rejected", "src/users.js")]))
        self.assertTrue(prior.suppresses(FP_REJECTED))
        self.assertFalse(prior.suppresses(FP_LEAD), "it suppresses only the exact claim")

    def test_a_rejection_whose_source_changed_does_not_suppress(self):
        """RECONNAISSANCE.md:68: changed evidence is current work, not a settled claim."""
        prior = cli.Prior(plan=plan_for([record(FP_REJECTED, "rejected", "src/users.js")],
                                        changed_paths={"src/users.js"}))
        self.assertFalse(prior.suppresses(FP_REJECTED))
        self.assertEqual(prior.source_state()[FP_REJECTED], "changed")

    def test_a_retained_rejection_is_exempt_from_parity(self):
        prior = cli.Prior(plan=plan_for([record(FP_REJECTED, "rejected", "src/users.js")]))
        self.assertIn(FP_REJECTED, [r["fingerprint"] for r in prior.retained()])
        self.assertIn(FP_REJECTED, prior.exempt())


class Carry(unittest.TestCase):
    def test_an_unchanged_lead_goes_back_through_a_verifier(self):
        """RECONNAISSANCE.md:67: never carried silently."""
        prior = cli.Prior(plan=plan_for([record(FP_LEAD, "needs_validation", "src/admin.js")]))
        again = prior.reverify()
        self.assertEqual([r["fingerprint"] for r in again], [FP_LEAD])
        self.assertFalse(prior.suppresses(FP_LEAD), "a lead is re-checked, never suppressed")
        self.assertEqual(prior.source_state()[FP_LEAD], "unchanged")

    def test_a_lead_whose_source_changed_is_not_carried(self):
        prior = cli.Prior(plan=plan_for([record(FP_LEAD, "needs_validation", "src/admin.js")],
                                        changed_paths={"src/admin.js"}))
        self.assertEqual(prior.reverify(), [])
        self.assertEqual(prior.source_state()[FP_LEAD], "changed")


class CarryAgainstThisRun(unittest.TestCase):
    """What `carry_prior` drops before a verifier is paid for it."""

    def prior(self):
        return cli.Prior(plan=plan_for([record(FP_LEAD, "needs_validation",
                                               "src/admin.js")]))

    def candidate(self, fingerprint, path, line=3):
        return {"fingerprint": fingerprint, "verdict": "needs_validation",
                "trace": [{"kind": "sink", "file": path, "line": line, "scope": "f",
                           "description": "d"}]}

    def test_a_lead_this_run_raised_again_is_not_carried_twice(self):
        notes = []
        carried = cli.carry_prior(self.prior(),
                                  [self.candidate(FP_LEAD, "src/admin.js")], notes)
        self.assertEqual(carried, [])
        self.assertEqual(notes, [], "the same fingerprint is an ordinary re-find")

    def test_a_lead_at_a_sink_this_run_already_covers_is_not_carried(self):
        """gpx-route-map#21: the wildcard lead was the injection lead seen twice."""
        notes = []
        other = self.candidate("sa1:wildcard:src/admin.js@deleteUser", "src/admin.js")
        carried = cli.carry_prior(self.prior(), [other], notes)
        self.assertEqual(carried, [])
        self.assertTrue(any(FP_LEAD in note and "already has a candidate at that sink"
                            in note for note in notes))

    def test_a_lead_at_a_sink_nobody_reached_is_carried_and_exempt_from_parity(self):
        notes = []
        elsewhere = self.candidate("sa1:injection:src/users.js@getUser", "src/users.js")
        carried = cli.carry_prior(self.prior(), [elsewhere], notes)
        self.assertEqual([r["fingerprint"] for r in carried], [FP_LEAD])
        self.assertEqual(notes, [])
        # Its unit was re-hunted and closed covered or deferred, so no unit claims it.
        # The gate must not quarantine the lead for that; drive() exempts what it carries.
        self.assertEqual(
            validatemod.check_fingerprint_parity([{"fingerprint": FP_LEAD}], [],
                                                 exempt=[FP_LEAD]), [])
        self.assertTrue(validatemod.check_fingerprint_parity([{"fingerprint": FP_LEAD}],
                                                             []),
                        "the control: without the exemption the gate fails the run")


class WriteBack(unittest.TestCase):
    def test_source_state_only_uses_publishs_vocabulary(self):
        """publish reads anything else as unknown, which never resolves a thread."""
        prior = cli.Prior(plan=plan_for([record(FP_REJECTED, "rejected", "src/users.js"),
                                         record(FP_LEAD, "needs_validation",
                                                "src/admin.js")],
                                        changed_paths={"src/admin.js"}))
        self.assertEqual(set(prior.source_state().values()), {"changed", "unchanged"})

    def test_an_active_suppression_is_written_for_the_next_run_to_age(self):
        prior = cli.Prior(plan=plan_for([record(FP_REJECTED, "rejected", "src/users.js")]))
        history = prior.history()
        self.assertTrue(history, "the next run needs this to count pushes")
        self.assertIn(FP_REJECTED, str(history))


class FirstRun(unittest.TestCase):
    def test_no_prior_state_changes_nothing(self):
        prior = cli.Prior()
        self.assertIsNone(prior.unit_status())
        self.assertFalse(prior.suppresses(FP_REJECTED))
        self.assertEqual((prior.reverify(), prior.retained(), prior.exempt(),
                          prior.source_state(), prior.history()), ([], [], [], {}, []))
        self.assertIsNone(prior.architecture())

    def test_without_a_token_prior_state_is_skipped_with_a_note(self):
        notes = []
        prior = cli.load_prior(Cfg(), cli.Services(), repo=None, diff={}, notes=notes)
        self.assertFalse(prior.usable)
        self.assertTrue(any("prior-run state" in n for n in notes))

    def test_an_unexpected_failure_degrades_to_a_first_run(self):
        """Prior state is optional: losing it must never cost the review itself."""

        class Broken:
            def list_artifacts(self, repo, page=1, per_page=100):
                raise KeyError("malformed response")

        notes = []
        prior = cli.load_prior(Cfg(), cli.Services(gh=Broken()), repo=None, diff={},
                               notes=notes)
        self.assertFalse(prior.usable)
        self.assertTrue(any("unexpected error: KeyError" in n for n in notes), notes)


class Cfg:
    repository = "o/r"
    pr_number = 7
    head_sha = "b" * 40
    workflow_ref = "o/r/.github/workflows/security-review.yml@refs/heads/main"
    out_dir = "/nonexistent-out"


if __name__ == "__main__":
    unittest.main()
