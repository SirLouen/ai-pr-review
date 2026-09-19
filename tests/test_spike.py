"""The M1 spike runs once against the paid API. It must not fail halfway through.

This drives the whole script with a scripted model in place of DeepSeek, which exercises
the fixture, the production pipeline, the metrics and the decision -- everything except
the raw HTTP probes, which only make sense against the real endpoint.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tests.test_main import ScriptedModel  # noqa: E402


def load_spike():
    spec = importlib.util.spec_from_file_location(
        "m1_spike", os.path.join(ROOT, "scripts", "m1_spike.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SpikeRuns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spike = load_spike()

    def run_spike(self, **overrides):
        out = tempfile.mkdtemp(prefix="spike-test-")
        self.addCleanup(shutil.rmtree, out, True)
        argv = ["--out", out, "--verifiers", "3", "--hunters", "1", "--max-usd", "5"]
        code = self.spike.main(argv, provider=overrides.get("provider", ScriptedModel()))
        with open(os.path.join(out, "report.json"), encoding="utf-8") as handle:
            return code, json.load(handle), out

    def test_a_well_behaved_model_is_a_go(self):
        code, report, _ = self.run_spike()
        self.assertEqual(report["verdict"], "GO", report["reason"])
        self.assertEqual(code, 0)
        verifier = report["probes"]["verifier"]
        self.assertEqual(verifier["first_try_rate"], 1.0)
        self.assertEqual(len(verifier["runs"]), 3)
        self.assertIn("hunter", report["probes"])

    def test_every_exchange_is_recorded_as_a_cassette(self):
        """The real responses are the point: they become free regression fixtures."""
        _, report, out = self.run_spike()
        cassettes = [f for f in os.listdir(os.path.join(out, "cassettes"))
                     if f.endswith(".json")]
        self.assertGreater(len(cassettes), 0)
        self.assertEqual(len(cassettes), report["cassettes"])

    def test_the_raw_probes_are_skipped_without_a_live_endpoint(self):
        _, report, _ = self.run_spike()
        for probe in ("model-name", "passback", "reasoning-cap", "json-thinking",
                      "strict-tools"):
            self.assertNotIn(probe, report["probes"])

    def test_no_key_and_no_provider_sends_nothing(self):
        saved = os.environ.pop("DEEPSEEK_API_KEY", None)
        try:
            out = tempfile.mkdtemp(prefix="spike-test-")
            self.addCleanup(shutil.rmtree, out, True)
            self.assertEqual(self.spike.main(["--out", out]), 2)
            self.assertFalse(os.path.exists(os.path.join(out, "report.json")))
        finally:
            if saved is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved


class Decision(unittest.TestCase):
    """The go/no-go rule, independent of any model."""

    @classmethod
    def setUpClass(cls):
        cls.spike = load_spike()

    def decide(self, first, within):
        report = self.spike.Report()
        report.probes["verifier"] = {"first_try_rate": first, "within_feedback_rate": within}
        return self.spike.decide(report)[0]

    def test_the_bar_is_first_try_validity(self):
        self.assertEqual(self.decide(0.9, 0.9), "GO")

    def test_the_feedback_fallback_is_a_conditional_go(self):
        self.assertEqual(self.decide(0.5, 0.95), "CONDITIONAL-GO")

    def test_poor_validity_even_with_feedback_is_a_no_go(self):
        self.assertEqual(self.decide(0.2, 0.6), "NO-GO")

    def test_no_verifier_data_is_never_a_go(self):
        report = self.spike.Report()
        self.assertEqual(self.spike.decide(report)[0], "NO-GO")


if __name__ == "__main__":
    unittest.main()


class Concerns(unittest.TestCase):
    """Borderline results are surfaced even when the verdict is GO."""

    @classmethod
    def setUpClass(cls):
        cls.spike = load_spike()

    def test_thin_headroom_and_a_cold_cache_are_flagged(self):
        report = self.spike.Report()
        report.probes["verifier"] = {"headroom": 0.1, "first_turn_cache_hit_after_first": 0.2,
                                     "unparsable_calls": 1, "conversations_recovered": 0}
        found = self.spike.concerns(report)
        self.assertEqual(len(found), 3, found)

    def test_healthy_numbers_raise_nothing(self):
        report = self.spike.Report()
        report.probes["verifier"] = {"headroom": 0.6, "first_turn_cache_hit_after_first": 0.9,
                                     "unparsable_calls": 1, "conversations_recovered": 1}
        self.assertEqual(self.spike.concerns(report), [])
