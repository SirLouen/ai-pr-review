"""Tests for the provider layer: response parsing, the spend meter and replay."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prreview.security import config
from prreview.security.providers import deepseek
from prreview.security.providers.base import (BudgetExceeded, CostMeter, ProviderError,
                                              Response, ToolCall, Usage,
                                              request_fingerprint)
from prreview.security.providers.replay import ReplayProvider


def completion(content="ok", tool_calls=None, finish="stop", usage=None):
    message = {"content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message, "finish_reason": finish}],
            "usage": usage or {"prompt_tokens": 100, "prompt_cache_hit_tokens": 40,
                               "completion_tokens": 20}}


class ResponseParsing(unittest.TestCase):
    def test_plain_text(self):
        response = deepseek._to_response(completion("hello"), "deepseek-flash")
        self.assertEqual(response.text, "hello")
        self.assertEqual(response.usage.cache_hit, 40)
        self.assertEqual(response.usage.cache_miss, 60)

    def test_tool_call_arguments_are_parsed(self):
        data = completion("", [{"id": "c1", "function": {"name": "read_file",
                                "arguments": '{"path": "a.py", "ref": "head"}'}}],
                          finish="tool_calls")
        response = deepseek._to_response(data, "deepseek-flash")
        self.assertEqual(response.tool_calls[0].name, "read_file")
        self.assertEqual(response.tool_calls[0].arguments["path"], "a.py")

    def test_reasoning_is_carried_for_passback(self):
        data = completion("done")
        data["choices"][0]["message"]["reasoning_content"] = "step 1"
        data["usage"]["completion_tokens_details"] = {"reasoning_tokens": 700}
        response = deepseek._to_response(data, "deepseek-flash")
        self.assertEqual(response.opaque["reasoning_content"], "step 1")
        self.assertEqual(response.usage.reasoning, 700)

    def test_error_payload_raises(self):
        with self.assertRaises(ProviderError):
            deepseek._to_response({"error": {"message": "rate limited"}}, "deepseek-flash")

    def test_error_prose_in_200_is_not_silence(self):
        """A failed call must never look like an agent that found nothing."""
        with self.assertRaises(ProviderError):
            deepseek._to_response({"object": "error", "message": "upstream"}, "deepseek-flash")

    def test_empty_completion_raises(self):
        with self.assertRaises(ProviderError):
            deepseek._to_response(completion(""), "deepseek-flash")

    def test_unparsable_tool_arguments_become_a_recoverable_call(self):
        """The M1 spike lost a verifier to `"path_glob": **`. That is the model's slip,
        not a provider failure, so it must reach the tool surface to be answered."""
        raw = '{"fixed_string": true, "path_glob": **, "pattern": "db.query"}'
        data = completion("", [{"id": "c1", "function": {"name": "grep", "arguments": raw}}],
                          finish="tool_calls")
        response = deepseek._to_response(data, "deepseek-flash")
        call = response.tool_calls[0]
        self.assertEqual(call.name, "grep")
        self.assertIsNone(call.arguments)
        self.assertIn("not valid JSON", call.error)
        self.assertEqual(call.raw, raw, "the model's exact text is kept for the history")

    def test_a_non_object_argument_is_also_recoverable(self):
        data = completion("", [{"id": "c1", "function": {"name": "grep", "arguments": "[1]"}}],
                          finish="tool_calls")
        call = deepseek._to_response(data, "deepseek-flash").tool_calls[0]
        self.assertIn("not a JSON object", call.error)

    def test_non_allowlisted_base_url_refused(self):
        with self.assertRaises(ProviderError):
            deepseek.DeepSeekProvider("k", base_url="https://evil.example")
        provider = deepseek.DeepSeekProvider("k", base_url="https://evil.example",
                                             allow_custom_base_url=True)
        self.assertEqual(provider.base_url, "https://evil.example")


class Meter(unittest.TestCase):
    def test_charges_and_stops_before_crossing(self):
        meter = CostMeter(max_usd=1.0)
        meter.charge("hunter", "deepseek-flash", Usage(cache_miss=1_000_000, output=100_000))
        self.assertAlmostEqual(meter.spent, 0.30 + 0.12, places=4)
        meter.check("hunter", "deepseek-flash", 100_000, 10_000)
        with self.assertRaises(BudgetExceeded):
            meter.check("hunter", "deepseek-flash", 5_000_000, 200_000)

    def test_reasoning_is_billed_once_as_part_of_output(self):
        """completion_tokens already includes reasoning; adding them double-bills it.

        This test previously asserted the double count, which is how the bug survived.
        """
        meter = CostMeter(max_usd=10.0)
        price = config.PRICES["deepseek-flash"]
        meter.charge("hunter", "deepseek-flash", Usage(output=100_000, reasoning=90_000))
        self.assertAlmostEqual(meter.spent, price.usd(0, 0, 100_000), places=6)
        self.assertNotAlmostEqual(meter.spent, price.usd(0, 0, 190_000), places=6)

    def test_unknown_model_is_not_charged_blindly(self):
        meter = CostMeter(max_usd=1.0)
        self.assertEqual(meter.charge("hunter", "mystery-model", Usage(output=10)), 0.0)


class Replay(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="cassette-")

    def test_records_then_replays_without_calling_inner(self):
        calls = []

        class Inner:
            def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
                calls.append(role)
                return Response(text="live", usage=Usage(cache_miss=10, output=5),
                                model=model, finish_reason="stop")

        messages = [{"role": "user", "content": "hunt"}]
        recorder = ReplayProvider(self.dir, inner=Inner(), mode="record")
        first = recorder.complete("hunter", "deepseek-flash", messages)
        self.assertEqual(first.text, "live")

        player = ReplayProvider(self.dir, mode="replay")
        second = player.complete("hunter", "deepseek-flash", messages)
        self.assertEqual(second.text, "live")
        self.assertEqual(second.usage.cache_miss, 10)
        self.assertEqual(calls, ["hunter"], "replay must not reach the live provider")

    def test_changed_prompt_misses_rather_than_replaying_stale(self):
        class Inner:
            def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
                return Response(text="live", model=model)

        recorder = ReplayProvider(self.dir, inner=Inner(), mode="record")
        recorder.complete("hunter", "deepseek-flash", [{"role": "user", "content": "a"}])
        player = ReplayProvider(self.dir, mode="replay")
        with self.assertRaises(ProviderError):
            player.complete("hunter", "deepseek-flash", [{"role": "user", "content": "b"}])

    def test_tool_calls_survive_a_round_trip(self):
        class Inner:
            def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
                return Response(tool_calls=[ToolCall("c1", "grep", {"pattern": "x"})],
                                model=model, finish_reason="tool_calls")

        messages = [{"role": "user", "content": "find"}]
        ReplayProvider(self.dir, inner=Inner(), mode="record").complete(
            "hunter", "deepseek-flash", messages)
        replayed = ReplayProvider(self.dir, mode="replay").complete(
            "hunter", "deepseek-flash", messages)
        self.assertEqual(replayed.tool_calls[0].name, "grep")
        self.assertEqual(replayed.tool_calls[0].arguments, {"pattern": "x"})

    def test_fingerprint_covers_tools_and_model(self):
        messages = [{"role": "user", "content": "a"}]
        base = request_fingerprint("deepseek-flash", messages, None)
        self.assertNotEqual(base, request_fingerprint("deepseek-v4-pro", messages, None))
        self.assertNotEqual(base, request_fingerprint(
            "deepseek-flash", messages, [{"name": "read_file"}]))

    def test_an_unparsable_call_replays_as_unparsable(self):
        class Inner:
            def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
                return Response(tool_calls=[ToolCall("c1", "grep", None, error="bad json",
                                                     raw="{x: **}")],
                                model=model, finish_reason="tool_calls")

        messages = [{"role": "user", "content": "find"}]
        ReplayProvider(self.dir, inner=Inner(), mode="record").complete(
            "hunter", "deepseek-flash", messages)
        call = ReplayProvider(self.dir, mode="replay").complete(
            "hunter", "deepseek-flash", messages).tool_calls[0]
        self.assertEqual((call.error, call.raw, call.arguments), ("bad json", "{x: **}", None))

    def test_cassettes_are_readable_json(self):
        class Inner:
            def complete(self, role, model, messages, tools=None, max_tokens=4096, extra=None):
                return Response(text="live", model=model)

        ReplayProvider(self.dir, inner=Inner(), mode="record").complete(
            "hunter", "deepseek-flash", [{"role": "user", "content": "a"}])
        name = [f for f in os.listdir(self.dir) if f.endswith(".json")][0]
        with open(os.path.join(self.dir, name), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["text"], "live")


if __name__ == "__main__":
    unittest.main()


class ReasoningLevels(unittest.TestCase):
    def test_off_is_the_parameter_production_already_sends(self):
        """verify_review.py sends thinking: disabled to DeepSeek today."""
        self.assertEqual(deepseek.reasoning_params("off"), {"thinking": {"type": "disabled"}})

    def test_effort_levels_map_to_reasoning_effort(self):
        for level in ("low", "medium", "high"):
            self.assertEqual(deepseek.reasoning_params(level), {"reasoning_effort": level})

    def test_no_level_sends_nothing(self):
        self.assertEqual(deepseek.reasoning_params(None), {})

    def test_an_unknown_level_is_refused_before_it_is_sent(self):
        with self.assertRaises(ProviderError):
            deepseek.reasoning_params("maximum")

    def test_config_parses_a_per_role_map(self):
        self.assertEqual(config.parse_reasoning("recon=off, critic=low"),
                         {"recon": "off", "critic": "low"})
        self.assertEqual(config.parse_reasoning(""), {})
        for bad in ("planner=low", "hunter=extreme", "hunter"):
            with self.assertRaises(config.ConfigError):
                config.parse_reasoning(bad)
